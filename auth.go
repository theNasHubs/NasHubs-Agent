package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// HTTP Signature scheme (must match iOS AgentTransport exactly):
//
//	X-NasHubs-Keyid: base64( 32-byte Ed25519 public key )
//	X-NasHubs-Ts:    decimal unix seconds
//	X-NasHubs-Nonce: base64( 16 random bytes )
//	X-NasHubs-Sig:   base64( 64-byte Ed25519 signature )
//
//	sigBase = METHOD + "\n" + PATH + "\n" + ts + "\n" + nonce + "\n" + hex(sha256(body))
//	(PATH = URL path only, no query string; GET/empty body hashes to sha256("").
const (
	hdrKeyID = "X-NasHubs-Keyid"
	hdrTs    = "X-NasHubs-Ts"
	hdrNonce = "X-NasHubs-Nonce"
	hdrSig   = "X-NasHubs-Sig"

	maxSkew   = 60 * time.Second
	nonceTTL  = 2 * time.Minute
	maxNonces = 50_000 // hard cap to prevent unbounded memory growth under burst
)

// nonceCache prevents replay of previously seen (ts,nonce) pairs.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newNonceCache() *nonceCache {
	return &nonceCache{seen: map[string]time.Time{}}
}

// checkAndAdd returns false if the nonce was already seen (replay). Prunes expired.
func (n *nonceCache) checkAndAdd(key string, now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	// prune expired entries
	for k, t := range n.seen {
		if now.Sub(t) > nonceTTL {
			delete(n.seen, k)
		}
	}
	// hard cap: if still too large after pruning, clear the whole cache.
	// This sacrifices replay protection for the brief window but prevents OOM.
	if len(n.seen) >= maxNonces {
		n.seen = map[string]time.Time{}
	}
	if _, ok := n.seen[key]; ok {
		return false
	}
	n.seen[key] = now
	return true
}

type authResult struct {
	keyID string
	role  Role
}

// verifyRequest validates the HTTP signature. Returns the trusted keyId on success.
func (s *server) verifyRequest(r *http.Request, body []byte) (authResult, error) {
	keyID, tsStr, nonce, sigB64, err := signatureHeaders(r.Header)
	if err != nil {
		return authResult{}, err
	}

	// 1) timestamp freshness
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return authResult{}, fmt.Errorf("bad timestamp")
	}
	now := time.Now()
	if diff := now.Sub(time.Unix(ts, 0)); diff > maxSkew || diff < -maxSkew {
		return authResult{}, fmt.Errorf("timestamp out of range")
	}

	// 2) key must be trusted: either injected at bootstrap (env) or enrolled as
	// a device. A revoked device is rejected even if its key is still in env.
	dev := s.devices.lookup(keyID)
	if dev != nil && dev.revoked() {
		return authResult{}, fmt.Errorf("device revoked")
	}
	if dev == nil && !s.cfg.TrustedPublicKeys[keyID] {
		return authResult{}, fmt.Errorf("untrusted key")
	}
	pub, err := base64.StdEncoding.DecodeString(keyID)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return authResult{}, fmt.Errorf("bad key id")
	}

	// 3) signature must verify over the canonical base
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return authResult{}, fmt.Errorf("bad signature encoding")
	}
	base := signatureBase(r.Method, r.URL.Path, tsStr, nonce, body)
	if !ed25519.Verify(ed25519.PublicKey(pub), base, sig) {
		return authResult{}, fmt.Errorf("invalid signature")
	}

	// 4) replay protection — recorded ONLY after the key is trusted and the
	// signature is valid. Doing this last prevents an unauthenticated attacker
	// from "burning" a (ts,nonce) pair with a forged request and thereby
	// blocking the legitimate signed request that reuses it within the window.
	// A genuine replay still fails here: the captured request has a valid
	// signature, reaches this point, and checkAndAdd returns false.
	replayKey := tsStr + ":" + nonce
	if !s.nonces.checkAndAdd(replayKey, now) {
		return authResult{}, fmt.Errorf("replay detected")
	}

	// 5) resolve role. An enrolled device uses its stored role; an env-trusted
	// key that has not enrolled yet is treated as owner (the bootstrap device).
	role := RoleOwner
	if dev != nil {
		role = dev.Role
	}
	s.devices.touch(keyID)
	return authResult{keyID: keyID, role: role}, nil
}

// Header names used by the pre-rebrand ("Nasdeck") iOS app that is still in production. The
// signature scheme and canonical string are identical; only the header prefix differs.
const (
	legacyHdrKeyID = "X-Nasdeck-Keyid"
	legacyHdrTs    = "X-Nasdeck-Ts"
	legacyHdrNonce = "X-Nasdeck-Nonce"
	legacyHdrSig   = "X-Nasdeck-Sig"
)

// signatureHeaders returns the four signature headers from exactly ONE scheme: the current
// X-NasHubs-* set or the legacy X-Nasdeck-* set. A request carrying headers of both schemes is
// rejected as ambiguous, so fields can never be mixed across schemes (header confusion).
func signatureHeaders(h http.Header) (keyID, ts, nonce, sig string, err error) {
	current := h.Get(hdrKeyID) != "" || h.Get(hdrTs) != "" || h.Get(hdrNonce) != "" || h.Get(hdrSig) != ""
	legacy := h.Get(legacyHdrKeyID) != "" || h.Get(legacyHdrTs) != "" || h.Get(legacyHdrNonce) != "" || h.Get(legacyHdrSig) != ""
	switch {
	case current && legacy:
		return "", "", "", "", fmt.Errorf("ambiguous signature headers")
	case legacy:
		keyID, ts, nonce, sig = h.Get(legacyHdrKeyID), h.Get(legacyHdrTs), h.Get(legacyHdrNonce), h.Get(legacyHdrSig)
	default:
		keyID, ts, nonce, sig = h.Get(hdrKeyID), h.Get(hdrTs), h.Get(hdrNonce), h.Get(hdrSig)
	}
	if keyID == "" || ts == "" || nonce == "" || sig == "" {
		return "", "", "", "", fmt.Errorf("missing signature headers")
	}
	return keyID, ts, nonce, sig, nil
}

// signatureBase builds the canonical message that is signed/verified.
func signatureBase(method, path, ts, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	// method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex(sha256(body))
	return []byte(method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}
