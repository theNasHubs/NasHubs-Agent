package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// interop_test pins the exact byte vectors the iOS AgentTransport must reproduce.
// Ed25519 signing is deterministic (RFC 8032), so for a fixed 32-byte seed and
// message, Go and Swift CryptoKit Curve25519.Signing MUST produce the identical
// signature. The iOS test embeds these vectors and asserts the same outputs.

// fixedSeed is 32 bytes (1..32). The private key seed CryptoKit stores via
// privateKey.rawRepresentation; Go reconstructs via ed25519.NewKeyFromSeed.
var fixedSeed = func() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 1)
	}
	return s
}()

func TestSignatureBaseFormat(t *testing.T) {
	// Canonical sigBase: METHOD\nPATH\nTS\nNONCE\nHEX(sha256(body))
	body := []byte(`{"id":"qbittorrent"}`)
	base := signatureBase("POST", "/deploy", "1700000000", "nonceABC=", body)

	sum := sha256.Sum256(body)
	want := "POST\n/deploy\n1700000000\nnonceABC=\n" + hex.EncodeToString(sum[:])
	if string(base) != want {
		t.Fatalf("sigBase mismatch:\n got: %q\nwant: %q", base, want)
	}
}

func TestEd25519DeterministicVector(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(fixedSeed)
	pub := priv.Public().(ed25519.PublicKey)
	msg := []byte("nasdeck interop test\n")
	sig := ed25519.Sign(priv, msg)

	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("verify failed")
	}

	// Print the canonical vector for embedding in the iOS interop test.
	// (Visible with: go test -run TestEd25519DeterministicVector -v)
	t.Logf("VECTOR seed_b64=%s", base64.StdEncoding.EncodeToString(fixedSeed))
	t.Logf("VECTOR pub_b64=%s", base64.StdEncoding.EncodeToString(pub))
	t.Logf("VECTOR msg=%q", string(msg))
	t.Logf("VECTOR sig_b64=%s", base64.StdEncoding.EncodeToString(sig))
	t.Logf("VECTOR seed_hex=%s", hex.EncodeToString(fixedSeed))

	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		t.Fatal("unexpected key/sig size")
	}
}

// TestRequestSigningRoundTrip signs a canonical request base and verifies it,
// mirroring exactly what verifyRequest() checks in production.
func TestRequestSigningRoundTrip(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(fixedSeed)
	pub := priv.Public().(ed25519.PublicKey)
	body := []byte(`{"compose":"x"}`)

	ts := "1700000123"
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce1234567890"))
	base := signatureBase("POST", "/deploy", ts, nonce, body)
	sig := ed25519.Sign(priv, base)

	if !ed25519.Verify(pub, base, sig) {
		t.Fatal("round-trip verify failed")
	}

	// Sanity: a tampered body must fail verification.
	bad := signatureBase("POST", "/deploy", ts, nonce, []byte(`{"compose":"y"}`))
	if ed25519.Verify(pub, bad, sig) {
		t.Fatal("verify should fail for tampered body")
	}
}
