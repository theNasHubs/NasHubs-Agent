package main

import (
	"crypto/subtle"
	"net/http"
	"time"
)

// pairingTTL bounds how long after agent start the one-time pairing secret is
// accepted. The app bootstraps and pairs immediately, so this stays short.
const pairingTTL = 15 * time.Minute

type pairRequest struct {
	PairingSecret string `json:"pairingSecret"`
	Label         string `json:"label"` // optional device label, e.g. "iPhone"
}

type pairResponse struct {
	OK              bool   `json:"ok"`
	CertFingerprint string `json:"certFingerprint"`
	Version         string `json:"version"`
	KeyID           string `json:"keyId"` // the trusted pubkey the app presented
	DeviceID        string `json:"deviceId,omitempty"`
	Role            string `json:"role,omitempty"`
}

// handlePair enrolls the calling device.
//
// Behaviour:
//   - Already-enrolled (non-revoked) key → idempotent success WITHOUT the secret
//     (supports reconnects and the app's boot-time retry loop).
//   - New key → requires the one-time pairing secret, still within pairingTTL.
//     The secret is invalidated after the first successful enrollment. The first
//     device becomes `owner`; any later one (if a secret is ever re-provisioned)
//     becomes `admin`.
//
// The request is already signature-authenticated by middleware.
func (s *server) handlePair(w http.ResponseWriter, r *http.Request) {
	if !s.pairLimiter.allow(clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, errMap("too many pairing attempts", nil))
		return
	}

	auth := authFrom(r)
	var req pairRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("bad request", err))
		return
	}

	// Single critical section so concurrent retries from the same device don't
	// double-enroll.
	s.pairMu.Lock()
	defer s.pairMu.Unlock()

	// Idempotent path: key already enrolled and active.
	if dev := s.devices.lookup(auth.keyID); dev != nil && !dev.revoked() {
		writeJSON(w, http.StatusOK, pairResponse{
			OK: true, CertFingerprint: s.certFingerprint, Version: s.cfg.Version,
			KeyID: auth.keyID, DeviceID: dev.DeviceID, Role: string(dev.Role),
		})
		return
	}

	// New key → must present the pairing secret within the window. Only keys trusted at bootstrap
	// (env) reach this handler at all, and each enrols once; every other request from an env key
	// is refused until it has paired (see verifyRequest), so a second bootstrap key (another
	// device of the same owner) can still pair within the window.
	if s.cfg.PairingSecret == "" {
		writeJSON(w, http.StatusForbidden, errMap("no pairing secret configured", nil))
		return
	}
	if time.Since(s.startedAt) > pairingTTL {
		writeJSON(w, http.StatusForbidden, errMap("pairing window expired", nil))
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.PairingSecret), []byte(s.cfg.PairingSecret)) != 1 {
		writeJSON(w, http.StatusForbidden, errMap("pairing secret mismatch", nil))
		return
	}

	role := RoleAdmin
	if s.devices.isEmpty() {
		role = RoleOwner
	}
	label := req.Label
	if label == "" {
		label = "device"
	}
	dev, err := s.devices.enroll(auth.keyID, label, role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("enroll device", err))
		return
	}

	writeJSON(w, http.StatusOK, pairResponse{
		OK: true, CertFingerprint: s.certFingerprint, Version: s.cfg.Version,
		KeyID: auth.keyID, DeviceID: dev.DeviceID, Role: string(dev.Role),
	})
}
