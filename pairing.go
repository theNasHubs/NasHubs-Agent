package main

import (
	"net/http"
)

type pairRequest struct {
	PairingSecret string `json:"pairingSecret"`
	Label         string `json:"label"` // optional device label, e.g. "iPhone"
}

type pairResponse struct {
	OK               bool   `json:"ok"`
	CertFingerprint  string `json:"certFingerprint"`
	Version          string `json:"version"`
	KeyID            string `json:"keyId"` // the trusted pubkey the app presented
}

// handlePair confirms the one-time pairing secret. The request is already
// signature-authenticated by middleware (so we know it came from a trusted key);
// matching the secret guards against talking to the wrong NAS / stale install.
func (s *server) handlePair(w http.ResponseWriter, r *http.Request) {
	auth := authFrom(r)
	var req pairRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("bad request", err))
		return
	}
	if s.cfg.PairingSecret == "" {
		writeJSON(w, http.StatusForbidden, errMap("no pairing secret configured", nil))
		return
	}
	if req.PairingSecret != s.cfg.PairingSecret {
		writeJSON(w, http.StatusForbidden, errMap("pairing secret mismatch", nil))
		return
	}
	writeJSON(w, http.StatusOK, pairResponse{
		OK:              true,
		CertFingerprint: s.certFingerprint,
		Version:         s.cfg.Version,
		KeyID:           auth.keyID,
	})
}
