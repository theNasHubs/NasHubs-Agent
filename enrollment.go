package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const invitationTTL = 10 * time.Minute

type invitation struct {
	Hash      string    `json:"hash"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expiresAt"`
	Issuer    string    `json:"issuer,omitempty"`
	Used      bool      `json:"used"`
}

type invitationStore struct {
	mu      sync.Mutex
	path    string
	entries map[string]invitation
	loadErr error
}

func newInvitationStore(dir string) *invitationStore {
	st := &invitationStore{path: filepath.Join(dir, "invitations.json"), entries: map[string]invitation{}}
	b, err := os.ReadFile(st.path)
	if os.IsNotExist(err) {
		return st
	}
	if err != nil {
		st.loadErr = err
		return st
	}
	st.loadErr = json.Unmarshal(b, &st.entries)
	if st.entries == nil {
		st.entries = map[string]invitation{}
		st.loadErr = fmt.Errorf("invalid invitation store")
	}
	return st
}

func invitationHash(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

func (st *invitationStore) persistLocked() error {
	b, err := json.MarshalIndent(st.entries, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(st.path), ".invitations-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), st.path)
}

func (st *invitationStore) create(role Role, issuer string) (string, time.Time, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.loadErr != nil {
		return "", time.Time{}, st.loadErr
	}
	now := time.Now()
	for k, v := range st.entries {
		if !now.Before(v.ExpiresAt) {
			delete(st.entries, k)
		}
	}
	if len(st.entries) >= 100 {
		return "", time.Time{}, fmt.Errorf("too many active invitations")
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	code := base64.RawURLEncoding.EncodeToString(b)
	hash := invitationHash(code)
	expires := now.Add(invitationTTL)
	st.entries[hash] = invitation{Hash: hash, Role: role, ExpiresAt: expires, Issuer: issuer}
	if err := st.persistLocked(); err != nil {
		delete(st.entries, hash)
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// Consume durably BEFORE enrollment. Disk failure burns a code rather than
// authorizing two keys; already enrolled clients reconnect through /pair.
func (st *invitationStore) consume(code string, devices *deviceStore) (Role, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.loadErr != nil {
		return "", st.loadErr
	}
	hash := invitationHash(code)
	inv, ok := st.entries[hash]
	if !ok || inv.Used || !time.Now().Before(inv.ExpiresAt) {
		return "", fmt.Errorf("invitation invalid or expired")
	}
	if inv.Issuer != "" {
		d := devices.lookup(inv.Issuer)
		if d == nil || d.revoked() || d.Role != RoleOwner {
			return "", fmt.Errorf("invitation issuer unavailable")
		}
	}
	inv.Used = true
	st.entries[hash] = inv
	if err := st.persistLocked(); err != nil {
		return "", err
	}
	return inv.Role, nil
}

func (s *server) createInvitation(w http.ResponseWriter, r *http.Request, localRoot bool) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Role Role `json:"role"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, 400, errMap("bad request", nil))
		return
	}
	if req.Role == "" {
		req.Role = RoleAdmin
	}
	if req.Role != RoleViewer && req.Role != RoleAdmin && !(localRoot && req.Role == RoleOwner) {
		writeJSON(w, 400, errMap("invalid invitation role", nil))
		return
	}
	issuer := ""
	if !localRoot {
		issuer = authFrom(r).keyID
		// An env-trusted bootstrap owner must enroll before delegating access.
		if d := s.devices.lookup(issuer); d == nil || d.revoked() || d.Role != RoleOwner {
			writeJSON(w, 403, errMap("enroll owner first", nil))
			return
		}
	}
	code, expires, err := s.invitations.create(req.Role, issuer)
	if err != nil {
		writeJSON(w, 500, errMap("create invitation failed", nil))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "code": code, "role": req.Role, "expiresAt": expires.UTC().Format(time.RFC3339), "certFingerprint": s.certFingerprint})
}

func (s *server) handleCreateInvitation(w http.ResponseWriter, r *http.Request) {
	s.createInvitation(w, r, false)
}

func (s *server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.pairLimiter.allow("enroll:"+clientIP(r)) || !s.pairLimiter.allow("enroll-global") {
		writeJSON(w, 429, errMap("too many pairing attempts", nil))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSON(w, 400, errMap("bad request", nil))
		return
	}
	auth, err := s.verifySignature(r, body, false)
	if err != nil {
		writeJSON(w, 401, errMap("auth failed", err))
		return
	}
	var req struct {
		Code  string `json:"code"`
		Label string `json:"label"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Code) > 128 || len(req.Label) > 80 {
		writeJSON(w, 400, errMap("bad request", nil))
		return
	}
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	if d := s.devices.lookup(auth.keyID); d != nil {
		if d.revoked() {
			writeJSON(w, 403, errMap("device revoked", nil))
			return
		}
		s.writePairedDevice(w, d)
		return
	}
	role, err := s.invitations.consume(req.Code, s.devices)
	if err != nil {
		writeJSON(w, 403, errMap("invitation invalid or expired", nil))
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "device"
	}
	d, err := s.devices.enroll(auth.keyID, label, role)
	if err != nil {
		writeJSON(w, 500, errMap("enroll device failed", nil))
		return
	}
	s.writePairedDevice(w, d)
}

func (s *server) writePairedDevice(w http.ResponseWriter, d *Device) {
	writeJSON(w, 200, pairResponse{OK: true, CertFingerprint: s.certFingerprint, Version: s.cfg.Version, KeyID: d.KeyID, DeviceID: d.DeviceID, Role: string(d.Role)})
}
