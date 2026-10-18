package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Role is the permission level of an enrolled device (iPhone).
//
//	owner  — full control: pair/revoke devices, all mutating actions
//	admin  — deploy/operate apps + gateway/tunnel, but no device management
//	viewer — read-only status/logs
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleViewer Role = "viewer"
)

// Device is one enrolled client identity.
type Device struct {
	DeviceID  string `json:"deviceId"`
	KeyID     string `json:"keyId"` // base64 Ed25519 public key (== the signing key)
	Label     string `json:"label"`
	Role      Role   `json:"role"`
	PairedAt  string `json:"pairedAt"`
	LastSeen  string `json:"lastSeenAt,omitempty"`
	RevokedAt string `json:"revokedAt,omitempty"`
}

func (d *Device) revoked() bool { return d.RevokedAt != "" }

// deviceStore persists enrolled devices to <dir>/devices.json (atomic writes).
// It is the source of truth for authorization once a device is enrolled; the
// bootstrap-injected env key (NASHUBS_TRUSTED_PUBKEY) grants owner-level access
// only until it enrolls itself via /pair.
type deviceStore struct {
	mu      sync.Mutex
	path    string
	devices map[string]*Device // keyID → device
	loadErr error
}

func newDeviceStore(dir string) *deviceStore {
	ds := &deviceStore{path: filepath.Join(dir, "devices.json"), devices: map[string]*Device{}}
	ds.load()
	return ds
}

func (ds *deviceStore) load() {
	b, err := os.ReadFile(ds.path)
	if err != nil {
		if !os.IsNotExist(err) {
			ds.loadErr = err
		}
		return // no store yet
	}
	var list []*Device
	if err := json.Unmarshal(b, &list); err != nil {
		ds.loadErr = err
		return
	}
	for _, d := range list {
		if d == nil || d.KeyID == "" || (d.Role != RoleOwner && d.Role != RoleAdmin && d.Role != RoleViewer) || ds.devices[d.KeyID] != nil {
			ds.loadErr = fmt.Errorf("invalid device store")
			return
		}
		if d.KeyID != "" {
			ds.devices[d.KeyID] = d
		}
	}
}

// persistLocked writes the store atomically. Caller must hold ds.mu.
func (ds *deviceStore) persistLocked() error {
	list := make([]*Device, 0, len(ds.devices))
	for _, d := range ds.devices {
		list = append(list, d)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := ds.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ds.path)
}

// lookup returns the device for a keyID (or nil).
func (ds *deviceStore) lookup(keyID string) *Device {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if d := ds.devices[keyID]; d != nil {
		cp := *d
		return &cp
	}
	return nil
}

// isEmpty reports whether there is no active (non-revoked) device yet.
func (ds *deviceStore) isEmpty() bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, d := range ds.devices {
		if !d.revoked() {
			return false
		}
	}
	return true
}

// enroll records a new device, or returns the existing one if the key is
// already enrolled and not revoked (idempotent).
func (ds *deviceStore) enroll(keyID, label string, role Role) (*Device, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if ds.loadErr != nil {
		return nil, ds.loadErr
	}
	if d, ok := ds.devices[keyID]; ok && !d.revoked() {
		cp := *d
		return &cp, nil
	}
	if d := ds.devices[keyID]; d != nil && d.revoked() {
		return nil, fmt.Errorf("device revoked")
	}
	idBytes := make([]byte, 8)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	d := &Device{
		DeviceID: hex.EncodeToString(idBytes),
		KeyID:    keyID,
		Label:    label,
		Role:     role,
		PairedAt: time.Now().UTC().Format(time.RFC3339),
	}
	ds.devices[keyID] = d
	if err := ds.persistLocked(); err != nil {
		delete(ds.devices, keyID)
		return nil, err
	}
	cp := *d
	return &cp, nil
}

// list returns a snapshot copy of all devices.
func (ds *deviceStore) list() []*Device {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	out := make([]*Device, 0, len(ds.devices))
	for _, d := range ds.devices {
		cp := *d
		out = append(out, &cp)
	}
	return out
}

// revoke marks a device (by deviceId) revoked. Returns false if not found.
func (ds *deviceStore) revoke(deviceID string) (bool, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, d := range ds.devices {
		if d.DeviceID == deviceID {
			if d.revoked() {
				return true, nil
			}
			d.RevokedAt = time.Now().UTC().Format(time.RFC3339)
			if err := ds.persistLocked(); err != nil {
				d.RevokedAt = ""
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// touch updates lastSeen in memory only (avoids a disk write per request).
func (ds *deviceStore) touch(keyID string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if d, ok := ds.devices[keyID]; ok {
		d.LastSeen = time.Now().UTC().Format(time.RFC3339)
	}
}

// --- HTTP handlers ---

// handleListDevices returns all enrolled devices (viewer+).
func (s *server) handleListDevices(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "devices": s.devices.list()})
}

type revokeRequest struct {
	DeviceID string `json:"deviceId"`
}

// handleRevokeDevice revokes another device (owner-only). A device may not
// revoke itself (prevents accidentally locking everyone out).
func (s *server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := decodeBody(r, &req); err != nil || req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, errMap("deviceId required", err))
		return
	}
	auth := authFrom(r)
	if d := s.devices.lookup(auth.keyID); d != nil && d.DeviceID == req.DeviceID {
		writeJSON(w, http.StatusBadRequest, errMap("cannot revoke your own device", nil))
		return
	}
	ok, err := s.devices.revoke(req.DeviceID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("revoke", err))
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, errMap("device not found", nil))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
