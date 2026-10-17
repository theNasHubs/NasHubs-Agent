package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
}

func newDeviceStore(dir string) *deviceStore {
	ds := &deviceStore{path: filepath.Join(dir, "devices.json"), devices: map[string]*Device{}}
	ds.load()
	return ds
}

func (ds *deviceStore) load() {
	b, err := os.ReadFile(ds.path)
	if err != nil {
		return // no store yet
	}
	var list []*Device
	if json.Unmarshal(b, &list) != nil {
		return
	}
	for _, d := range list {
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
	// fsync before rename so a power loss cannot leave a truncated devices.json, which
	// load() would treat as an empty store (un-revoking every device).
	tmp := ds.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, ds.path)
}

// lookup returns a snapshot of the device for a keyID (or nil). It is a copy so callers can
// read Role/RevokedAt without holding ds.mu while revoke() mutates the stored device.
func (ds *deviceStore) lookup(keyID string) *Device {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	d := ds.devices[keyID]
	if d == nil {
		return nil
	}
	c := *d
	return &c
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
	if d, ok := ds.devices[keyID]; ok && !d.revoked() {
		return d, nil
	}
	idBytes := make([]byte, 8)
	_, _ = rand.Read(idBytes)
	d := &Device{
		DeviceID: hex.EncodeToString(idBytes),
		KeyID:    keyID,
		Label:    label,
		Role:     role,
		PairedAt: time.Now().UTC().Format(time.RFC3339),
	}
	ds.devices[keyID] = d
	if err := ds.persistLocked(); err != nil {
		return nil, err
	}
	return d, nil
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
			return true, ds.persistLocked()
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
