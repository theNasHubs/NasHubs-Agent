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

// Role is the permission level of an enrolled device. It mirrors the DSM account
// that paired it:
//
//	admin  — a DSM administrator: runs the Agent, installs and configures mini-apps,
//	         manages devices and remote access. All admins are equal.
//	member — an ordinary DSM user: uses the mini-apps that are open to members.
type Role string

const (
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"

	// Roles stored by agents before 2.2; read once and migrated.
	legacyRoleOwner  Role = "owner"
	legacyRoleViewer Role = "viewer"
)

// normalizeRole maps legacy role names onto the two current roles.
// It returns "" for anything else.
func normalizeRole(r Role) Role {
	switch r {
	case RoleAdmin, legacyRoleOwner:
		return RoleAdmin
	case RoleMember, legacyRoleViewer:
		return RoleMember
	}
	return ""
}

// Device is one enrolled client identity.
type Device struct {
	DeviceID  string `json:"deviceId"`
	KeyID     string `json:"keyId"` // base64 Ed25519 public key (== the signing key)
	Label     string `json:"label"`
	Role      Role   `json:"role"`
	DSMUser   string `json:"dsmUser,omitempty"` // DSM account that paired this device (empty for devices paired before 2.2)
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
	if ds.load() {
		ds.mu.Lock()
		if err := ds.persistLocked(); err != nil {
			ds.loadErr = err
		}
		ds.mu.Unlock()
	}
	return ds
}

// load reads the store and reports whether legacy roles were migrated (the caller persists).
func (ds *deviceStore) load() (migrated bool) {
	b, err := os.ReadFile(ds.path)
	if err != nil {
		if !os.IsNotExist(err) {
			ds.loadErr = err
		}
		return false // no store yet
	}
	var list []*Device
	if err := json.Unmarshal(b, &list); err != nil {
		ds.loadErr = err
		return false
	}
	if list == nil {
		ds.loadErr = fmt.Errorf("invalid device store")
		return false
	}
	for _, d := range list {
		if d == nil || d.KeyID == "" || normalizeRole(d.Role) == "" || ds.devices[d.KeyID] != nil {
			ds.loadErr = fmt.Errorf("invalid device store")
			ds.devices = map[string]*Device{}
			return false
		}
		if r := normalizeRole(d.Role); r != d.Role {
			d.Role = r
			migrated = true
		}
		ds.devices[d.KeyID] = d
	}
	return migrated
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

// activeAdmins counts admin devices that are not revoked.
func (ds *deviceStore) activeAdmins() int {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	n := 0
	for _, d := range ds.devices {
		if d.Role == RoleAdmin && !d.revoked() {
			n++
		}
	}
	return n
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
	return ds.enrollAs(keyID, label, role, "")
}

// enrollAs enrolls a device paired by a known DSM account.
func (ds *deviceStore) enrollAs(keyID, label string, role Role, dsmUser string) (*Device, error) {
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
		DSMUser:  dsmUser,
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

// handleRevokeDevice revokes a device. Admins revoke any device; members only their own
// (signing out). The last admin device cannot revoke itself, so the NAS always keeps one.
func (s *server) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := decodeBody(r, &req); err != nil || req.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, errMap("deviceId required", err))
		return
	}
	auth := authFrom(r)
	self := s.devices.lookup(auth.keyID)
	own := self != nil && self.DeviceID == req.DeviceID
	if auth.role != RoleAdmin && !own {
		writeJSON(w, http.StatusForbidden, errMap("insufficient role", nil))
		return
	}
	if own && auth.role == RoleAdmin && s.devices.activeAdmins() <= 1 {
		writeJSON(w, http.StatusBadRequest, errMap("cannot revoke the last admin device", nil))
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
