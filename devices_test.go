package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeviceStoreEnrollRevokePersist(t *testing.T) {
	dir := t.TempDir()
	ds := newDeviceStore(dir)

	if !ds.isEmpty() {
		t.Fatal("a fresh store should be empty")
	}

	d, err := ds.enroll("keyA", "iPhone", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if d.Role != RoleAdmin || d.DeviceID == "" {
		t.Fatalf("unexpected device: %+v", d)
	}
	if ds.isEmpty() {
		t.Fatal("store should not be empty after enroll")
	}

	// Enrolling the same active key again is idempotent (same device, role kept).
	d2, err := ds.enroll("keyA", "iPhone", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if d2.DeviceID != d.DeviceID || d2.Role != RoleAdmin {
		t.Fatalf("re-enroll should return the same owner device, got %+v", d2)
	}

	// Revoke and confirm it is rejected + counted as empty.
	ok, err := ds.revoke(d.DeviceID)
	if err != nil || !ok {
		t.Fatalf("revoke failed ok=%v err=%v", ok, err)
	}
	if got := ds.lookup("keyA"); got == nil || !got.revoked() {
		t.Fatal("device should be revoked")
	}
	if !ds.isEmpty() {
		t.Fatal("a store with only revoked devices should count as empty")
	}

	// Revocation must survive a reload from disk.
	ds2 := newDeviceStore(dir)
	if got := ds2.lookup("keyA"); got == nil || !got.revoked() {
		t.Fatal("revocation should persist across reload")
	}
}

func TestLegacyRolesMigrateToAdminAndMember(t *testing.T) {
	dir := t.TempDir()
	legacy := `[{"deviceId":"a","keyId":"k1","label":"owner phone","role":"owner","pairedAt":"2026-10-19T00:00:00Z"},
{"deviceId":"b","keyId":"k2","label":"second","role":"admin","pairedAt":"2026-10-19T00:00:00Z"},
{"deviceId":"c","keyId":"k3","label":"family","role":"viewer","pairedAt":"2026-10-19T00:00:00Z"}]`
	if err := os.WriteFile(filepath.Join(dir, "devices.json"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	ds := newDeviceStore(dir)
	if ds.loadErr != nil {
		t.Fatal(ds.loadErr)
	}
	for k, want := range map[string]Role{"k1": RoleAdmin, "k2": RoleAdmin, "k3": RoleMember} {
		if d := ds.lookup(k); d == nil || d.Role != want {
			t.Fatalf("%s: %+v", k, d)
		}
	}
	// The migration is written back, so the next start reads the new roles directly.
	b, _ := os.ReadFile(filepath.Join(dir, "devices.json"))
	if bytes.Contains(b, []byte(`"owner"`)) || bytes.Contains(b, []byte(`"viewer"`)) {
		t.Fatal(string(b))
	}
	if ds.activeAdmins() != 2 {
		t.Fatal(ds.activeAdmins())
	}
}

func TestRevokeRules(t *testing.T) {
	dir := t.TempDir()
	s := &server{devices: newDeviceStore(dir)}
	admin, _ := s.devices.enroll("ka", "admin", RoleAdmin)
	member, _ := s.devices.enroll("km", "member", RoleMember)
	other, _ := s.devices.enroll("ko", "other member", RoleMember)
	call := func(key string, role Role, id string) int {
		req := httptest.NewRequest("POST", "/devices/revoke", strings.NewReader(`{"deviceId":"`+id+`"}`))
		req = req.WithContext(context.WithValue(req.Context(), authKey, authResult{keyID: key, role: role}))
		rec := httptest.NewRecorder()
		s.handleRevokeDevice(rec, req)
		return rec.Code
	}
	if c := call("km", RoleMember, other.DeviceID); c != 403 {
		t.Fatalf("member revoked another device: %d", c)
	}
	if c := call("ka", RoleAdmin, admin.DeviceID); c != 400 {
		t.Fatalf("last admin revoked itself: %d", c)
	}
	if c := call("km", RoleMember, member.DeviceID); c != 200 {
		t.Fatalf("member could not sign out: %d", c)
	}
	if c := call("ka", RoleAdmin, other.DeviceID); c != 200 {
		t.Fatalf("admin could not revoke: %d", c)
	}
}
