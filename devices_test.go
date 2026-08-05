package main

import "testing"

func TestDeviceStoreEnrollRevokePersist(t *testing.T) {
	dir := t.TempDir()
	ds := newDeviceStore(dir)

	if !ds.isEmpty() {
		t.Fatal("a fresh store should be empty")
	}

	d, err := ds.enroll("keyA", "iPhone", RoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if d.Role != RoleOwner || d.DeviceID == "" {
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
	if d2.DeviceID != d.DeviceID || d2.Role != RoleOwner {
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
