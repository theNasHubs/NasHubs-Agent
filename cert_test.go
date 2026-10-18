package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnsureCertStableAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	_, fp1, err := ensureCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := ensureCert(dir)
	if err != nil || fp1 != fp2 {
		t.Fatalf("fingerprint changed: %s → %s (%v)", fp1, fp2, err)
	}
	for _, f := range []string{"agent.crt", "agent.key"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

// A damaged or half-present cert must not be replaced silently: that would
// change the fingerprint every paired app pins.
func TestEnsureCertRefusesToReplaceBrokenCert(t *testing.T) {
	cases := map[string]func(dir string){
		"corrupt cert": func(dir string) { os.WriteFile(filepath.Join(dir, "agent.crt"), []byte("garbage"), 0o600) },
		"corrupt key":  func(dir string) { os.WriteFile(filepath.Join(dir, "agent.key"), []byte("garbage"), 0o600) },
		"key missing":  func(dir string) { os.Remove(filepath.Join(dir, "agent.key")) },
		"cert missing": func(dir string) { os.Remove(filepath.Join(dir, "agent.crt")) },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, _, err := ensureCert(dir); err != nil {
				t.Fatal(err)
			}
			damage(dir)
			before := snapshot(t, dir)
			_, _, err := ensureCert(dir)
			if err == nil || !strings.Contains(err.Error(), "refusing to replace") {
				t.Fatalf("err = %v", err)
			}
			if after := snapshot(t, dir); after != before {
				t.Fatal("cert files were modified")
			}
		})
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var s strings.Builder
	for _, f := range []string{"agent.crt", "agent.key"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			s.WriteString(f + ":missing;")
			continue
		}
		s.WriteString(f + ":" + string(b) + ";")
	}
	return s.String()
}
