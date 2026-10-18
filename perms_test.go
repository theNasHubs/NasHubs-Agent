package main

import (
	"os"
	"path/filepath"
	"testing"
)

func mode(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestWritePrivateFileTightensExisting(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, p); m != 0o600 {
		t.Fatalf("mode = %o, want 600", m)
	}
}

func TestSaveStateIsPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := saveState(dir, "app", deployState{Current: "v1"}); err != nil {
		t.Fatal(err)
	}
	if m := mode(t, statePath(dir, "app")); m != 0o600 {
		t.Fatalf("state.json mode = %o, want 600", m)
	}
}

func TestTightenDataFilePerms(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, m os.FileMode) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), m); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, m); err != nil {
			t.Fatal(err)
		}
		return p
	}
	private := []string{
		write("devices.json", 0o644),
		write("agent.key", 0o640),
		write("app/state.json", 0o644),
		write("app/v123/docker-compose.yml", 0o664),
	}
	appData := write("app/v123/data/config.yml", 0o644) // app data: must stay as is
	tightenDataFilePerms(dir)
	for _, p := range private {
		if m := mode(t, p); m != 0o600 {
			t.Errorf("%s mode = %o, want 600", p, m)
		}
	}
	if m := mode(t, appData); m != 0o644 {
		t.Errorf("app data mode changed to %o", m)
	}
}
