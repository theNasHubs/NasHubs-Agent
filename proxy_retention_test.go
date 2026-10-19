package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #31: the agent's own proxy conf must not be writable or removable through
// /proxy — an admin could otherwise sever remote access to the agent.
func TestProxyRejectsReservedAgentID(t *testing.T) {
	confDir := t.TempDir()
	confFile := filepath.Join(confDir, "dsm.nashubs-agent.conf")
	if err := os.WriteFile(confFile, []byte("location ^~ /nashubs-agent/ {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: Config{NginxConfDir: confDir}}

	for _, body := range []string{
		`{"id":"agent","remove":true}`,
		`{"id":"agent","internalPort":9999,"pathPrefix":"/x"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/proxy", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleProxy(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403", body, rec.Code)
		}
	}
	if _, err := os.Stat(confFile); err != nil {
		t.Fatalf("agent proxy conf was removed: %v", err)
	}
}

// #33: deploy artifacts are immutable and must not accumulate forever.
func TestPruneVersionsKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	var names []string
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("v%012x", i+1)
		names = append(names, name)
		vd := filepath.Join(dir, name)
		if err := os.MkdirAll(vd, 0o755); err != nil {
			t.Fatal(err)
		}
		// Oldest → newest so ModTime ordering is deterministic.
		mt := time.Now().Add(-time.Duration(8-i) * time.Hour)
		_ = os.Chtimes(vd, mt, mt)
	}
	// Non-version entries must be left alone.
	for _, extra := range []string{"state.json", "data", "vshort"} {
		p := filepath.Join(dir, extra)
		if strings.HasSuffix(extra, ".json") {
			_ = os.WriteFile(p, []byte("{}"), 0o600)
		} else {
			_ = os.MkdirAll(p, 0o755)
		}
	}

	pruneVersions(dir, 5)

	entries, _ := os.ReadDir(dir)
	remaining := map[string]bool{}
	for _, e := range entries {
		remaining[e.Name()] = true
	}
	for i, name := range names {
		want := i >= 3 // keep the 5 newest
		if remaining[name] != want {
			t.Fatalf("%s remaining=%v, want %v", name, remaining[name], want)
		}
	}
	for _, extra := range []string{"state.json", "data", "vshort"} {
		if !remaining[extra] {
			t.Fatalf("non-version entry %s was pruned", extra)
		}
	}
}
