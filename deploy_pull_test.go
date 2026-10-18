package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeComposeRecorder installs a `docker` stub on PATH that appends its full
// argv to a log, so a test can see whether `compose pull` ran before `up`.
func fakeComposeRecorder(t *testing.T) func() string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "argv.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() string { b, _ := os.ReadFile(log); return string(b) }
}

func deployReq(t *testing.T, s *server, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), authKey, authResult{role: RoleOwner}))
	rec := httptest.NewRecorder()
	s.handleDeploy(rec, req)
	return rec
}

func TestDeployPullRunsComposePullBeforeUp(t *testing.T) {
	log := fakeComposeRecorder(t)
	dir := t.TempDir()
	s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
	body, _ := json.Marshal(map[string]any{"id": "app", "compose": "services:\n  a:\n    image: alpine\n", "pull": true})
	if rec := deployReq(t, s, string(body)); rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	out := log()
	pull := strings.Index(out, " pull")
	up := strings.Index(out, " up -d")
	if pull < 0 || up < 0 || pull > up {
		t.Fatalf("expected `pull` before `up -d`; argv:\n%s", out)
	}
}

func TestDeployWithoutPullSkipsComposePull(t *testing.T) {
	log := fakeComposeRecorder(t)
	dir := t.TempDir()
	s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
	body, _ := json.Marshal(map[string]any{"id": "app", "compose": "services:\n  a:\n    image: alpine\n"})
	if rec := deployReq(t, s, string(body)); rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	for _, line := range strings.Split(strings.TrimSpace(log()), "\n") {
		if strings.Contains(line, "compose") && strings.HasSuffix(strings.TrimSpace(line), "pull") {
			t.Fatalf("compose pull ran without pull:true: %q", line)
		}
	}
}
