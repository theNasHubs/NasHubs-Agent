package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// deployReqAs is deployReq with an explicit role instead of RoleOwner.
func deployReqAs(t *testing.T, s *server, body string, role Role) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), authKey, authResult{role: role}))
	rec := httptest.NewRecorder()
	s.handleDeploy(rec, req)
	return rec
}

// fakeDockerProjectLabel labels every inspected container as belonging to the given
// compose project, simulating a redeploy whose container_name already exists
// inside the same project.
func fakeDockerProjectLabel(t *testing.T, project string) func() string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "argv.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n" +
		"if [ \"$1\" = \"inspect\" ]; then echo " + project + "; fi\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() string { b, _ := os.ReadFile(log); return string(b) }
}

// #27: a non-owner compose naming a foreign container must NOT rm -f it; the
// name conflict is left for `compose up` to fail on.
func TestDeployNonOwnerNeverRemovesForeignContainer(t *testing.T) {
	log := fakeComposeRecorder(t) // inspect returns "" → foreign/unknown container
	dir := t.TempDir()
	s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
	body := `{"id":"evil","compose":"services:\n  x:\n    image: alpine\n    container_name: syncloud-drive-server\n"}`
	rec := deployReqAs(t, s, body, RoleAdmin)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	for _, l := range splitLines(log()) {
		if l == "rm -f syncloud-drive-server" {
			t.Fatal("non-owner deploy force-removed a foreign container")
		}
	}
}

// #27: the same name under this project's compose label IS cleared, so
// non-owner redeploys (e.g. immich's non-prefixed names) keep working.
func TestDeployNonOwnerRemovesOwnProjectContainer(t *testing.T) {
	log := fakeDockerProjectLabel(t, "nashubs-immich")
	dir := t.TempDir()
	s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
	body := `{"id":"immich","compose":"services:\n  db:\n    image: x\n    container_name: immich_redis\n"}`
	rec := deployReqAs(t, s, body, RoleAdmin)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if !containsLine(log(), "rm -f immich_redis") {
		t.Fatalf("expected `rm -f immich_redis` for same-project container; argv:\n%s", log())
	}
}

// #29: a non-owner may not deploy over the remote-access infra ids — doing so
// would rm -f the tunnel container and cut remote access.
func TestDeployInfraRequiresOwner(t *testing.T) {
	for _, id := range []string{"cloudflared", "cloudflared-quick", "cloudflared-login", "tailscale"} {
		log := fakeComposeRecorder(t)
		dir := t.TempDir()
		s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
		body := `{"id":"` + id + `","compose":"services:\n  x:\n    image: alpine\n"}`
		rec := deployReqAs(t, s, body, RoleAdmin)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: status %d, want 403 (%s)", id, rec.Code, rec.Body)
		}
		for _, l := range splitLines(log()) {
			if strings.HasPrefix(l, "rm -f") {
				t.Fatalf("%s: docker rm ran on a rejected deploy: %q", id, l)
			}
		}
	}
}

// #29: deploys that smuggle infra container names are rejected for non-owners
// before the compose is even written.
func TestDeployNonOwnerRejectsInfraContainerName(t *testing.T) {
	log := fakeComposeRecorder(t)
	dir := t.TempDir()
	s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
	body := `{"id":"x","compose":"services:\n  a:\n    image: alpine\n    container_name: nashubs-cloudflared\n"}`
	rec := deployReqAs(t, s, body, RoleAdmin)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403 (%s)", rec.Code, rec.Body)
	}
	for _, l := range splitLines(log()) {
		if strings.HasPrefix(l, "rm -f") {
			t.Fatalf("docker rm ran on a rejected deploy: %q", l)
		}
	}
}

// #29: /remove and /rollback on infra ids are owner-only.
func TestRemoveAndRollbackInfraRequireOwner(t *testing.T) {
	for _, id := range []string{"cloudflared", "tailscale"} {
		dir := t.TempDir()
		s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}}

		req := httptest.NewRequest(http.MethodPost, "/remove/"+id, nil)
		req = req.WithContext(context.WithValue(req.Context(), authKey, authResult{role: RoleAdmin}))
		rec := httptest.NewRecorder()
		s.handleRemove(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("remove %s: status %d, want 403", id, rec.Code)
		}

		req = httptest.NewRequest(http.MethodPost, "/rollback/"+id, nil)
		req = req.WithContext(context.WithValue(req.Context(), authKey, authResult{role: RoleAdmin}))
		rec = httptest.NewRecorder()
		s.handleRollback(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("rollback %s: status %d, want 403", id, rec.Code)
		}
	}
}
