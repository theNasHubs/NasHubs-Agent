package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDocker puts a `docker` stub first on PATH that records every invocation,
// so tests can assert whether the privileged nginx helper would have been run.
func fakeDocker(t *testing.T) (calls func() []string) {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		data, err := os.ReadFile(log)
		if err != nil {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

func nginxTestServer(t *testing.T, confDir string) *server {
	t.Helper()
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := saveState(dataDir, "app", deployState{Current: "v1", InternalPort: 8096, PathPrefix: "/app"}); err != nil {
		t.Fatal(err)
	}
	return &server{cfg: Config{DataDir: dataDir, HostDataDir: dataDir, NginxConfDir: confDir}}
}

func TestNginxDisabledValue(t *testing.T) {
	for _, v := range []string{"", "none", "NONE", " off ", "disabled"} {
		if !nginxDisabledValue(v) {
			t.Errorf("%q should disable nginx", v)
		}
	}
	for _, v := range []string{"/etc/nginx/conf.d", "/tmp/none"} {
		if nginxDisabledValue(v) {
			t.Errorf("%q should not disable nginx", v)
		}
	}
}

func TestLoadConfigNginxNone(t *testing.T) {
	t.Setenv("NASHUBS_NGINX_CONF_DIR", "none")
	if got := loadConfig().NginxConfDir; got != "" {
		t.Fatalf("NginxConfDir = %q, want disabled", got)
	}
	t.Setenv("NASHUBS_NGINX_CONF_DIR", "/x/conf.d")
	if got := loadConfig().NginxConfDir; got != "/x/conf.d" {
		t.Fatalf("NginxConfDir = %q", got)
	}
}

func TestNginxDisabledNeverRunsPrivilegedHelper(t *testing.T) {
	calls := fakeDocker(t)
	cwd := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(cwd); err != nil { // a stray relative write would land here
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	s := nginxTestServer(t, "")

	if err := s.testNginx(); !errors.Is(err, errNginxDisabled) {
		t.Fatalf("testNginx: %v", err)
	}
	if err := s.reloadNginx(); !errors.Is(err, errNginxDisabled) {
		t.Fatalf("reloadNginx: %v", err)
	}
	s.ensureSelfProxy()
	s.ensureAllProxies()

	for _, tc := range []struct {
		method, path, body string
		h                  http.HandlerFunc
		want               int
	}{
		{"POST", "/proxy", `{"id":"app","internalPort":8096}`, s.handleProxy, http.StatusServiceUnavailable},
		{"POST", "/proxy", `{"id":"app","remove":true}`, s.handleProxy, http.StatusServiceUnavailable},
		{"POST", "/proxies/configure-all", ``, s.handleConfigureAllProxies, http.StatusServiceUnavailable},
		{"GET", "/proxies", ``, s.handleListProxies, http.StatusOK},
	} {
		rec := httptest.NewRecorder()
		tc.h(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
		if rec.Code != tc.want {
			t.Errorf("%s %s %s = %d, want %d (%s)", tc.method, tc.path, tc.body, rec.Code, tc.want, rec.Body)
		}
	}

	if c := calls(); len(c) != 0 {
		t.Fatalf("docker invoked while nginx disabled: %q", c)
	}
	if entries, _ := os.ReadDir(cwd); len(entries) != 0 {
		t.Fatalf("files written to cwd: %v", entries)
	}
}

func TestNginxNotTestedWhenConfWriteFails(t *testing.T) {
	calls := fakeDocker(t)
	s := nginxTestServer(t, filepath.Join(t.TempDir(), "missing-dir"))
	s.ensureSelfProxy()
	s.ensureAllProxies()
	if c := calls(); len(c) != 0 {
		t.Fatalf("nginx helper run although no conf was written: %q", c)
	}
}

// Positive control: with a writable conf dir the helper does run, which proves
// the stub above is actually what the agent would execute.
func TestNginxEnabledRunsHelper(t *testing.T) {
	calls := fakeDocker(t)
	s := nginxTestServer(t, t.TempDir())
	s.ensureSelfProxy()
	c := calls()
	if len(c) == 0 || !strings.Contains(c[0], "nginx -t") {
		t.Fatalf("expected nginx -t via helper, got %q", c)
	}
}
