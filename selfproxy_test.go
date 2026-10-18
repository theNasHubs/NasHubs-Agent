package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDockerNginx stubs docker; `nginx -t` fails when failTest is true.
func fakeDockerNginx(t *testing.T, failTest bool) func() []string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n"
	if failTest {
		script += "case \"$*\" in *'nginx -t'*) echo 'duplicate location'; exit 1;; esac\n"
	}
	script += "exit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		b, _ := os.ReadFile(log)
		if len(b) == 0 {
			return nil
		}
		return strings.Split(strings.TrimSpace(string(b)), "\n")
	}
}

func readConf(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func TestSelfProxyInstallsLegacyAlias(t *testing.T) {
	calls := fakeDockerNginx(t, false)
	dir := t.TempDir()
	s := &server{cfg: Config{NginxConfDir: dir}}
	s.ensureSelfProxy()
	if !strings.Contains(readConf(t, filepath.Join(dir, "dsm.nashubs-agent.conf")), "location ^~ /nashubs-agent/") {
		t.Fatal("self proxy conf missing")
	}
	legacy := readConf(t, filepath.Join(dir, "dsm.nasdeck-agent.conf"))
	if !strings.Contains(legacy, "location ^~ /nasdeck-agent/") || !strings.Contains(legacy, "proxy_pass https://127.0.0.1:8443/;") {
		t.Fatalf("legacy alias conf = %q", legacy)
	}
	if len(calls()) == 0 {
		t.Fatal("nginx not tested/reloaded")
	}

	// Second boot: nothing changes, nginx is not touched.
	n := len(calls())
	s.ensureSelfProxy()
	if len(calls()) != n {
		t.Fatalf("idempotent boot touched nginx: %q", calls()[n:])
	}
}

func TestSelfProxyKeepsLeftoverLegacyConf(t *testing.T) {
	fakeDockerNginx(t, false)
	dir := t.TempDir()
	leftover := "# written by the Nasdeck agent\nlocation ^~ /nasdeck-agent/ { proxy_pass https://127.0.0.1:8443/; }\n"
	p := filepath.Join(dir, "dsm.nasdeck-agent.conf")
	if err := os.WriteFile(p, []byte(leftover), 0o644); err != nil {
		t.Fatal(err)
	}
	(&server{cfg: Config{NginxConfDir: dir}}).ensureSelfProxy()
	if readConf(t, p) != leftover {
		t.Fatal("leftover Nasdeck conf was modified")
	}
}

func TestSelfProxyRollsBackWhenNginxTestFails(t *testing.T) {
	calls := fakeDockerNginx(t, true)
	dir := t.TempDir()
	old := "# previous self proxy\n"
	self := filepath.Join(dir, "dsm.nashubs-agent.conf")
	if err := os.WriteFile(self, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	(&server{cfg: Config{NginxConfDir: dir}}).ensureSelfProxy()
	if readConf(t, self) != old {
		t.Fatalf("self proxy not restored: %q", readConf(t, self))
	}
	if _, err := os.Stat(filepath.Join(dir, "dsm.nasdeck-agent.conf")); !os.IsNotExist(err) {
		t.Fatal("legacy conf left behind after failed nginx -t")
	}
	for _, c := range calls() {
		if strings.Contains(c, "reload") || strings.Contains(c, "restart") {
			t.Fatalf("nginx reloaded after failed test: %q", calls())
		}
	}
}
