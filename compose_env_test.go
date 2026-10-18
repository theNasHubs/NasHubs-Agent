package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposeEnvIsAllowlist(t *testing.T) {
	got := composeEnv([]string{
		"PATH=/bin", "HOME=/root", "NASHUBS_PAIRING_SECRET=s", "NASHUBS_TRUSTED_PUBKEY=k",
		"nashubs_x=1", "NASDECK_PAIRING_SECRET=old", "DOCKER_HOST=unix:///var/run/docker.sock",
		"CLOUDFLARE_TOKEN=t", "TS_AUTHKEY=a", "SOME_FUTURE_SECRET=f", "PATHX=1",
	})
	want := "PATH=/bin HOME=/root DOCKER_HOST=unix:///var/run/docker.sock"
	if strings.Join(got, " ") != want {
		t.Fatalf("composeEnv = %q, want %q", got, want)
	}
}

// The compose CLI started by runCompose must not see the pairing secret.
func TestRunComposeDoesNotLeakSecretToCLI(t *testing.T) {
	bin := t.TempDir()
	dump := filepath.Join(bin, "env.txt")
	script := "#!/bin/sh\nenv > " + dump + "\n"
	if err := os.WriteFile(filepath.Join(bin, "fakecompose"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NASHUBS_PAIRING_SECRET", "super-secret-value")
	t.Setenv("CLOUDFLARE_API_TOKEN", "super-secret-value")
	s := &server{composeArgs: []string{filepath.Join(bin, "fakecompose")}}
	if _, err := s.runCompose("/x/docker-compose.yml", "app", "up", "-d"); err != nil {
		t.Fatal(err)
	}
	env, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(env), "super-secret-value") {
		t.Fatal("pairing secret visible to the compose CLI")
	}
	if !strings.Contains(string(env), "COMPOSE_COMPATIBILITY=true") {
		t.Fatal("compose env not applied")
	}
}

// With the real compose CLI: agent variables are not interpolated into a
// deployed compose, while a project .env file still is.
func TestRealComposeInterpolation(t *testing.T) {
	argv := detectCompose()
	if len(argv) == 0 {
		t.Skip("no compose CLI")
	}
	if _, err := exec.Command(argv[0], append(argv[1:], "version")...).CombinedOutput(); err != nil {
		t.Skip("compose CLI not usable")
	}
	dir := t.TempDir()
	compose := "services:\n  a:\n    image: alpine\n    environment:\n      - LEAK=${NASHUBS_PAIRING_SECRET:-none}\n      - FROM_DOTENV=${APP_VALUE}\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_VALUE=from-dotenv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NASHUBS_PAIRING_SECRET", "super-secret-value")
	s := &server{composeArgs: argv}
	out, err := s.runCompose(filepath.Join(dir, "docker-compose.yml"), "envtest", "config")
	if err != nil {
		t.Fatalf("compose config: %v\n%s", err, out)
	}
	if strings.Contains(out, "super-secret-value") || !strings.Contains(out, "LEAK: none") {
		t.Fatalf("agent secret interpolated:\n%s", out)
	}
	if !strings.Contains(out, "FROM_DOTENV: from-dotenv") {
		t.Fatalf(".env interpolation broken:\n%s", out)
	}
}
