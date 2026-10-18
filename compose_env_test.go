package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposeEnvDropsAgentConfig(t *testing.T) {
	got := composeEnv([]string{
		"PATH=/bin", "HOME=/root", "NASHUBS_PAIRING_SECRET=s", "NASHUBS_TRUSTED_PUBKEY=k",
		"nashubs_x=1", "NASDECK_PAIRING_SECRET=old", "DOCKER_HOST=unix:///var/run/docker.sock",
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
