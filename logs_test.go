package main

import (
	"strings"
	"testing"
)

func TestComposeLogsTargetsTheDeployedProject(t *testing.T) {
	argv := composeLogsArgs([]string{"docker", "compose"}, "hello", "/volume1/docker/hello/v8e727205d064/docker-compose.yml", false)
	got := strings.Join(argv, " ")
	want := "docker compose -p nashubs-hello -f /volume1/docker/hello/v8e727205d064/docker-compose.yml --project-directory /volume1/docker/hello/v8e727205d064 logs --no-color --tail 200"
	if got != want {
		t.Fatalf("argv mismatch\n got: %s\nwant: %s", got, want)
	}
	// The project name must match what deploy uses (runCompose).
	if !strings.Contains(got, "-p nashubs-hello ") {
		t.Fatal("logs must use the deploy's compose project")
	}
	if f := composeLogsArgs([]string{"docker-compose"}, "a", "/d/a/v1/docker-compose.yml", true); f[len(f)-1] != "-f" || f[0] != "docker-compose" {
		t.Fatalf("follow / compose v1 not handled: %v", f)
	}
}
