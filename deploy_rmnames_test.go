package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestComposeContainerNames(t *testing.T) {
	compose := `
services:
  server:
    image: x
    container_name: immich_server
  db:
    image: y
    container_name: immich_postgres
  noname:
    image: z
  evil:
    image: w
    container_name: "-rf"
`
	got := composeContainerNames([]byte(compose))
	sort.Strings(got)
	want := []string{"immich_postgres", "immich_server"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v (a leading-dash name must be skipped)", got, want)
	}
}

func TestComposeContainerNamesInvalidYAML(t *testing.T) {
	if n := composeContainerNames([]byte("services: [")); n != nil {
		t.Fatalf("invalid yaml should yield nil, got %v", n)
	}
}

// The deploy handler must rm -f the container_name declared in the compose,
// so a redeploy (incl. of an app from the old agent) does not hit a 422.
func TestDeployRemovesDeclaredContainerName(t *testing.T) {
	log := fakeComposeRecorder(t) // from deploy_pull_test.go
	dir := t.TempDir()
	s := &server{cfg: Config{DataDir: dir, HostDataDir: dir}, composeArgs: []string{"docker", "compose"}}
	body := `{"id":"immich","compose":"services:\n  server:\n    image: x\n    container_name: immich_server\n"}`
	rec := deployReq(t, s, body) // from deploy_pull_test.go
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	out := log()
	if !containsLine(out, "rm -f immich_server") {
		t.Fatalf("expected `rm -f immich_server`; argv:\n%s", out)
	}
	if !containsLine(out, "rm -f nashubs-immich") {
		t.Fatalf("expected `rm -f nashubs-immich`; argv:\n%s", out)
	}
}

func containsLine(out, want string) bool {
	for _, l := range splitLines(out) {
		if l == want {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			lines = append(lines, cur)
			cur = ""
		} else {
			cur += string(r)
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
