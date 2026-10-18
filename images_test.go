package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelperImagesArePinned(t *testing.T) {
	for _, img := range []string{helperImage, cloudflaredImage} {
		_, d, ok := strings.Cut(img, "@")
		if !ok || !imageDigest.MatchString(d) {
			t.Errorf("%s is not pinned by digest", img)
		}
	}
}

func TestNormalizeRepo(t *testing.T) {
	for in, want := range map[string]string{
		"docker.io/library/alpine": "alpine", "alpine": "alpine", "index.docker.io/library/alpine": "alpine",
		"docker.io/cloudflare/cloudflared": "cloudflare/cloudflared", "ghcr.io/o/agent": "ghcr.io/o/agent",
	} {
		if got := normalizeRepo(in); got != want {
			t.Errorf("normalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImageRepo(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/thenashubs/nashubs-agent:latest":       "ghcr.io/thenashubs/nashubs-agent",
		"ghcr.io/thenashubs/nashubs-agent":              "ghcr.io/thenashubs/nashubs-agent",
		"localhost:5000/agent:v1":                       "localhost:5000/agent",
		"localhost:5000/agent":                          "localhost:5000/agent",
		"alpine:3.24@sha256:" + strings.Repeat("a", 64): "alpine",
	} {
		if got := imageRepo(in); got != want {
			t.Errorf("imageRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeDockerInspect stubs docker: logs every call and answers
// `docker image inspect` with repo@<digest>.
func fakeDockerInspect(t *testing.T, repo, digest string) func() []string {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(bin, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\n" +
		"if [ \"$1\" = image ]; then echo " + repo + "@" + digest + "; fi\nexit 0\n"
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

func agentUpdate(t *testing.T, body string) (int, map[string]any) {
	t.Helper()
	s := &server{cfg: Config{AgentImage: "ghcr.io/o/agent:latest"}}
	rec := httptest.NewRecorder()
	s.handleAgentUpdate(rec, httptest.NewRequest(http.MethodPost, "/agent/update", strings.NewReader(body)))
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

func TestAgentUpdateWithoutDigestReportsDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("1", 64)
	calls := fakeDockerInspect(t, "ghcr.io/o/agent", d)
	for _, body := range []string{"", "{}"} {
		code, m := agentUpdate(t, body)
		if code != 200 || m["digest"] != d {
			t.Fatalf("body %q: %d %v", body, code, m)
		}
	}
	for _, c := range calls() {
		if strings.HasPrefix(c, "tag ") {
			t.Fatalf("unexpected re-tag: %q", calls())
		}
	}
	if c := calls(); c[0] != "pull ghcr.io/o/agent:latest" {
		t.Fatalf("calls = %q", c)
	}
}

func TestAgentUpdatePinnedDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("2", 64)
	calls := fakeDockerInspect(t, "ghcr.io/o/agent", d)
	code, m := agentUpdate(t, `{"digest":"`+d+`"}`)
	if code != 200 || m["digest"] != d {
		t.Fatalf("%d %v", code, m)
	}
	c := calls()
	if len(c) < 2 || c[0] != "pull ghcr.io/o/agent@"+d || c[1] != "tag ghcr.io/o/agent@"+d+" ghcr.io/o/agent:latest" {
		t.Fatalf("calls = %q", c)
	}
}

func TestAgentUpdateDigestMismatch(t *testing.T) {
	calls := fakeDockerInspect(t, "ghcr.io/o/agent", "sha256:"+strings.Repeat("3", 64))
	code, m := agentUpdate(t, `{"digest":"sha256:`+strings.Repeat("4", 64)+`"}`)
	if code == 200 || m["ok"] != false {
		t.Fatalf("mismatch accepted: %d %v (%q)", code, m, calls())
	}
}

func TestAgentUpdateRejectsBadDigest(t *testing.T) {
	calls := fakeDockerInspect(t, "ghcr.io/o/agent", "sha256:"+strings.Repeat("5", 64))
	for _, d := range []string{"latest", "sha256:abc", "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 64) + " --help"} {
		if code, _ := agentUpdate(t, `{"digest":"`+d+`"}`); code != http.StatusBadRequest {
			t.Errorf("digest %q: %d", d, code)
		}
	}
	if code, _ := agentUpdate(t, `{bad`); code != http.StatusBadRequest {
		t.Errorf("bad json: %d", code)
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("docker called for invalid input: %q", c)
	}
}
