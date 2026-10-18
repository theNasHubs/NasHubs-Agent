package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// handleAgentUpdate pulls the latest agent image so the container can be
// recreated on a newer version. This is a TYPED, fixed-argument action that
// replaces the removed generic POST /exec/{container} endpoint: it never
// accepts an arbitrary command or container from the client — it only ever runs
// `docker pull <configured agent image>`.
//
// An optional body {"digest":"sha256:…"} pins the update: the agent pulls
// <repo>@<digest>, which Docker verifies against the content, and only then
// re-tags it as the configured image. The response always reports the digest
// that the configured image now resolves to, so the app can compare it.
func (s *server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Digest string `json:"digest"`
	}
	body, _ := io.ReadAll(r.Body)
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, errMap("bad request", err))
			return
		}
	}
	pullRef := s.cfg.AgentImage
	if req.Digest != "" {
		ref, err := pinnedRef(s.cfg.AgentImage, req.Digest)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errMap("invalid digest", err))
			return
		}
		pullRef = ref
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "pull", pullRef).CombinedOutput()
	if err == nil && pullRef != s.cfg.AgentImage {
		var tagOut []byte
		tagOut, err = exec.CommandContext(ctx, "docker", "tag", pullRef, s.cfg.AgentImage).CombinedOutput()
		out = append(out, tagOut...)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":     false,
			"image":  s.cfg.AgentImage,
			"output": string(out),
			"error":  err.Error(),
		})
		return
	}
	digest := ""
	if d, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{range .RepoDigests}}{{println .}}{{end}}", s.cfg.AgentImage).Output(); err == nil {
		repo := normalizeRepo(imageRepo(s.cfg.AgentImage))
		for _, line := range strings.Split(string(d), "\n") {
			if r, dg, ok := strings.Cut(strings.TrimSpace(line), "@"); ok && normalizeRepo(r) == repo {
				digest = dg
				break
			}
		}
	}
	if req.Digest != "" && digest != req.Digest {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":     false,
			"image":  s.cfg.AgentImage,
			"digest": digest,
			"error":  "pulled image does not match the requested digest",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"image":  s.cfg.AgentImage,
		"digest": digest,
		"output": string(out),
	})
}
