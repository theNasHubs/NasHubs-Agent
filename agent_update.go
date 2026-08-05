package main

import (
	"context"
	"net/http"
	"os/exec"
	"time"
)

// handleAgentUpdate pulls the latest agent image so the container can be
// recreated on a newer version. This is a TYPED, fixed-argument action that
// replaces the removed generic POST /exec/{container} endpoint: it never
// accepts an arbitrary command or container from the client — it only ever runs
// `docker pull <configured agent image>`.
func (s *server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "pull", s.cfg.AgentImage).CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":     false,
			"image":  s.cfg.AgentImage,
			"output": string(out),
			"error":  err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"image":  s.cfg.AgentImage,
		"output": string(out),
	})
}
