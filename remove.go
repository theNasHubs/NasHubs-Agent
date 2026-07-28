package main

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// handleRemove reads the current state of a deployed project, runs
// `docker compose down` on its current artifact, and entirely removes
// the project state directory to mark it as uninstalled.
func (s *server) handleRemove(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/remove/")
	if !idSafe.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, errMap("bad id", nil))
		return
	}

	projectDir := filepath.Join(s.cfg.DataDir, id)
	st, err := loadState(s.cfg.DataDir, id)
	if err != nil {
		// State not found, just delete the folder if it exists.
		_ = os.RemoveAll(projectDir)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "msg": "already removed or state not found"})
		return
	}

	// Tear down the current deployment if compose file exists
	if st.HostPath != "" {
		_, _ = s.runCompose(st.HostPath, "down")
	}

	// Fallback: forcefully remove any container named nasdeck-{id}
	// This ensures manually run or failed deployments are cleaned up.
	containerName := "nasdeck-" + id
	_ = exec.Command("docker", "rm", "-f", containerName).Run()

	if err := os.RemoveAll(projectDir); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("failed to remove data dir", err))
		return
	}

	// Also clean up cloudflared-quick if removing cloudflared
	if id == "cloudflared" {
		quickDir := filepath.Join(s.cfg.DataDir, "cloudflared-quick")
		if _, err := os.Stat(quickDir); err == nil {
			_ = exec.Command("docker", "rm", "-f", "nasdeck-cloudflared-quick").Run()
			_ = os.RemoveAll(quickDir)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
