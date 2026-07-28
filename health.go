package main

import (
	"net/http"
	"path/filepath"
	"strings"
)

// handleHealth reports a coarse running state for a deployed project by asking
// `docker compose ps`. (A real HTTP health probe of the service port is a
// follow-up; for now we report whether any service container is up.)
func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/health/")
	if !idSafe.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, errMap("bad id", nil))
		return
	}
	st, err := loadState(s.cfg.DataDir, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errMap("no such deploy", err))
		return
	}
	// Probe both `ps` (running) and `ps -a` (running + stopped) so we can tell
	// "stopped" from "deleted" via the shared classifier in state.go. The old
	// "non-empty ⇒ up" check was also wrong on docker-compose v1, which prints a
	// header row even for an empty project.
	runningOut, _ := s.runCompose(st.HostPath, id, "ps")
	allOut, _ := s.runCompose(st.HostPath, id, "ps", "-a")
	state := classifyState(runningOut, allOut)
	trimmed := strings.TrimSpace(runningOut)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":     id,
		"state":  state,
		"detail": trimmed,
		"path":   filepath.Dir(st.HostPath),
	})
}
