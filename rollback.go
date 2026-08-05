package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// handleRollback repoints the "current" version of a project to the previous
// deployed artifact and re-runs `docker compose up -d`.
func (s *server) handleRollback(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/rollback/")
	if !idSafe.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, errMap("bad id", nil))
		return
	}
	projectDir := filepath.Join(s.cfg.DataDir, id)
	entries, err := os.ReadDir(projectDir)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errMap("no such deploy", err))
		return
	}

	type versionEntry struct {
		name    string
		modTime time.Time
	}
	var versions []versionEntry
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") {
			info, err := e.Info()
			if err != nil {
				continue
			}
			versions = append(versions, versionEntry{name: e.Name(), modTime: info.ModTime()})
		}
	}
	// Sort by modification time, newest first (correct chronological order).
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].modTime.After(versions[j].modTime)
	})

	st, _ := loadState(s.cfg.DataDir, id)
	current := st.Current
	target := ""
	for _, v := range versions {
		if v.name == current {
			continue
		}
		target = v.name // first one that isn't current = previous (list is desc by time)
		break
	}
	if target == "" {
		writeJSON(w, http.StatusConflict, errMap("no previous version to roll back to", nil))
		return
	}

	hostCompose := filepath.Join(s.cfg.HostDataDir, id, target, "docker-compose.yml")
	out, runErr := s.runCompose(hostCompose, id, "up", "-d")
	_ = saveState(s.cfg.DataDir, id, deployState{
		Current:   target,
		HostPath:  hostCompose,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	resp := map[string]any{
		"ok":       runErr == nil,
		"version":  target,
		"previous": current,
		"output":   out,
	}
	code := http.StatusOK
	if runErr != nil {
		code = http.StatusUnprocessableEntity
	}
	writeJSON(w, code, resp)
}
