package main

import (
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// Deployment inventory + drift reconciliation.
//
// Painpoint: the app could not tell that a mini-app container was deleted or
// stopped outside the agent (e.g. via the Synology DSM UI or `docker rm`). The
// old /health collapsed "stopped" and "deleted" both into "down", and was even
// wrong on docker-compose v1 (it prints a header row for an empty project,
// which the old "non-empty ⇒ up" check read as "up").
//
// GET /state lists every deployment the agent has ever made (one row per
// <DataDir>/<id>/state.json), each annotated with its true container state:
//   "up"      — at least one running container
//   "down"    — a container exists but is stopped
//   "missing" — no container at all (deleted externally = drift)
//   "unknown" — could not probe (daemon down, compose file wiped, orphan dir)

const (
	stUp      = "up"
	stDown    = "down"
	stMissing = "missing"
	stUnknown = "unknown"
)

type deploymentStatus struct {
	ID           string `json:"id"`
	Current      string `json:"current"`
	HostPath     string `json:"hostPath"`
	UpdatedAt    string `json:"updatedAt"`
	State        string `json:"state"`
	InternalPort int    `json:"internalPort,omitempty"`
	PathPrefix   string `json:"pathPrefix,omitempty"`
}

// classifyState maps raw `docker compose ps` stdout (no daemon, pure) into the
// 3-state value. runningOut = `docker compose ps`; allOut = `docker compose ps -a`.
func classifyState(runningOut, allOut string) string {
	switch {
	case hasData(runningOut):
		return stUp
	case hasData(allOut):
		return stDown
	default:
		return stMissing
	}
}

// headerKeywords are the column titles compose prints in the table header.
var headerKeywords = []string{
	"name", "container id", "image", "command", "status",
	"ports", "service", "services", "created", "names", "state", "exit code",
}

// hasData reports whether the stdout of `docker compose ps` actually lists at
// least one container. We CANNOT just check "output is non-empty":
//   - docker-compose v1 (DSM 7.0, python) prints a header + dashed separator
//     even when no container exists, so "non-empty ⇒ up" would read as "up".
//   - docker-compose v1 also prints "No containers" / "No containers found".
//
// Strategy: drop empty lines, separator lines, and header lines; the first
// surviving non-empty line is a real data row. We deliberately do NOT match
// status words as substrings: the v2 header contains a CREATED and a STATUS
// column, so substring-matching "created"/"status" would false-positive on the
// header itself. Header detection (all letters+spaces + a known keyword) plus
// separator detection avoids that entirely.
func hasData(out string) bool {
	if strings.Contains(strings.ToLower(out), "no container") {
		// v1 "No containers" / "No containers found" marker ⇒ definitively empty.
		return false
	}
	for _, raw := range strings.Split(out, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || isSeparatorLine(line) || isHeaderLine(line) {
			continue
		}
		return true // first surviving line is a data row
	}
	return false
}

// isHeaderLine detects a compose table header: a line made only of letters and
// spaces that also contains a known column keyword. Data rows always contain
// digits, slashes, dots, quotes or parens (status/ports/image), so they never
// satisfy the "letters+spaces only" half of the test.
func isHeaderLine(line string) bool {
	for _, c := range line {
		isUpper := c >= 'A' && c <= 'Z'
		isLower := c >= 'a' && c <= 'z'
		if !isUpper && !isLower && c != ' ' {
			return false
		}
	}
	low := strings.ToLower(line)
	for _, kw := range headerKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// isSeparatorLine detects a v1 dashed separator line (e.g. a run of '-').
func isSeparatorLine(line string) bool {
	if len(line) < 3 {
		return false
	}
	for _, c := range line {
		if c != '-' && c != '=' {
			return false
		}
	}
	return true
}

// probeState runs the two compose `ps` invocations against a host compose file
// and returns the classified state. This is the only place docker is touched;
// on any compose error (file missing, daemon down) it returns "unknown" rather
// than guessing. runCompose prepends `-f <hostCompose> --project-directory <dir>`.
func (s *server) probeState(id, hostCompose string) string {
	runningOut, runErr := s.runCompose(hostCompose, "ps")
	if runErr != nil {
		return stUnknown
	}
	allOut, _ := s.runCompose(hostCompose, "ps", "-a")
	state := classifyState(runningOut, allOut)
	
	// Fallback for manually deployed or non-compose containers
	if state == stMissing {
		containerName := "nasdeck-" + id
		if exec.Command("docker", "inspect", containerName).Run() == nil {
			// Container exists
			if exec.Command("docker", "ps", "-q", "-f", "name=^/"+containerName+"$").Run() == nil {
				out, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", containerName).Output()
				if strings.TrimSpace(string(out)) == "true" {
					return stUp
				}
				return stDown
			}
		}
	}
	return state
}

// handleState lists all known deployments and their live container state.
// It always returns HTTP 200 (the per-row `state` carries drift); 500 only if
// the data directory itself is unreadable.
func (s *server) handleState(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.cfg.DataDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("read data dir", err))
		return
	}

	out := []deploymentStatus{} // non-nil so empty list serializes as `[]`
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !idSafe.MatchString(id) {
			continue
		}
		st, err := loadState(s.cfg.DataDir, id)
		if err != nil {
			// Orphan dir (no state.json / corrupt): surface it for cleanup.
			out = append(out, deploymentStatus{ID: id, State: stUnknown})
			continue
		}
		out = append(out, deploymentStatus{
			ID:           id,
			Current:      st.Current,
			HostPath:     st.HostPath,
			UpdatedAt:    st.UpdatedAt,
			State:        s.probeState(id, st.HostPath),
			InternalPort: st.InternalPort,
			PathPrefix:   st.PathPrefix,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deployments": out})
}
