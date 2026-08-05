package main

import (
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
)

// execRequest is the JSON body for POST /exec/{container}.
type execRequest struct {
	Cmd []string `json:"cmd"` // e.g. ["tunnel", "login"]
}

// handleExec runs a command inside a running container and streams
// stdout/stderr back as Server-Sent Events.
//
//	POST /exec/{container}
//	Body: {"cmd": ["tunnel", "login"]}
//	Response: text/event-stream with data: lines
//
// This enables multi-step setup flows (e.g. cloudflared tunnel login →
// create → run) without needing to rebuild or restart containers.
func (s *server) handleExec(w http.ResponseWriter, r *http.Request) {
	container := strings.TrimPrefix(r.URL.Path, "/exec/")
	if !idSafe.MatchString(container) {
		writeJSON(w, http.StatusBadRequest, errMap("bad container name", nil))
		return
	}

	var req execRequest
	if err := decodeBody(r, &req); err != nil || len(req.Cmd) == 0 {
		writeJSON(w, http.StatusBadRequest, errMap("cmd required", err))
		return
	}

	// Validate: only allow safe commands (no shell injection).
	for _, arg := range req.Cmd {
		if strings.ContainsAny(arg, ";|&`$") {
			writeJSON(w, http.StatusBadRequest, errMap("unsafe characters in cmd", nil))
			return
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errMap("streaming unsupported", nil))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// docker exec -i {container} {cmd...}
	argv := []string{"docker", "exec", "-i", container}
	argv = append(argv, req.Cmd...)
	cmd := exec.Command(argv[0], argv[1:]...)

	sw := &sseWriter{w: w, f: flusher}
	cmd.Stdout = sw
	cmd.Stderr = sw

	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("exec start", err))
		return
	}

	// Kill the exec process when the client disconnects.
	ctx := r.Context()
	go func() {
		<-ctx.Done()
		_ = cmd.Process.Kill()
	}()

	exitErr := cmd.Wait()

	// Send exit code as final SSE event.
	exitCode := 0
	if exitErr != nil {
		if ee, ok := exitErr.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	exitData, _ := json.Marshal(map[string]any{"exit_code": exitCode})
	sw.Write([]byte("__EXIT__:" + string(exitData) + "\n"))
}
