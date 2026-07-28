package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
)

// handleLogs streams container logs as Server-Sent Events.
//
//	GET /logs/{id}?follow=1   → docker compose logs -f --tail 200
//	GET /logs/{id}            → docker compose logs --tail 200 (one-shot)
func (s *server) handleLogs(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/logs/")
	if !idSafe.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, errMap("bad id", nil))
		return
	}
	follow := r.URL.Query().Has("follow")

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errMap("streaming unsupported", nil))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering

	var cmd *exec.Cmd

	st, err := loadState(s.cfg.DataDir, id)
	if err == nil {
		// Primary path: use docker compose logs with the deploy's compose file
		argv := append([]string{}, s.composeArgs...)
		argv = append(argv, "-f", st.HostPath, "--project-directory", filepath.Dir(st.HostPath),
			"logs", "--no-color", "--tail", "200")
		if follow {
			argv = append(argv, "-f")
		}
		cmd = exec.Command(argv[0], argv[1:]...)
	} else {
		// Fallback: no state.json — try `docker logs nasdeck-{id}` directly.
		// This handles containers deployed via SSH bootstrap or Container Manager.
		containerName := "nasdeck-" + id
		argv := []string{"docker", "logs", "--tail", "200"}
		if follow {
			argv = append(argv, "-f")
		}
		argv = append(argv, containerName)
		cmd = exec.Command(argv[0], argv[1:]...)
	}

	sw := &sseWriter{w: w, f: flusher}
	cmd.Stdout = sw
	cmd.Stderr = sw

	if err := cmd.Start(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("start docker", err))
		return
	}
	// Kill the process when the client disconnects.
	ctx := r.Context()
	go func() {
		<-ctx.Done()
		_ = cmd.Process.Kill()
	}()
	_ = cmd.Wait()
}

// sseWriter is an io.Writer that emits one SSE "data:" event per line,
// flushing immediately. stdout and stderr share one instance so they merge.
type sseWriter struct {
	w   http.ResponseWriter
	f   http.Flusher
	buf []byte
}

func (s *sseWriter) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	for {
		i := bytes.IndexByte(s.buf, '\n')
		if i < 0 {
			break
		}
		line := string(s.buf[:i])
		s.buf = s.buf[i+1:]
		fmt.Fprintf(s.w, "data: %s\n\n", line)
		s.f.Flush()
	}
	return len(p), nil
}
