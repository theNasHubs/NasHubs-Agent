package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

type server struct {
	cfg             Config
	nonces          *nonceCache
	certFingerprint string
	composeArgs     []string // ["docker","compose"] (v2) or ["docker-compose"] (v1, DSM 7.0 "Docker" pkg)
}

// detectCompose picks the compose invocation available on the host. DSM 7.0's
// legacy "Docker" package ships only docker-compose v1 (no `docker compose`);
// DSM 7.2+ Container Manager ships the v2 plugin.
func detectCompose() []string {
	if out, err := exec.Command("docker", "compose", "version").CombinedOutput(); err == nil {
		s := string(out)
		if !strings.Contains(s, "not a docker command") && strings.Contains(strings.ToLower(s), "version") {
			return []string{"docker", "compose"}
		}
	}
	return []string{"docker-compose"}
}

type contextKey string

const authKey contextKey = "auth"

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", s.handlePing)

	// Signature-authenticated routes.
	mux.HandleFunc("POST /pair", s.requireAuth(s.handlePair))
	mux.HandleFunc("POST /deploy", s.requireAuth(s.handleDeploy))
	mux.HandleFunc("GET /logs/", s.requireAuth(s.handleLogs))
	mux.HandleFunc("GET /health/", s.requireAuth(s.handleHealth))
	mux.HandleFunc("POST /rollback/", s.requireAuth(s.handleRollback))
	mux.HandleFunc("POST /remove/", s.requireAuth(s.handleRemove))
	mux.HandleFunc("POST /exec/", s.requireAuth(s.handleExec))
	mux.HandleFunc("POST /proxy", s.requireAuth(s.handleProxy))
	mux.HandleFunc("GET /proxies", s.requireAuth(s.handleListProxies))
	mux.HandleFunc("GET /state", s.requireAuth(s.handleState))
	mux.HandleFunc("GET /remote-status", s.requireAuth(s.handleRemoteStatus))
	mux.HandleFunc("POST /configure-proxy", s.requireAuth(s.handleConfigureAllProxies))
	mux.HandleFunc("GET /configure-cloudflare", s.requireAuth(s.handleGetCloudflare))
	mux.HandleFunc("POST /configure-cloudflare", s.requireAuth(s.handleConfigureCloudflare))
	return s.recoverer(mux)
}

func (s *server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.cfg.Version})
}

// requireAuth reads the full request body (needed for the signature's body hash),
// verifies the Ed25519 signature + replay protection, then forwards to the
// handler with the body restored and the auth result in context.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<20)) // 4 MiB cap
		_ = r.Body.Close()
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errMap("read body", err))
			return
		}
		auth, err := s.verifyRequest(r, body)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, errMap("auth failed", err))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), authKey, auth)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func authFrom(r *http.Request) authResult {
	if v, ok := r.Context().Value(authKey).(authResult); ok {
		return v
	}
	return authResult{}
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func errMap(msg string, err error) map[string]any {
	m := map[string]any{"error": msg}
	if err != nil {
		m["detail"] = fmt.Sprint(err)
	}
	return m
}

// recoverer prevents a panicking handler from killing the process.
func (s *server) recoverer(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				writeJSON(w, http.StatusInternalServerError, errMap("internal error", fmt.Errorf("%v", rec)))
			}
		}()
		h.ServeHTTP(w, r)
	})
}
