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
	"sync"
	"time"
)

type server struct {
	cfg             Config
	nonces          *nonceCache
	certFingerprint string
	composeArgs     []string // ["docker","compose"] (v2) or ["docker-compose"] (v1, DSM 7.0 "Docker" pkg)

	devices     *deviceStore
	startedAt   time.Time    // for the pairing TTL window
	pairLimiter *rateLimiter // throttles /pair attempts per client IP
	reqLimiter  *rateLimiter // throttles ALL signed requests per client IP (DoS guard)

	pairMu          sync.Mutex // serialises the enroll decision
	logStreamSlots  chan struct{} // semaphore: concurrent /logs?follow streams
}

// acquireLogStream takes one /logs?follow slot (non-blocking). Returns false
// when maxLogFollowStreams streams are already running.
func (s *server) acquireLogStream() bool {
	if s.logStreamSlots == nil {
		return true // cap disabled (tests/embedded use)
	}
	select {
	case s.logStreamSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *server) releaseLogStream() {
	if s.logStreamSlots == nil {
		return
	}
	select {
	case <-s.logStreamSlots:
	default:
	}
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

	// Pairing: authenticated, but role is resolved inside the handler (a not-yet
	// enrolled but env-trusted key must be able to enroll itself).
	mux.HandleFunc("POST /pair", s.requireAuth(s.handlePair))

	// Read-only routes (viewer and above).
	mux.HandleFunc("GET /logs/", s.requireAuth(s.requireRole(RoleViewer, s.handleLogs)))
	mux.HandleFunc("GET /health/", s.requireAuth(s.requireRole(RoleViewer, s.handleHealth)))
	mux.HandleFunc("GET /proxies", s.requireAuth(s.requireRole(RoleViewer, s.handleListProxies)))
	mux.HandleFunc("GET /state", s.requireAuth(s.requireRole(RoleViewer, s.handleState)))
	mux.HandleFunc("GET /remote-status", s.requireAuth(s.requireRole(RoleViewer, s.handleRemoteStatus)))
	mux.HandleFunc("GET /configure-cloudflare", s.requireAuth(s.requireRole(RoleAdmin, s.handleGetCloudflare)))
	mux.HandleFunc("GET /devices", s.requireAuth(s.requireRole(RoleViewer, s.handleListDevices)))
	mux.HandleFunc("GET /volumes", s.requireAuth(s.requireRole(RoleViewer, s.handleListVolumes)))

	// Mutating routes (admin and above).
	mux.HandleFunc("POST /deploy", s.requireAuth(s.requireRole(RoleAdmin, s.handleDeploy)))
	mux.HandleFunc("POST /rollback/", s.requireAuth(s.requireRole(RoleAdmin, s.handleRollback)))
	mux.HandleFunc("POST /remove/", s.requireAuth(s.requireRole(RoleAdmin, s.handleRemove)))
	mux.HandleFunc("POST /proxy", s.requireAuth(s.requireRole(RoleAdmin, s.handleProxy)))
	mux.HandleFunc("POST /configure-proxy", s.requireAuth(s.requireRole(RoleAdmin, s.handleConfigureAllProxies)))
	mux.HandleFunc("POST /configure-cloudflare", s.requireAuth(s.requireRole(RoleAdmin, s.handleConfigureCloudflare)))
	// Typed self-update replaces the removed generic /exec.
	mux.HandleFunc("POST /agent/update", s.requireAuth(s.requireRole(RoleAdmin, s.handleAgentUpdate)))

	// Owner-only device management.
	mux.HandleFunc("POST /devices/revoke", s.requireAuth(s.requireRole(RoleOwner, s.handleRevokeDevice)))
	return s.recoverer(mux)
}

// requireRole gates a handler behind a minimum role. Must be wrapped by
// requireAuth (which puts the resolved authResult in the request context).
func (s *server) requireRole(min Role, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		role := authFrom(r).role
		if role == "" {
			writeJSON(w, http.StatusForbidden, errMap("device not paired", nil))
			return
		}
		ok := false
		switch min {
		case RoleViewer:
			ok = role == RoleViewer || role == RoleAdmin || role == RoleOwner
		case RoleAdmin:
			ok = role == RoleAdmin || role == RoleOwner
		case RoleOwner:
			ok = role == RoleOwner
		}
		if !ok {
			writeJSON(w, http.StatusForbidden, errMap("insufficient role", nil))
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (s *server) handlePing(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.cfg.Version})
}

// requireAuth reads the full request body (needed for the signature's body hash),
// verifies the Ed25519 signature + replay protection, then forwards to the
// handler with the body restored and the auth result in context.
func (s *server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Rate limit before doing any work (body read, hashing, verify) so an
		// unauthenticated flood is cheap to reject. Keyed by the signing keyId
		// when present: behind nginx every request arrives from 127.0.0.1, so a
		// per-IP bucket would let one flood throttle ALL users (shared fate).
		// Rotating fake keyIds lands in the bounded overflow bucket instead.
		key := r.Header.Get(hdrKeyID)
		if key == "" {
			key = r.Header.Get(legacyHdrKeyID)
		}
		if key == "" {
			key = clientIP(r)
		}
		if s.reqLimiter != nil && !s.reqLimiter.allow(key) {
			writeJSON(w, http.StatusTooManyRequests, errMap("rate limit exceeded", nil))
			return
		}
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
