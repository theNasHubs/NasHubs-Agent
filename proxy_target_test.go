package main

import (
	"net/http"
	"testing"
)

// Issue #35: non-owner /proxy + /deploy auto-proxy must not shadow DSM/agent
// paths or expose restricted loopback ports; the agent's own route prefixes
// are denied for every role.
func TestValidProxyTarget(t *testing.T) {
	cases := []struct {
		name   string
		prefix string
		port   int
		owner  bool
		wantOK bool
	}{
		// Reserved agent routes — denied for EVERY role.
		{"agent prefix owner", "/nashubs-agent", 8096, true, false},
		{"legacy agent prefix", "/nasdeck-agent", 8096, true, false},
		{"agent prefix nested", "/nashubs-agent/x", 8096, true, false},
		{"agent prefix non-owner", "/nashubs-agent", 8096, false, false},

		// DSM-surface segments — denied for non-owner, allowed for owner.
		{"webapi non-owner", "/webapi", 8096, false, false},
		{"login non-owner", "/login", 8096, false, false},
		{"query nested non-owner", "/query/foo", 8096, false, false},
		{"api non-owner", "/api", 8096, false, false},
		{"webapi owner", "/webapi", 8096, true, true},

		// Sensitive ports — denied for non-owner.
		{"dsm port 5000", "/app", 5000, false, false},
		{"dsm port 5001", "/app", 5001, false, false},
		{"agent port 8443", "/app", 8443, false, false},
		{"ssh port 22", "/app", 22, false, false},
		{"privileged port", "/app", 80, false, false},
		{"docker api port", "/app", 2375, false, false},
		{"iscsi port", "/app", 3260, false, false},

		// Owner keeps full latitude on ports.
		{"dsm port owner", "/app", 5000, true, true},
		{"privileged port owner", "/app", 443, true, true},

		// Normal app proxies stay allowed.
		{"app non-owner", "/jellyfin", 8096, false, true},
		{"nested app non-owner", "/apps/qbittorrent", 8080, false, true},
		{"high port non-owner", "/app", 65000, false, true},
		{"empty prefix", "", 8096, true, false},
	}
	for _, c := range cases {
		err := validProxyTarget(c.prefix, c.port, c.owner)
		if ok := err == nil; ok != c.wantOK {
			t.Errorf("%s: validProxyTarget(%q,%d,owner=%v) ok=%v want %v (err=%v)",
				c.name, c.prefix, c.port, c.owner, ok, c.wantOK, err)
		}
	}
}

// Issue #36: the /logs?follow semaphore caps concurrent streams.
func TestLogStreamSemaphore(t *testing.T) {
	s := &server{logStreamSlots: make(chan struct{}, 2)}
	if !s.acquireLogStream() || !s.acquireLogStream() {
		t.Fatal("first two acquires should succeed")
	}
	if s.acquireLogStream() {
		t.Fatal("third acquire should fail while cap is full")
	}
	s.releaseLogStream()
	if !s.acquireLogStream() {
		t.Fatal("acquire should succeed after release")
	}
}

// Issue #36: a container emitting one huge line without '\n' must not grow
// the SSE buffer unbounded.
func TestSSEWriterTruncatesLongLine(t *testing.T) {
	w := &sseWriter{w: &discardWriter{}, f: nopFlusher{}}
	big := make([]byte, maxSSELineLen+1024)
	for i := range big {
		big[i] = 'x'
	}
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	if len(w.buf) != 0 {
		t.Fatalf("buffer should be drained after truncation, got %d bytes", len(w.buf))
	}
}

type discardWriter struct{ last string }

func (d *discardWriter) Header() http.Header          { return http.Header{} }
func (d *discardWriter) Write(p []byte) (int, error) { d.last = string(p); return len(p), nil }
func (d *discardWriter) WriteHeader(int)             {}

type nopFlusher struct{}

func (nopFlusher) Flush() {}
