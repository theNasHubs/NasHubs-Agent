package main

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a tiny fixed-window limiter keyed by a string (e.g. client IP).
// Used to throttle sensitive endpoints like /pair against brute force.
type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}, max: max, window: window}
}

// maxLimiterKeys bounds the distinct keys tracked. Signing keys are
// attacker-chosen strings, so without a cap a flood of fake keyIds would grow
// the map unbounded. When full, new keys share one overflow bucket — flooding
// then self-throttles without affecting known keys.
const maxLimiterKeys = 4096

// allow reports whether another hit is permitted for key within the window,
// and records it when so.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := now.Add(-rl.window)
	if _, ok := rl.hits[key]; !ok && len(rl.hits) >= maxLimiterKeys {
		for k, ts := range rl.hits { // prune fully-expired buckets first
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(rl.hits, k)
			}
		}
		if len(rl.hits) >= maxLimiterKeys {
			key = "\x00overflow"
		}
	}
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.max {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// clientIP extracts the client IP from an HTTP request (best-effort).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
