package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A burst of signed requests from one IP is throttled with 429, before the
// body is read, while a normal rate is allowed.
func TestRequestRateLimit(t *testing.T) {
	s := &server{cfg: Config{}, nonces: newNonceCache(), reqLimiter: newRateLimiter(5, time.Hour)}
	h := s.requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	got429 := 0
	for i := 0; i < 8; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/state", nil)
		req.RemoteAddr = "10.0.0.9:1234"
		h(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			got429++
		}
	}
	if got429 != 3 { // 5 allowed (then fail auth 401), 3 over the cap → 429
		t.Fatalf("want 3 rate-limited of 8, got %d", got429)
	}
	// A different IP is not affected by the first IP's burst.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/state", nil)
	req.RemoteAddr = "10.0.0.10:1"
	h(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("second IP should not be rate-limited by the first IP's burst")
	}
}
