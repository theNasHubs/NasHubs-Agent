package main

import (
	"testing"
	"time"
)

func TestNonceReplayRejected(t *testing.T) {
	n := newNonceCache()
	now := time.Now()
	if !n.checkAndAdd("ts:a", now) {
		t.Fatal("first use should be accepted")
	}
	if n.checkAndAdd("ts:a", now) {
		t.Fatal("replay must be rejected")
	}
}

// Filling the cache with in-window nonces must NOT open a replay window: an
// in-window nonce already seen stays rejected, and the full cache fails closed.
func TestNonceNoReplayWindowWhenFull(t *testing.T) {
	defer func(m int) { maxNonces = m }(maxNonces)
	maxNonces = 100
	n := newNonceCache()
	now := time.Now()
	victim := "ts:victim"
	if !n.checkAndAdd(victim, now) {
		t.Fatal("victim first use accepted")
	}
	for i := 0; i < maxNonces+10; i++ {
		n.checkAndAdd(string(rune(i/256))+string(rune(i%256))+":fill", now)
	}
	// The victim (still within the window) must still be remembered → replay rejected.
	if n.checkAndAdd(victim, now) {
		t.Fatal("in-window nonce was evicted — replay window opened")
	}
}

// Nonces older than maxSkew are evicted when full (they can't be replayed
// anyway: the timestamp check rejects them), which makes room again.
func TestNonceEvictsOutOfWindow(t *testing.T) {
	defer func(m int) { maxNonces = m }(maxNonces)
	maxNonces = 100
	n := newNonceCache()
	old := time.Now().Add(-2 * maxSkew)
	for i := 0; i < maxNonces; i++ {
		n.checkAndAdd(string(rune(i/256))+string(rune(i%256))+":old", old)
	}
	// Now a fresh nonce: the old ones are >maxSkew so they get evicted, room is made.
	if !n.checkAndAdd("ts:fresh", time.Now()) {
		t.Fatal("fresh nonce rejected although out-of-window entries should be evicted")
	}
}
