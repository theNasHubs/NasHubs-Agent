package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// schemeHeaders signs a request and returns the four signature headers under the given prefix
// ("NasHubs" for the current apps, "Nasdeck" for the pre-rebrand iOS app in production).
func schemeHeaders(priv ed25519.PrivateKey, prefix, method, path string, body []byte, ts string) map[string]string {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	nonce := base64.StdEncoding.EncodeToString(n)
	sum := sha256.Sum256(body)
	base := []byte(method + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
	p := "X-" + prefix + "-"
	return map[string]string{
		p + "Keyid": base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		p + "Ts":    ts, p + "Nonce": nonce,
		p + "Sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, base)),
	}
}

func send(t *testing.T, method, url string, body []byte, headers map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var e struct{ Detail string }
	_ = json.Unmarshal(b, &e)
	return resp.StatusCode, e.Detail
}

func now() string { return strconv.FormatInt(time.Now().Unix(), 10) }

func TestBothSchemesPairAndSign(t *testing.T) {
	for _, prefix := range []string{"NasHubs", "Nasdeck"} {
		t.Run(prefix, func(t *testing.T) {
			ts, priv, _ := newTestServer(t)
			defer ts.Close()
			pair, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
			if code, d := send(t, "POST", ts.URL+"/pair", pair, schemeHeaders(priv, prefix, "POST", "/pair", pair, now())); code != 200 {
				t.Fatalf("pair = %d %s", code, d)
			}
			if code, d := send(t, "GET", ts.URL+"/state", nil, schemeHeaders(priv, prefix, "GET", "/state", nil, now())); code != 200 {
				t.Fatalf("signed /state = %d %s", code, d)
			}
		})
	}
}

func TestMixedSchemesAreRejected(t *testing.T) {
	ts, priv, _ := newTestServer(t)
	defer ts.Close()
	current := schemeHeaders(priv, "NasHubs", "GET", "/state", nil, now())
	legacy := schemeHeaders(priv, "Nasdeck", "GET", "/state", nil, now())
	cases := map[string]map[string]string{
		// Full valid sets of both: ambiguous, never pick one.
		"both complete": merge(current, legacy),
		// Signature fields split across schemes.
		"split fields": {"X-NasHubs-Keyid": current["X-NasHubs-Keyid"], "X-NasHubs-Ts": current["X-NasHubs-Ts"],
			"X-Nasdeck-Nonce": current["X-NasHubs-Nonce"], "X-Nasdeck-Sig": current["X-NasHubs-Sig"]},
		"incomplete legacy": {"X-Nasdeck-Keyid": legacy["X-Nasdeck-Keyid"], "X-Nasdeck-Ts": legacy["X-Nasdeck-Ts"]},
	}
	for name, h := range cases {
		if code, d := send(t, "GET", ts.URL+"/state", nil, h); code != http.StatusUnauthorized {
			t.Errorf("%s: status %d (%s), want 401", name, code, d)
		}
	}
}

func TestReplayAndTamperRejectedInBothSchemes(t *testing.T) {
	for _, prefix := range []string{"NasHubs", "Nasdeck"} {
		t.Run(prefix, func(t *testing.T) {
			ts, priv, _ := newTestServer(t)
			defer ts.Close()
			pair, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
			send(t, "POST", ts.URL+"/pair", pair, schemeHeaders(priv, prefix, "POST", "/pair", pair, now()))
			h := schemeHeaders(priv, prefix, "GET", "/state", nil, now())
			if code, _ := send(t, "GET", ts.URL+"/state", nil, h); code != 200 {
				t.Fatalf("first request = %d", code)
			}
			if code, d := send(t, "GET", ts.URL+"/state", nil, h); code != http.StatusUnauthorized || d != "replay detected" {
				t.Fatalf("replay = %d %s", code, d)
			}
			signed := schemeHeaders(priv, prefix, "POST", "/deploy", []byte(`{"id":"a"}`), now())
			if code, d := send(t, "POST", ts.URL+"/deploy", []byte(`{"id":"b"}`), signed); code != http.StatusUnauthorized || d != "invalid signature" {
				t.Fatalf("tampered = %d %s", code, d)
			}
			old := strconv.FormatInt(time.Now().Unix()-3600, 10)
			if code, d := send(t, "GET", ts.URL+"/state", nil, schemeHeaders(priv, prefix, "GET", "/state", nil, old)); code != http.StatusUnauthorized || d != "timestamp out of range" {
				t.Fatalf("stale = %d %s", code, d)
			}
		})
	}
}

func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
