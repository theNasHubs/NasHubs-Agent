package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Integration test: boots the real server in-process and exercises the full
// Ed25519 request-signing pipeline the iOS AgentTransport must speak.

func newTestServer(t *testing.T) (*httptest.Server, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		DataDir:          t.TempDir(),
		HostDataDir:      t.TempDir(),
		TrustedPublicKeys: map[string]bool{base64.StdEncoding.EncodeToString(pub): true},
		PairingSecret:    "test-secret",
		Version:          "test",
	}
	cert, fp, err := ensureCert(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg:             cfg,
		nonces:          newNonceCache(),
		certFingerprint: fp,
		devices:         newDeviceStore(cfg.DataDir),
		startedAt:       time.Now(),
		pairLimiter:     newRateLimiter(100, time.Minute), // high cap so tests aren't throttled
	}
	ts := httptest.NewUnstartedServer(s.routes())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	return ts, priv, fp
}

// signedRequest mirrors exactly what iOS AgentTransport will do.
func signedRequest(t *testing.T, client *http.Client, priv ed25519.PrivateKey,
	method, url string, body []byte) *http.Response {
	t.Helper()
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.StdEncoding.EncodeToString([]byte("nonce" + url))
	sum := sha256.Sum256(body)
	sigBase := []byte(method + "\n" + pathOf(url) + "\n" + ts + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(priv, sigBase)
	pub := priv.Public().(ed25519.PublicKey)

	req, _ := http.NewRequest(method, url, bytes.NewReader(body))
	req.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(pub))
	req.Header.Set(hdrTs, ts)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(sig))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func pathOf(u string) string {
	idx := strings.Index(u, "://")
	if idx < 0 {
		return u
	}
	pathStart := strings.IndexByte(u[idx+3:], '/')
	if pathStart < 0 {
		return "/"
	}
	return u[idx+3+pathStart:]
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test only
	}}
}

func TestPingUnsigned(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()
	resp, err := client().Get(ts.URL + "/ping")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("ping status = %d, want 200", resp.StatusCode)
	}
}

func TestUnsignedProtectedIsRejected(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()
	resp, _ := client().Post(ts.URL+"/deploy", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned deploy status = %d, want 401", resp.StatusCode)
	}
}

func TestPairHappyPath(t *testing.T) {
	ts, priv, fp := newTestServer(t)
	defer ts.Close()
	body, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
	resp := signedRequest(t, client(), priv, "POST", ts.URL+"/pair", body)
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("pair status = %d body=%s, want 200", resp.StatusCode, b)
	}
	var pr pairResponse
	_ = json.NewDecoder(resp.Body).Decode(&pr)
	if !pr.OK || pr.CertFingerprint != fp || pr.Version != "test" {
		t.Fatalf("unexpected pair response: %+v", pr)
	}
}

func TestPairWrongSecretRejected(t *testing.T) {
	ts, priv, _ := newTestServer(t)
	defer ts.Close()
	body, _ := json.Marshal(pairRequest{PairingSecret: "WRONG"})
	resp := signedRequest(t, client(), priv, "POST", ts.URL+"/pair", body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-secret pair status = %d, want 403", resp.StatusCode)
	}
}

func TestUntrustedKeyRejected(t *testing.T) {
	ts, _, _ := newTestServer(t)
	defer ts.Close()
	// A key NOT in the trust set.
	_, rogue, _ := ed25519.GenerateKey(nil)
	body, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
	resp := signedRequest(t, client(), rogue, "POST", ts.URL+"/pair", body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted key status = %d, want 401", resp.StatusCode)
	}
}

// TestBadSignatureDoesNotBurnNonce verifies the replay cache is only written
// AFTER a valid signature. A forged request (correct ts/nonce, invalid sig)
// must not consume the (ts,nonce) pair and block the legitimate signed request
// that reuses it within the skew window.
func TestBadSignatureDoesNotBurnNonce(t *testing.T) {
	ts, priv, _ := newTestServer(t)
	defer ts.Close()
	c := client()
	url := ts.URL + "/pair"
	body, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})

	fixedTs := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.StdEncoding.EncodeToString([]byte("burn-nonce"))
	pub := priv.Public().(ed25519.PublicKey)

	// 1) Forged request: valid headers/ts/nonce but an all-zero (invalid) sig.
	bad, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	bad.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(pub))
	bad.Header.Set(hdrTs, fixedTs)
	bad.Header.Set(hdrNonce, nonce)
	bad.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	badResp, err := c.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	_ = badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged request status = %d, want 401", badResp.StatusCode)
	}

	// 2) Legitimate signed request reusing the SAME (ts,nonce) must still succeed.
	sum := sha256.Sum256(body)
	sigBase := []byte("POST\n/pair\n" + fixedTs + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
	sig := ed25519.Sign(priv, sigBase)
	good, _ := http.NewRequest("POST", url, bytes.NewReader(body))
	good.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(pub))
	good.Header.Set(hdrTs, fixedTs)
	good.Header.Set(hdrNonce, nonce)
	good.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(sig))
	goodResp, err := c.Do(good)
	if err != nil {
		t.Fatal(err)
	}
	defer goodResp.Body.Close()
	if goodResp.StatusCode != 200 {
		b, _ := io.ReadAll(goodResp.Body)
		t.Fatalf("legit request after forged attempt = %d body=%s, want 200", goodResp.StatusCode, b)
	}
}

func TestReplayRejected(t *testing.T) {
	ts, priv, _ := newTestServer(t)
	defer ts.Close()
	url := ts.URL + "/pair"
	body, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
	first := signedRequest(t, client(), priv, "POST", url, body)
	_ = first.Body.Close()
	// Same (ts,nonce) → nonce cache should reject.
	second := signedRequest(t, client(), priv, "POST", url, body)
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", second.StatusCode)
	}
}
