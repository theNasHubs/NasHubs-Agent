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

// TestAudienceBinding covers #34: a request carrying X-NasHubs-Aud binds to this
// agent's fingerprint — a wrong aud is rejected even with a valid signature,
// and the aud is inside the signed base so it can't be stripped. Requests
// without the header keep working (transition for pre-audience clients).
func TestAudienceBinding(t *testing.T) {
	ts, priv, fp := newTestServer(t)
	defer ts.Close()
	c := client()

	sign := func(url, aud string, body []byte) *http.Response {
		t0 := strconv.FormatInt(time.Now().Unix(), 10)
		nonce := base64.StdEncoding.EncodeToString([]byte("aud-" + aud + url))
		sum := sha256.Sum256(body)
		base := "GET\n/state\n" + t0 + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
		if aud != "" {
			base += "\n" + aud
		}
		req, _ := http.NewRequest("GET", url, bytes.NewReader(body))
		req.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		req.Header.Set(hdrTs, t0)
		req.Header.Set(hdrNonce, nonce)
		req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base))))
		if aud != "" {
			req.Header.Set(hdrAud, aud)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	// Enrol so the device has a role.
	body, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
	resp := signedRequest(t, c, priv, "POST", ts.URL+"/pair", body)
	if resp.StatusCode != 200 {
		t.Fatalf("pair = %d", resp.StatusCode)
	}
	resp.Body.Close()

	if r := sign(ts.URL+"/state", fp, nil); r.StatusCode != 200 {
		t.Fatalf("correct aud = %d, want 200", r.StatusCode)
	}
	if r := sign(ts.URL+"/state", "deadbeef", nil); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong aud = %d, want 401", r.StatusCode)
	}
	// Signature without aud in base, but header present → invalid signature.
	t0 := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.StdEncoding.EncodeToString([]byte("aud-strip"))
	sum := sha256.Sum256(nil)
	base := "GET\n/state\n" + t0 + "\n" + nonce + "\n" + hex.EncodeToString(sum[:])
	req, _ := http.NewRequest("GET", ts.URL+"/state", nil)
	req.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	req.Header.Set(hdrTs, t0)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(base))))
	req.Header.Set(hdrAud, fp)
	r, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stripped-aud sig = %d, want 401", r.StatusCode)
	}
	// Legacy request without aud still verifies.
	if r := sign(ts.URL+"/state", "", nil); r.StatusCode != 200 {
		t.Fatalf("no aud = %d, want 200", r.StatusCode)
	}
}

func TestReplayRejected(t *testing.T) {
	ts, priv, _ := newTestServer(t)
	defer ts.Close()
	url := ts.URL + "/pair"
	body, _ := json.Marshal(pairRequest{PairingSecret: "test-secret"})
	// Send the exact same signed request twice. (Calling signedRequest twice re-reads the clock,
	// so the two requests could land in different seconds and not be a replay at all.)
	ts0 := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := base64.StdEncoding.EncodeToString([]byte("replay-nonce"))
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(priv, []byte("POST\n/pair\n"+ts0+"\n"+nonce+"\n"+hex.EncodeToString(sum[:])))
	send := func() *http.Response {
		req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
		req.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
		req.Header.Set(hdrTs, ts0)
		req.Header.Set(hdrNonce, nonce)
		req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(sig))
		resp, err := client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	first := send()
	_ = first.Body.Close()
	// Same (ts,nonce) → nonce cache should reject.
	second := send()
	if second.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401", second.StatusCode)
	}
}
