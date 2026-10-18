package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// twoKeyServer trusts two bootstrap keys (two devices of the owner), like a production deploy.
func twoKeyServer(t *testing.T, startedAt time.Time) (*httptest.Server, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	pub2, priv2, _ := ed25519.GenerateKey(nil)
	cfg := Config{DataDir: t.TempDir(), HostDataDir: t.TempDir(), PairingSecret: "test-secret", Version: "test",
		TrustedPublicKeys: map[string]bool{base64.StdEncoding.EncodeToString(pub1): true, base64.StdEncoding.EncodeToString(pub2): true}}
	cert, fp, err := ensureCert(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{cfg: cfg, nonces: newNonceCache(), certFingerprint: fp, devices: newDeviceStore(cfg.DataDir),
		startedAt: startedAt, pairLimiter: newRateLimiter(100, time.Minute)}
	ts := httptest.NewUnstartedServer(s.routes())
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	return ts, priv1, priv2
}

func pairAs(t *testing.T, ts *httptest.Server, priv ed25519.PrivateKey, secret string) (int, string, pairResponse) {
	body, _ := json.Marshal(pairRequest{PairingSecret: secret})
	resp := freshSigned(t, priv, "POST", ts.URL, "/pair", body)
	defer resp.Body.Close()
	var raw map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&raw)
	b, _ := json.Marshal(raw)
	var pr pairResponse
	_ = json.Unmarshal(b, &pr)
	detail, _ := raw["detail"].(string)
	if detail == "" {
		detail, _ = raw["error"].(string)
	}
	return resp.StatusCode, detail, pr
}

func TestUnpairedBootstrapKeyCanOnlyPair(t *testing.T) {
	ts, owner, _ := twoKeyServer(t, time.Now())
	defer ts.Close()
	for _, path := range []string{"/state", "/devices", "/volumes"} {
		resp := freshSigned(t, owner, "GET", ts.URL, path, nil)
		var e struct{ Error string }
		_ = json.NewDecoder(resp.Body).Decode(&e)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || e.Error != "device not paired" {
			t.Fatalf("unpaired %s = %d %q, want 403 device not paired", path, resp.StatusCode, e.Error)
		}
	}
	if code, d, pr := pairAs(t, ts, owner, "test-secret"); code != 200 || pr.Role != string(RoleOwner) {
		t.Fatalf("pair = %d %s %+v", code, d, pr)
	}
	resp := freshSigned(t, owner, "GET", ts.URL, "/state", nil)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("paired /state = %d", resp.StatusCode)
	}
}

func TestSecondBootstrapKeyPairsAsAdmin(t *testing.T) {
	ts, owner, second := twoKeyServer(t, time.Now())
	defer ts.Close()
	pairAs(t, ts, owner, "test-secret")
	if code, d, pr := pairAs(t, ts, second, "test-secret"); code != 200 || pr.Role != string(RoleAdmin) {
		t.Fatalf("second device pair = %d %s %+v, want 200 admin", code, d, pr)
	}
}

func TestPairingSecretStillRequired(t *testing.T) {
	ts, owner, _ := twoKeyServer(t, time.Now())
	defer ts.Close()
	if code, d, _ := pairAs(t, ts, owner, "wrong"); code != http.StatusForbidden || d != "pairing secret mismatch" {
		t.Fatalf("wrong secret = %d %s", code, d)
	}
}

func TestPairingWindowExpires(t *testing.T) {
	ts, owner, _ := twoKeyServer(t, time.Now().Add(-pairingTTL-time.Minute))
	defer ts.Close()
	if code, d, _ := pairAs(t, ts, owner, "test-secret"); code != http.StatusForbidden || d != "pairing window expired" {
		t.Fatalf("expired window = %d %s", code, d)
	}
}

func TestKeyNotTrustedAtBootstrapCannotPair(t *testing.T) {
	ts, _, _ := twoKeyServer(t, time.Now())
	defer ts.Close()
	_, stranger, _ := ed25519.GenerateKey(nil)
	if code, d, _ := pairAs(t, ts, stranger, "test-secret"); code != http.StatusUnauthorized || d != "untrusted key" {
		t.Fatalf("stranger pair = %d %s, want 401 untrusted key", code, d)
	}
}

// freshSigned signs with a random nonce (signedRequest's nonce is fixed per URL, so two requests
// to the same URL within a second would be rejected as a replay).
func freshSigned(t *testing.T, priv ed25519.PrivateKey, method, base, path string, body []byte) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, bytesReader(body))
	if body == nil {
		body = []byte{}
	}
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	nonce := base64.StdEncoding.EncodeToString(n)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(priv, []byte(method+"\n"+path+"\n"+ts+"\n"+nonce+"\n"+hex.EncodeToString(sum[:])))
	req.Header.Set(hdrKeyID, base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)))
	req.Header.Set(hdrTs, ts)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(sig))
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
