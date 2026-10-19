package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func enrollmentServer(t *testing.T, dir string) (*server, *httptest.Server) {
	t.Helper()
	s := &server{cfg: Config{DataDir: dir, TrustedPublicKeys: map[string]bool{}, Version: "test"}, devices: newDeviceStore(dir), nonces: newNonceCache(), pairLimiter: newRateLimiter(1000, time.Minute), certFingerprint: "stable-cert", startedAt: time.Now()}
	ts := httptest.NewServer(s.routes())
	t.Cleanup(ts.Close)
	return s, ts
}
func freshKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, e := ed25519.GenerateKey(nil)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func keyID(k ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(k.Public().(ed25519.PublicKey))
}
func enrollRequest(t *testing.T, ts *httptest.Server, k ed25519.PrivateKey, path string, body any) *http.Response {
	t.Helper()
	b, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	method := "POST"
	if body == nil {
		method = "GET"
		b = nil
	}
	req, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(b))
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	n := make([]byte, 16)
	rand.Read(n)
	nonce := base64.StdEncoding.EncodeToString(n)
	req.Header.Set(hdrKeyID, keyID(k))
	req.Header.Set(hdrTs, stamp)
	req.Header.Set(hdrNonce, nonce)
	req.Header.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(k, signatureBase(method, path, stamp, nonce, b))))
	r, e := ts.Client().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Body.Close() })
	return r
}
func invitationCode(t *testing.T, s *server, role Role, issuer string) string {
	t.Helper()
	c, _, e := s.invitations.create(role, issuer)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func assertStatus(t *testing.T, r *http.Response, want int) {
	t.Helper()
	if r.StatusCode != want {
		b, _ := io.ReadAll(r.Body)
		t.Fatalf("status=%d want=%d body=%s", r.StatusCode, want, b)
	}
}

func TestLiveEnrollmentPersistsAndReconnectsAfterRestart(t *testing.T) {
	dir := t.TempDir()
	s, ts := enrollmentServer(t, dir)
	owner := freshKey(t)
	s.devices.enroll(keyID(owner), "existing iPhone", RoleOwner)
	code := invitationCode(t, s, RoleAdmin, keyID(owner))
	newKey := freshKey(t)
	assertStatus(t, enrollRequest(t, ts, newKey, "/state", nil), 401)
	r := enrollRequest(t, ts, newKey, "/devices/enroll", map[string]string{"code": code, "label": "Android"})
	assertStatus(t, r, 200)
	var pair pairResponse
	json.NewDecoder(r.Body).Decode(&pair)
	if pair.Role != "admin" || pair.KeyID != keyID(newKey) || pair.CertFingerprint != "stable-cert" {
		t.Fatal(pair)
	}
	assertStatus(t, enrollRequest(t, ts, newKey, "/devices", nil), 200)
	assertStatus(t, enrollRequest(t, ts, owner, "/pair", pairRequest{}), 200)
	s2, ts2 := enrollmentServer(t, dir)
	assertStatus(t, enrollRequest(t, ts2, newKey, "/pair", pairRequest{}), 200)
	assertStatus(t, enrollRequest(t, ts2, freshKey(t), "/devices/enroll", map[string]string{"code": code}), 403)
	if len(s2.devices.list()) != 2 {
		t.Fatal("lost existing devices")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "invitations.json"))
	if bytes.Contains(b, []byte(code)) {
		t.Fatal("plaintext invitation persisted")
	}
}
func TestInvitationAccessAndRoles(t *testing.T) {
	for _, role := range []Role{RoleViewer, RoleAdmin, RoleOwner} {
		t.Run(string(role), func(t *testing.T) {
			s, ts := enrollmentServer(t, t.TempDir())
			k := freshKey(t)
			s.devices.enroll(keyID(k), "device", role)
			want := 403
			if role == RoleOwner {
				want = 200
			}
			assertStatus(t, enrollRequest(t, ts, k, "/devices/invitations", map[string]string{"role": "viewer"}), want)
			if role == RoleOwner {
				assertStatus(t, enrollRequest(t, ts, k, "/devices/invitations", map[string]string{"role": "owner"}), 400)
			}
		})
	}
	s, ts := enrollmentServer(t, t.TempDir())
	k := freshKey(t)
	c := invitationCode(t, s, RoleViewer, "")
	assertStatus(t, enrollRequest(t, ts, k, "/devices/enroll", map[string]string{"code": c}), 200)
	assertStatus(t, enrollRequest(t, ts, k, "/devices", nil), 200)
	assertStatus(t, enrollRequest(t, ts, k, "/deploy", map[string]string{}), 403)
}
func TestInvalidExpiredAndRevokedInvitations(t *testing.T) {
	for _, mode := range []string{"wrong", "expired", "revoked-device", "revoked-issuer"} {
		t.Run(mode, func(t *testing.T) {
			s, ts := enrollmentServer(t, t.TempDir())
			owner := freshKey(t)
			d, _ := s.devices.enroll(keyID(owner), "owner", RoleOwner)
			c := invitationCode(t, s, RoleAdmin, keyID(owner))
			k := freshKey(t)
			switch mode {
			case "wrong":
				c = "bad"
			case "expired":
				v := s.invitations.entries[invitationHash(c)]
				v.ExpiresAt = time.Now().Add(-time.Second)
				s.invitations.entries[v.Hash] = v
			case "revoked-device":
				v, _ := s.devices.enroll(keyID(k), "revoked", RoleAdmin)
				s.devices.revoke(v.DeviceID)
			case "revoked-issuer":
				s.devices.revoke(d.DeviceID)
			}
			want := 403
			if mode == "revoked-device" {
				want = 401
			}
			assertStatus(t, enrollRequest(t, ts, k, "/devices/enroll", map[string]string{"code": c}), want)
		})
	}
}
func TestInvitationConcurrentSingleUse(t *testing.T) {
	s, ts := enrollmentServer(t, t.TempDir())
	code := invitationCode(t, s, RoleAdmin, "")
	var wg sync.WaitGroup
	results := make(chan int, 8)
	for i := 0; i < 8; i++ {
		k := freshKey(t)
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := enrollRequest(t, ts, k, "/devices/enroll", map[string]string{"code": code})
			results <- r.StatusCode
		}()
	}
	wg.Wait()
	close(results)
	ok := 0
	for status := range results {
		if status == 200 {
			ok++
		} else if status != 403 {
			t.Fatal(status)
		}
	}
	if ok != 1 || len(s.devices.list()) != 1 {
		t.Fatalf("successful enrollments=%d", ok)
	}
}
func TestUnsignedEnrollmentRejectedWithoutBurningCode(t *testing.T) {
	s, ts := enrollmentServer(t, t.TempDir())
	c := invitationCode(t, s, RoleAdmin, "")
	r, e := http.Post(ts.URL+"/devices/enroll", "application/json", strings.NewReader(`{"code":"`+c+`"}`))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	assertStatus(t, r, 401)
	assertStatus(t, enrollRequest(t, ts, freshKey(t), "/devices/enroll", map[string]string{"code": c}), 200)
}
func TestRevokedDeviceCannotReenroll(t *testing.T) {
	s, _ := enrollmentServer(t, t.TempDir())
	d, _ := s.devices.enroll("key", "device", RoleAdmin)
	s.devices.revoke(d.DeviceID)
	if _, err := s.devices.enroll("key", "device", RoleOwner); err == nil {
		t.Fatal("revoked key silently restored")
	}
}
func TestLocalControlSocketPermissionsAndInvitation(t *testing.T) {
	s, _ := enrollmentServer(t, t.TempDir())
	closeControl, err := s.startControl()
	if err != nil {
		t.Fatal(err)
	}
	defer closeControl()
	info, err := os.Stat(filepath.Join(s.cfg.DataDir, "control.sock"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	if _, err := s.startControl(); err == nil {
		t.Fatal("second agent allowed to steal live socket")
	}
}
func TestInvitationCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "invitations.json"), []byte("invalid"), 0600)
	st := newInvitationStore(dir)
	if _, _, err := st.create(RoleAdmin, ""); err == nil {
		t.Fatal("corrupt store accepted")
	}
}
func TestReplayCacheCapacityFailsClosed(t *testing.T) {
	c := newNonceCache()
	now := time.Now()
	for i := 0; i < maxNonces; i++ {
		c.seen[strconv.Itoa(i)] = now
	}
	if c.checkAndAdd("new", now) || c.checkAndAdd("1", now) {
		t.Fatal("replay protection discarded at capacity")
	}
}

func TestCorruptDeviceStoreCannotFallBackToBootstrapTrust(t *testing.T) {
	for _, contents := range []string{"corrupted", "null", "[null]"} {
		t.Run(contents, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "devices.json"), []byte(contents), 0600)
			s, ts := enrollmentServer(t, dir)
			k := freshKey(t)
			s.cfg.TrustedPublicKeys[keyID(k)] = true
			assertStatus(t, enrollRequest(t, ts, k, "/devices", nil), 401)
			if _, err := s.devices.enroll(keyID(k), "owner", RoleOwner); err == nil {
				t.Fatal("corrupt store overwritten")
			}
		})
	}
}

func TestDeviceEnrollmentDiskFailureDoesNotGrantInMemoryAccess(t *testing.T) {
	ds := newDeviceStore(t.TempDir())
	ds.path = t.TempDir() // cannot rename over directory
	if _, err := ds.enroll("new-key", "device", RoleAdmin); err == nil {
		t.Fatal("expected persist error")
	}
	if ds.lookup("new-key") != nil {
		t.Fatal("failed enrollment authorized device")
	}
}

func TestResourcesUsesHostWithoutDSM(t *testing.T) {
	s, ts := enrollmentServer(t, t.TempDir())
	k := freshKey(t)
	s.devices.enroll(keyID(k), "viewer", RoleViewer)
	assertStatus(t, enrollRequest(t, ts, freshKey(t), "/resources", nil), 401)
	r := enrollRequest(t, ts, k, "/resources", nil)
	assertStatus(t, r, 200)
	var data struct {
		CPU struct {
			Usage float64 `json:"usagePercent"`
		} `json:"cpu"`
		Memory struct {
			Total uint64  `json:"totalBytes"`
			Usage float64 `json:"usagePercent"`
		} `json:"memory"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		t.Fatal(err)
	}
	if data.Memory.Total == 0 || data.CPU.Usage < 0 || data.CPU.Usage > 100 || data.Memory.Usage < 0 || data.Memory.Usage > 100 {
		t.Fatal("invalid host sample")
	}
}

func TestBootstrapSecretConsumptionSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s, ts := enrollmentServer(t, dir)
	k := freshKey(t)
	s.cfg.TrustedPublicKeys[keyID(k)] = true
	s.cfg.PairingSecret = "bootstrap-fixture"
	assertStatus(t, enrollRequest(t, ts, k, "/pair", pairRequest{PairingSecret: "bootstrap-fixture"}), 200)
	s2, ts2 := enrollmentServer(t, dir)
	s2.cfg.TrustedPublicKeys[keyID(k)] = true
	s2.cfg.PairingSecret = "bootstrap-fixture"
	assertStatus(t, enrollRequest(t, ts2, k, "/pair", pairRequest{}), 200)
	// Explicitly removing the store must not reuse the consumed bootstrap for the same key.
	os.Remove(filepath.Join(dir, "devices.json"))
	s3, ts3 := enrollmentServer(t, dir)
	s3.cfg.TrustedPublicKeys[keyID(k)] = true
	s3.cfg.PairingSecret = "bootstrap-fixture"
	assertStatus(t, enrollRequest(t, ts3, k, "/pair", pairRequest{PairingSecret: "bootstrap-fixture"}), 403)
}

func TestExistingTLSIdentityNeverRotatesSilently(t *testing.T) {
	dir := t.TempDir()
	_, fp, err := ensureCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, again, err := ensureCert(dir)
	if err != nil || fp != again {
		t.Fatal("identity changed on reload")
	}
	before, _ := os.ReadFile(filepath.Join(dir, "agent.crt"))
	os.WriteFile(filepath.Join(dir, "agent.key"), []byte("broken key"), 0600)
	if _, _, err := ensureCert(dir); err == nil {
		t.Fatal("corrupt identity silently replaced")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "agent.crt"))
	if !bytes.Equal(before, after) {
		t.Fatal("certificate overwritten")
	}
}

func TestEnrolledReconnectDoesNotConsumeBootstrapAttemptBudget(t *testing.T) {
	s, ts := enrollmentServer(t, t.TempDir())
	k := freshKey(t)
	s.devices.enroll(keyID(k), "owner", RoleOwner)
	s.pairLimiter = newRateLimiter(1, time.Minute)
	for i := 0; i < 15; i++ {
		assertStatus(t, enrollRequest(t, ts, k, "/pair", pairRequest{}), 200)
	}
}
