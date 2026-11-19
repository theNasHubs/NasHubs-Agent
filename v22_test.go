package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDeriveAppsDir(t *testing.T) {
	cases := map[[2]string]string{
		{"", "/volume1/docker/nashubs-agent/data"}: "/volume1/docker",
		{"", "/volume2/docker"}:                    "/volume2/docker",
		{"", "/data"}:                              "",
		{"/volume3/docker", "/data"}:               "/volume3/docker",
		{"/etc", "/volume1/docker"}:                "",
	}
	for in, want := range cases {
		if got := deriveAppsDir(in[0], in[1]); got != want {
			t.Errorf("deriveAppsDir(%q,%q)=%q want %q", in[0], in[1], got, want)
		}
	}
}

func TestDeployRendersAppDirAndRejectsUnrendered(t *testing.T) {
	s := &server{cfg: Config{DataDir: t.TempDir(), HostDataDir: "/x"}}
	call := func(compose string) (int, string) {
		body, _ := json.Marshal(deployRequest{ID: "jellyfin", Compose: compose})
		req := httptest.NewRequest("POST", "/deploy", strings.NewReader(string(body)))
		req = req.WithContext(withAuth(req.Context(), RoleViewer))
		rec := httptest.NewRecorder()
		s.handleDeploy(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, body := call("services:\n  a:\n    volumes: [\"{{APP_DIR}}/config:/config\"]\n"); code != 400 || !strings.Contains(body, "APPS_DIR_UNKNOWN") {
		t.Fatalf("unknown apps dir: %d %s", code, body)
	}
	s.cfg.AppsDir = "/volume1/docker"
	if code, body := call("services:\n  a:\n    image: x\n    environment: [\"P={{MEDIA_PATH}}\"]\n"); code != 400 || !strings.Contains(body, "UNRENDERED_PLACEHOLDER") {
		t.Fatalf("unrendered: %d %s", code, body)
	}
}

func TestListSharesSkipsSystemFolders(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"volume1/video", "volume1/docker", "volume1/@appstore", "volume1/#recycle", "volume2/photo", "volumeX/nope"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.WriteFile(filepath.Join(root, "volume1", "file.txt"), nil, 0o644)
	got := listShares(root)
	var paths []string
	for _, s := range got {
		paths = append(paths, s.Path)
	}
	want := []string{"/volume1/docker", "/volume1/video", "/volume2/photo"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("got %v", paths)
	}
}

func TestParseTailscaleStatus(t *testing.T) {
	out := []byte("Warning: client version mismatch\n" + `{"BackendState":"Running","AuthURL":"","Self":{"HostName":"nashubs","DNSName":"nashubs.tail1234.ts.net.","TailscaleIPs":["100.101.102.103","fd7a::1"],"Online":true}}`)
	info, err := parseTailscaleStatus(out)
	if err != nil || info.IPv4 != "100.101.102.103" || info.DNSName != "nashubs.tail1234.ts.net" || info.BackendState != "Running" {
		t.Fatalf("%+v %v", info, err)
	}
	info, _ = parseTailscaleStatus([]byte(`{"BackendState":"NeedsLogin","AuthURL":"https://login.tailscale.com/a/abc123","Self":{}}`))
	if info.AuthURL != "https://login.tailscale.com/a/abc123" {
		t.Fatal(info)
	}
	info, _ = parseTailscaleStatus([]byte(`{"BackendState":"NeedsLogin","AuthURL":"https://evil.example/a/x","Self":{}}`))
	if info.AuthURL != "" {
		t.Fatal("untrusted auth URL passed through")
	}
}

func fakeTailscale(loggedIn *bool, calls *[][]string) func(...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "status --json") && *loggedIn:
			return []byte(`{"BackendState":"Running","Self":{"DNSName":"nas.tail.ts.net.","TailscaleIPs":["100.64.1.2"],"UserID":42},"CurrentTailnet":{"Name":"duc@example.com"},"User":{"42":{"LoginName":"duc@example.com"}}}`), nil
		case strings.Contains(joined, "status --json"):
			return []byte(`{"BackendState":"NeedsLogin","Self":{}}`), errors.New("exit 1")
		case strings.Contains(joined, "tailscale logout"):
			*loggedIn = false
			return nil, nil
		case strings.Contains(joined, "tailscale up"):
			return []byte("To authenticate, visit:\n\n\thttps://login.tailscale.com/a/fresh42\n"), errors.New("timeout")
		}
		return nil, errors.New("unexpected " + joined)
	}
}

func TestTailscaleStatusReportsTailnetAccount(t *testing.T) {
	var calls [][]string
	on := true
	s := &server{runCmd: fakeTailscale(&on, &calls)}
	rec := httptest.NewRecorder()
	s.handleTailscaleStatus(rec, httptest.NewRequest("GET", "/remote/tailscale", nil).WithContext(withAuth(context.Background(), RoleAdmin)))
	body := rec.Body.String()
	for _, want := range []string{`"tailnet":"duc@example.com"`, `"loginName":"duc@example.com"`, `"ip":"100.64.1.2"`, `"dnsName":"nas.tail.ts.net"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
}

func TestTailscaleLoginURLOnlyForOwner(t *testing.T) {
	for _, tc := range []struct {
		role Role
		want bool
	}{{RoleAdmin, false}, {RoleOwner, true}} {
		var calls [][]string
		on := false
		s := &server{runCmd: fakeTailscale(&on, &calls)}
		rec := httptest.NewRecorder()
		s.handleTailscaleStatus(rec, httptest.NewRequest("GET", "/remote/tailscale", nil).WithContext(withAuth(context.Background(), tc.role)))
		if got := strings.Contains(rec.Body.String(), "login.tailscale.com/a/fresh42"); got != tc.want {
			t.Fatalf("role %s: authURL present=%v body=%s", tc.role, got, rec.Body)
		}
	}
}

func TestTailscaleReloginLogsOutAndReturnsNewURL(t *testing.T) {
	var calls [][]string
	on := true
	s := &server{runCmd: fakeTailscale(&on, &calls)}
	rec := httptest.NewRecorder()
	s.handleTailscaleRelogin(rec, httptest.NewRequest("POST", "/remote/tailscale/relogin", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "https://login.tailscale.com/a/fresh42") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var loggedOut bool
	for _, c := range calls {
		if reflect.DeepEqual(c, []string{"exec", "nashubs-tailscale", "tailscale", "logout"}) {
			loggedOut = true
		}
	}
	if !loggedOut {
		t.Fatal(calls)
	}
}

func TestMergeIngressKeepsOtherApps(t *testing.T) {
	existing := []ingressRule{{"immich.example.com", "http://localhost:2283"}, {"jellyfin.example.com", "http://localhost:8095"}}
	got := mergeIngress(existing, []ingressRule{{"jellyfin.example.com", "http://localhost:8096"}, {"pihole.example.com", "http://localhost:8080"}}, []string{"IMMICH.example.com"})
	want := []ingressRule{{"jellyfin.example.com", "http://localhost:8096"}, {"pihole.example.com", "http://localhost:8080"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestParseCloudflareConfigAndPorts(t *testing.T) {
	rules, err := parseCloudflareConfig([]byte("tunnel: abc\ningress:\n  - hostname: jf.example.com\n    service: http://localhost:8096\n  - hostname: nas.example.com\n    service: https://127.0.0.1:5001\n  - service: http_status:404\n"))
	if err != nil || len(rules) != 2 {
		t.Fatal(rules, err)
	}
	m := publicHostsByPort(rules)
	if m[8096] != "jf.example.com" || m[5001] != "nas.example.com" {
		t.Fatal(m)
	}
}

func TestComposeMounts(t *testing.T) {
	m := composeMounts([]byte("services:\n  jellyfin:\n    volumes:\n      - /volume1/docker/jellyfin/config:/config\n      - /volume1/video:/volume1/video:ro\n      - cache:/cache\n"))
	want := []mountInfo{{"jellyfin", "/volume1/docker/jellyfin/config", "/config", false}, {"jellyfin", "/volume1/video", "/volume1/video", true}}
	if !reflect.DeepEqual(m, want) {
		t.Fatal(m)
	}
}

func TestLanIPPrefersExplicitThenHostHeader(t *testing.T) {
	s := &server{}
	r := httptest.NewRequest("GET", "/remote-status", nil)
	r.Host = "192.168.1.20:8443"
	if got := s.lanIP(r); got != "192.168.1.20" {
		t.Fatal(got)
	}
	r.Host = "100.64.1.2:8443"
	if got := s.lanIP(r); got != "" {
		t.Fatal("tailnet address reported as LAN:", got)
	}
	s.cfg.LanIP = "10.0.0.5"
	if got := s.lanIP(r); got != "10.0.0.5" {
		t.Fatal(got)
	}
}

func withAppServer(t *testing.T, h http.HandlerFunc) *server {
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	old := appBaseURL
	appBaseURL = func(int) string { return ts.URL }
	t.Cleanup(func() { appBaseURL = old })
	return &server{httpc: ts.Client()}
}

func TestJellyfinSetupRunsWizardAndCreatesLibraries(t *testing.T) {
	var seen []string
	s := withAppServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/System/Info/Public":
			w.Write([]byte(`{"StartupWizardCompleted":false,"Version":"10.10.7","ServerName":"nas"}`))
		case "/Users/AuthenticateByName":
			if !strings.Contains(string(body), `"Pw":"secret1"`) {
				t.Error("password not sent")
			}
			w.Write([]byte(`{"AccessToken":"tok"}`))
		case "/Library/VirtualFolders":
			if r.URL.Query().Get("paths") != "/volume1/video/Movies" || !strings.Contains(r.Header.Get("Authorization"), `Token="tok"`) {
				t.Error("bad library call", r.URL.RawQuery)
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(204)
		}
	})
	res, err := s.setupJellyfin(jellyfinSetupReq{Port: 8096, Username: "admin", Password: "secret1", Language: "vi", Country: "VN",
		Libraries: []jellyfinLibrary{{Name: "Phim", Type: "movies", Paths: []string{"/volume1/video/Movies"}}}})
	if err != nil || res["ok"] != true {
		t.Fatal(res, err)
	}
	want := []string{"GET /System/Info/Public", "POST /Startup/Configuration", "GET /Startup/User", "POST /Startup/User", "POST /Startup/RemoteAccess", "POST /Startup/Complete", "POST /Users/AuthenticateByName", "POST /Library/VirtualFolders"}
	if !reflect.DeepEqual(seen, want) {
		t.Fatal(seen)
	}
}

func TestJellyfinSetupRefusesCompletedServer(t *testing.T) {
	s := withAppServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/System/Info/Public" {
			t.Error("touched a configured server:", r.URL.Path)
		}
		w.Write([]byte(`{"StartupWizardCompleted":true}`))
	})
	if _, err := s.setupJellyfin(jellyfinSetupReq{Port: 8096, Username: "a", Password: "secret1"}); err == nil || err.Error() != "ALREADY_SET_UP" {
		t.Fatal(err)
	}
}

func TestSetupRequestValidation(t *testing.T) {
	bad := []jellyfinSetupReq{
		{Port: 0, Username: "a", Password: "secret1"},
		{Port: 8096, Username: "a", Password: "secret1", Libraries: []jellyfinLibrary{{Name: "x", Type: "movies", Paths: []string{"/etc"}}}},
		{Port: 8096, Username: "a", Password: "secret1", Libraries: []jellyfinLibrary{{Name: "x", Type: "movies", Paths: []string{"/volume1/@appstore/x"}}}},
		{Port: 8096, Username: "a", Password: "secret1", Libraries: []jellyfinLibrary{{Name: "x", Type: "evil", Paths: []string{"/volume1/video"}}}},
	}
	for i, r := range bad {
		if r.valid() {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestImmichSetupCreatesAdminAndExternalLibrary(t *testing.T) {
	var seen []string
	s := withAppServer(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/api/server/config":
			w.Write([]byte(`{"isInitialized":false}`))
		case "/api/auth/login":
			w.Write([]byte(`{"accessToken":"t","userId":"u1"}`))
		case "/api/libraries":
			b, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(b), `"ownerId":"u1"`) || !strings.Contains(string(b), "/volume1/photo") {
				t.Error(string(b))
			}
			w.Write([]byte(`{"id":"lib1"}`))
		default:
			w.WriteHeader(201)
		}
	})
	req := immichSetupReq{Port: 2283, Email: "a@b.c", Password: "longpassword", Name: "Admin"}
	req.Libraries = append(req.Libraries, struct {
		Name  string   `json:"name"`
		Paths []string `json:"paths"`
	}{"Photo", []string{"/volume1/photo"}})
	res, err := s.setupImmich(req)
	if err != nil || res["ok"] != true {
		t.Fatal(res, err)
	}
	want := []string{"GET /api/server/config", "POST /api/auth/admin-sign-up", "POST /api/auth/login", "POST /api/libraries", "POST /api/libraries/lib1/scan"}
	if !reflect.DeepEqual(seen, want) {
		t.Fatal(seen)
	}
}

func TestUpgradeKeepsConfigAndRestoresOnFailure(t *testing.T) {
	inspect := `[{"Config":{"Image":"ghcr.io/thenashubs/nashubs-agent:latest","Env":["PATH=/usr/bin","NASHUBS_DATA_DIR=/volume1/docker","NASHUBS_TRUSTED_PUBKEY=k1,k2","NASHUBS_AGENT_IMAGE=old"]},"HostConfig":{"Binds":["/var/run/docker.sock:/var/run/docker.sock","/volume1:/volume1","/etc/nginx/conf.d:/etc/nginx/conf.d"],"PortBindings":{"8443/tcp":[{"HostIp":"","HostPort":"8443"}]}}}]`
	r := bootstrapFixture()
	r.Upgrade = true
	for _, healthy := range []bool{true, false} {
		var calls [][]string
		_, err := bootstrapAgent(r, func(args ...string) ([]byte, error) {
			calls = append(calls, args)
			switch args[0] {
			case "ps":
				return []byte("nashubs-agent\n"), nil
			case "inspect":
				return []byte(inspect), nil
			case "exec":
				if !healthy {
					return nil, errors.New("no cli")
				}
				if args[3] == "bootstrap-identity" {
					return []byte(`{"certFingerprint":"fp","enrolled":true}`), nil
				}
			}
			return nil, nil
		}, func() {})
		joined := ""
		for _, c := range calls {
			joined += strings.Join(c, " ") + "\n"
		}
		for _, want := range []string{"rename nashubs-agent nashubs-agent-previous", "-v /volume1:/volume1", "-v /etc/nginx/conf.d:/etc/nginx/conf.d", "-p 8443:8443", "-e NASHUBS_TRUSTED_PUBKEY=k1,k2", "-e NASHUBS_DATA_DIR=/volume1/docker", "-e NASHUBS_AGENT_IMAGE=" + r.Image} {
			if !strings.Contains(joined, want) {
				t.Errorf("healthy=%v missing %q", healthy, want)
			}
		}
		if strings.Contains(joined, "-e NASHUBS_AGENT_IMAGE=old") || strings.Contains(joined, "PATH=") {
			t.Error("stale env carried over")
		}
		if healthy && (err != nil || !strings.Contains(joined, "rm -f nashubs-agent-previous")) {
			t.Fatal(err, joined)
		}
		if !healthy && (err == nil || !strings.Contains(joined, "rename nashubs-agent-previous nashubs-agent") || !strings.Contains(joined, "start nashubs-agent")) {
			t.Fatal("not restored", err, joined)
		}
	}
}

func withAuth(ctx context.Context, role Role) context.Context {
	return context.WithValue(ctx, authKey, authResult{role: role})
}

func TestPickLanIPv4SkipsBridgesAndTailnet(t *testing.T) {
	mk := func(name string) net.Interface { return net.Interface{Name: name, Flags: net.FlagUp} }
	addrs := map[string]string{"docker0": "172.17.0.1/16", "tailscale0": "100.64.1.2/32", "eth0": "192.168.1.20/24"}
	got := pickLanIPv4([]net.Interface{mk("docker0"), mk("tailscale0"), mk("eth0")}, func(i net.Interface) ([]net.Addr, error) {
		_, n, _ := net.ParseCIDR(addrs[i.Name])
		ip, _, _ := net.ParseCIDR(addrs[i.Name])
		n.IP = ip
		return []net.Addr{n}, nil
	})
	if got != "192.168.1.20" {
		t.Fatal(got)
	}
}

func TestPingAdvertisesDSMGatewayOnlyWithNginx(t *testing.T) {
	for _, dir := range []string{"", "/etc/nginx/conf.d"} {
		s := &server{cfg: Config{NginxConfDir: dir}}
		rec := httptest.NewRecorder()
		s.handlePing(rec, httptest.NewRequest("GET", "/ping", nil))
		if got := strings.Contains(rec.Body.String(), "dsm-gateway-v1"); got != (dir != "") {
			t.Fatalf("dir=%q body=%s", dir, rec.Body)
		}
	}
}
