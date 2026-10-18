package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPolicy(t *testing.T) composePolicy {
	t.Helper()
	data := t.TempDir()
	return composePolicy{
		appID:       "jellyfin",
		dataDir:     data,
		hostDataDir: "/volume1/docker",
		projectDir:  filepath.Join(data, "jellyfin", "v0123456789ab"),
	}
}

func TestComposePolicyAllowsTypicalApps(t *testing.T) {
	p := testPolicy(t)
	ok := map[string]string{
		"jellyfin": `
services:
  jellyfin:
    image: jellyfin/jellyfin:10.9
    container_name: jellyfin
    restart: unless-stopped
    ports: ["8096:8096"]
    environment:
      - TZ=Asia/Ho_Chi_Minh
    volumes:
      - /volume1/docker/jellyfin/config:/config
      - /volume1/video:/media:ro
      - cache:/cache
      - ./data:/data
      - /tmp/anon
    devices:
      - /dev/dri:/dev/dri
volumes:
  cache: {}
`,
		"long syntax, anchors, vpn sidecar": `
x-common: &common
  restart: always
  logging: {driver: json-file}
services:
  vpn:
    <<: *common
    image: qmcgaw/gluetun
    devices: ["/dev/net/tun"]
  app:
    <<: *common
    image: qbittorrent
    network_mode: service:vpn
    tmpfs: [/run]
    volumes:
      - type: bind
        source: /volume2/downloads/qb
        target: /downloads
      - type: volume
        source: qbconf
        target: /config
volumes:
  qbconf:
    driver: local
networks:
  default:
    labels: {a: b}
`,
	}
	for name, c := range ok {
		if err := p.check([]byte(c)); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

func TestComposePolicyRejectsHostAccess(t *testing.T) {
	p := testPolicy(t)
	svc := func(body string) string { return "services:\n  a:\n    image: x\n" + body }
	vol := func(v string) string { return svc("    volumes:\n      - " + v + "\n") }
	bad := map[string]string{
		"privileged":            svc("    privileged: true\n"),
		"privileged string":     svc("    privileged: \"true\"\n"),
		"pid host":              svc("    pid: host\n"),
		"ipc host":              svc("    ipc: host\n"),
		"userns host":           svc("    userns_mode: host\n"),
		"network host":          svc("    network_mode: host\n"),
		"network container":     svc("    network_mode: container:nashubs-agent\n"),
		"network interpolated":  svc("    network_mode: ${NET}\n"),
		"cap_add":               svc("    cap_add: [SYS_ADMIN]\n"),
		"security_opt":          svc("    security_opt: [apparmor:unconfined]\n"),
		"volumes_from":          svc("    volumes_from: [\"container:nashubs-agent\"]\n"),
		"extends file":          svc("    extends: {file: /volume1/x/evil.yml, service: p}\n"),
		"build":                 svc("    build: /\n"),
		"env_file":              svc("    env_file: /etc/shadow\n"),
		"api socket":            svc("    use_api_socket: true\n"),
		"unknown key":           svc("    some_future_option: true\n"),
		"device disk":           svc("    devices: [\"/dev/sda:/dev/sda\"]\n"),
		"device long":           svc("    devices: [{source: /dev/mem, target: /dev/mem}]\n"),
		"root":                  vol("/:/host"),
		"docker.sock":           vol("/var/run/docker.sock:/var/run/docker.sock"),
		"etc":                   vol("/etc:/x"),
		"whole volume":          vol("/volume1:/v"),
		"synology system dir":   vol("/volume1/@docker:/x"),
		"recycle bin":           vol("/volume1/video/#recycle:/x"),
		"agent data dir":        vol("/volume1/docker:/x"),
		"app deploy dir":        vol("/volume1/docker/jellyfin:/x"),
		"other app version dir": vol("/volume1/docker/other/v0123456789ab:/x"),
		"state file":            vol("/volume1/docker/jellyfin/state.json:/x"),
		"dotdot":                vol("/volume1/video/../docker:/x"),
		"project dir":           vol(".:/x"),
		"project dir slash":     vol("./:/x"),
		"parent":                vol("../x:/y"),
		"own compose":           vol("./docker-compose.yml:/x"),
		"home":                  vol("~/x:/y"),
		"interpolated":          vol("${HOME}:/h"),
		"interpolated default":  vol("${X:-/}:/h"),
		"long bind root":        svc("    volumes:\n      - {type: bind, source: /, target: /h}\n"),
		"long volume abs":       svc("    volumes:\n      - {type: volume, source: /etc, target: /h}\n"),
		"npipe":                 svc("    volumes:\n      - {type: npipe, source: x, target: /h}\n"),
		"named volume bind":     svc("") + "volumes:\n  v:\n    driver_opts: {type: none, o: bind, device: /}\n",
		"external volume":       svc("") + "volumes:\n  v:\n    external: true\n",
		"host network external": svc("") + "networks:\n  default:\n    name: host\n    external: true\n",
		"include":               "include: [/volume1/x/evil.yml]\n" + svc(""),
		"v1 format":             "a:\n  image: x\n  privileged: true\n",
		"no services":           "version: '3'\n",
		"merge smuggles priv":   "x-p: &p\n  privileged: true\nservices:\n  a:\n    <<: *p\n    image: x\n",
		"duplicate key":         "services:\n  a:\n    image: x\n  a:\n    image: y\n    privileged: true\n",
		"invalid yaml":          "services: [",
		"service not a map":     "services:\n  a: x\n",
	}
	for name, c := range bad {
		if err := p.check([]byte(c)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestComposePolicyRejectsSymlinkedBind(t *testing.T) {
	p := testPolicy(t)
	if err := os.MkdirAll(p.projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(p.projectDir, "data")); err != nil {
		t.Fatal(err)
	}
	c := "services:\n  a:\n    image: x\n    volumes:\n      - ./data/etc:/x\n"
	if err := p.check([]byte(c)); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked bind accepted: %v", err)
	}
}

func TestDeployPolicyAppliesToAdminOnly(t *testing.T) {
	data := t.TempDir()
	s := &server{cfg: Config{DataDir: data, HostDataDir: data}}
	body := `{"id":"evil","compose":"services:\n  a:\n    image: alpine\n    privileged: true\n"}`
	for _, role := range []Role{RoleAdmin, RoleViewer, ""} {
		req := httptest.NewRequest(http.MethodPost, "/deploy", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), authKey, authResult{role: role}))
		rec := httptest.NewRecorder()
		s.handleDeploy(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("role %q: status %d, want 403 (%s)", role, rec.Code, rec.Body)
		}
	}
	if _, err := os.Stat(filepath.Join(data, "evil")); !os.IsNotExist(err) {
		t.Fatalf("rejected deploy wrote files: %v", err)
	}
}
