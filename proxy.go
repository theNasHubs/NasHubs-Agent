package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// proxyRequest is the body for POST /proxy.
type proxyRequest struct {
	ID           string `json:"id"`           // mini-app id, e.g. "jellyfin"
	InternalPort int    `json:"internalPort"` // container's host-mapped port, e.g. 8096
	PathPrefix   string `json:"pathPrefix"`   // URL path prefix, e.g. "/jellyfin"
	Remove       bool   `json:"remove"`       // true → delete the proxy rule
}

type proxyEntry struct {
	ID           string `json:"id"`
	InternalPort int    `json:"internalPort"`
	PathPrefix   string `json:"pathPrefix"`
}

var pathPrefixSafe = regexp.MustCompile(`^/[a-z0-9_-]+$`)

// appPrefixSafe validates reverse-proxy prefixes that arrive with /deploy or are read back from
// state.json. They are interpolated into an nginx config included by DSM's own server blocks,
// so only slash-separated slugs are allowed (templates use e.g. /apps/qbittorrent).
var appPrefixSafe = regexp.MustCompile(`^(/[A-Za-z0-9_-]+)+$`)

// validAppProxy reports whether prefix and port are safe to write into an nginx location block.
func validAppProxy(prefix string, port int) bool {
	return appPrefixSafe.MatchString(prefix) && port > 0 && port <= 65535
}

// handleProxy creates or removes an Nginx reverse proxy location block in
// DSM's nginx config directory. After writing the config, it reloads nginx
// so the change takes effect immediately.
//
// The location block is placed in /etc/nginx/conf.d/dsm.nashubs-{id}.conf,
// which DSM's main nginx.conf includes inside both the :5000 and :5001
// server blocks (via `include conf.d/dsm.*.conf`).
func (s *server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if !s.nginxEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, errMap("reverse proxy disabled", errNginxDisabled))
		return
	}
	var req proxyRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("bad request", err))
		return
	}
	if !idSafe.MatchString(req.ID) {
		writeJSON(w, http.StatusBadRequest, errMap("invalid id", nil))
		return
	}
	// "agent" maps to dsm.nashubs-agent.conf — the agent's own location block
	// written by ensureSelfProxy on boot. Creating here overwrites it (the
	// /nashubs-agent/ routes vanish until restart); removing deletes it
	// outright. Either way remote access to the agent is severed.
	if reservedAppIDs[req.ID] {
		writeJSON(w, http.StatusForbidden, errMap("id "+req.ID+" is reserved", nil))
		return
	}

	confFile := filepath.Join(s.cfg.NginxConfDir, fmt.Sprintf("dsm.nashubs-%s.conf", req.ID))

	if req.Remove {
		_ = os.Remove(confFile)
		if err := s.reloadNginx(); err != nil {
			writeJSON(w, http.StatusInternalServerError, errMap("nginx reload failed", err))
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": req.ID})
		return
	}

	// Validate
	if req.InternalPort <= 0 || req.InternalPort > 65535 {
		writeJSON(w, http.StatusBadRequest, errMap("invalid port", nil))
		return
	}
	prefix := req.PathPrefix
	if prefix == "" {
		prefix = "/" + req.ID
	}
	if !pathPrefixSafe.MatchString(prefix) {
		writeJSON(w, http.StatusBadRequest, errMap("invalid pathPrefix (must be /lowercase-slug)", nil))
		return
	}

	// Generate nginx location block
	conf := generateNginxConf(prefix, req.InternalPort)

	if err := os.WriteFile(confFile, []byte(conf), 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("write nginx conf", err))
		return
	}

	// Test config before reloading
	if err := s.testNginx(); err != nil {
		// Rollback: remove the bad config
		_ = os.Remove(confFile)
		writeJSON(w, http.StatusUnprocessableEntity, errMap("nginx config test failed — rolled back", err))
		return
	}

	if err := s.reloadNginx(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("nginx reload failed", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"id":         req.ID,
		"pathPrefix": prefix,
		"confFile":   confFile,
	})
}

// handleListProxies returns all active nashubs proxy rules by scanning the
// nginx conf directory for dsm.nashubs-*.conf files.
func (s *server) handleListProxies(w http.ResponseWriter, r *http.Request) {
	if !s.nginxEnabled() {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proxies": []proxyEntry{}})
		return
	}
	entries, err := os.ReadDir(s.cfg.NginxConfDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("read nginx conf dir", err))
		return
	}

	var proxies []proxyEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "dsm.nashubs-") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		// dsm.nashubs-{id}.conf → id
		id := strings.TrimSuffix(strings.TrimPrefix(name, "dsm.nashubs-"), ".conf")
		if id == "agent" {
			continue // skip the agent's own proxy
		}

		// Parse port and path from the config file
		data, err := os.ReadFile(filepath.Join(s.cfg.NginxConfDir, name))
		if err != nil {
			continue
		}
		port, path := parseNginxConf(string(data))
		proxies = append(proxies, proxyEntry{
			ID:           id,
			InternalPort: port,
			PathPrefix:   path,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "proxies": proxies})
}

// generateNginxConf creates an nginx location block that reverse-proxies
// from a path prefix to an internal HTTP port on localhost.
func generateNginxConf(pathPrefix string, port int) string {
	return fmt.Sprintf(`# Auto-generated by NasHubs Agent — do not edit manually.
# Mini-app reverse proxy: %s → http://127.0.0.1:%d

location = %s {
    absolute_redirect off;
    return 301 %s/;
}

location ^~ %s/ {
    proxy_pass http://127.0.0.1:%d/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    client_max_body_size 0;
}
`, pathPrefix, port, pathPrefix, pathPrefix, pathPrefix, port)
}

// errNginxDisabled is returned by every nginx operation when the reverse-proxy
// integration is turned off (NASHUBS_NGINX_CONF_DIR=none).
var errNginxDisabled = errors.New("reverse proxy integration is disabled (NASHUBS_NGINX_CONF_DIR=none)")

// nginxDisabledValue reports whether a NASHUBS_NGINX_CONF_DIR value means "off".
func nginxDisabledValue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "none", "off", "disabled":
		return true
	}
	return false
}

// nginxEnabled reports whether the agent manages DSM's nginx conf.d.
func (s *server) nginxEnabled() bool {
	return s.cfg.NginxConfDir != ""
}

// testNginx runs `nginx -t` on the host to validate the config before reloading.
func (s *server) testNginx() error {
	if !s.nginxEnabled() {
		return errNginxDisabled
	}
	// The agent is isolated, but has access to docker.sock.
	// We spawn an ephemeral container entering the host's namespace to run nginx -t.
	cmd := exec.Command("docker", "run", "--rm", "--pid=host", "--privileged", helperImage, "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "nginx", "-t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// reloadNginx sends the reload signal to the host's nginx process.
func (s *server) reloadNginx() error {
	if !s.nginxEnabled() {
		return errNginxDisabled
	}
	// Try Synology's native synosystemctl first
	cmdSyno := exec.Command("docker", "run", "--rm", "--pid=host", "--privileged", helperImage, "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "synosystemctl", "restart", "nginx")
	if out, err := cmdSyno.CombinedOutput(); err == nil {
		_ = out
		return nil
	}
	// Fallback to standard nginx reload
	cmd := exec.Command("docker", "run", "--rm", "--pid=host", "--privileged", helperImage, "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "nginx", "-s", "reload")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

// parseNginxConf extracts port and path prefix from a generated config file.
func parseNginxConf(content string) (port int, path string) {
	// Parse "location ^~ /prefix/ {"
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "location ^~ ") {
			// location ^~ /jellyfin/ {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				path = strings.TrimSuffix(parts[2], "/")
			}
		}
		if strings.HasPrefix(line, "proxy_pass http://127.0.0.1:") {
			// proxy_pass http://127.0.0.1:8096/;
			s := strings.TrimPrefix(line, "proxy_pass http://127.0.0.1:")
			s = strings.TrimSuffix(s, "/;")
			s = strings.TrimSuffix(s, ";")
			fmt.Sscanf(s, "%d", &port)
		}
	}
	return
}

// ensureSelfProxy creates the nginx configuration for the agent itself
// on boot, so it is accessible via the Synology reverse proxy (e.g., Cloudflare Tunnel).
func (s *server) ensureSelfProxy() {
	if s.cfg.NginxConfDir == "" {
		return
	}
	confFile := filepath.Join(s.cfg.NginxConfDir, "dsm.nashubs-agent.conf")

	// Agent proxy uses HTTPS and disables SSL verify because the agent's cert is self-signed.
	conf := `# Auto-generated by NasHubs Agent on boot
location = /nashubs-agent {
    absolute_redirect off;
    return 301 /nashubs-agent/;
}

location ^~ /nashubs-agent/ {
    proxy_pass https://127.0.0.1:8443/;
    proxy_ssl_verify off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_request_buffering off;
}`
	s.installConf(confFile, conf)
	s.ensureLegacySelfProxy()
}

// legacySelfProxyConf is the location the Nasdeck-era agent installed. The
// Nasdeck-era iOS app (still in production) falls back to /nasdeck-agent/ when
// it reaches the agent through DSM's reverse proxy.
const legacySelfProxyConf = `# Auto-generated by NasHubs Agent: legacy path for Nasdeck-era clients
location = /nasdeck-agent {
    absolute_redirect off;
    return 301 /nasdeck-agent/;
}

location ^~ /nasdeck-agent/ {
    proxy_pass https://127.0.0.1:8443/;
    proxy_ssl_verify off;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffering off;
    proxy_request_buffering off;
}`

// ensureLegacySelfProxy installs dsm.nasdeck-agent.conf only when it does not
// exist. A file left by the Nasdeck-era agent already proxies the same path to
// the same port, so it is kept as is; reusing its name means the two can never
// define the location twice.
func (s *server) ensureLegacySelfProxy() {
	confFile := filepath.Join(s.cfg.NginxConfDir, "dsm.nasdeck-agent.conf")
	if _, err := os.Lstat(confFile); err == nil || !os.IsNotExist(err) {
		return
	}
	s.installConf(confFile, legacySelfProxyConf)
}

// installConf writes an nginx conf file, validates the whole config with
// nginx -t and reloads. If the test fails, the previous file content is
// restored (or the new file removed) so DSM's nginx is never left with a
// config it cannot load.
func (s *server) installConf(confFile, conf string) {
	previous, readErr := os.ReadFile(confFile)
	if readErr == nil && string(previous) == conf {
		return // already up to date
	}
	if err := os.WriteFile(confFile, []byte(conf), 0o644); err != nil {
		return // nothing new on disk, so nothing to test or reload
	}
	if s.testNginx() != nil {
		if readErr == nil {
			_ = os.WriteFile(confFile, previous, 0o644)
		} else {
			_ = os.Remove(confFile)
		}
		return
	}
	_ = s.reloadNginx()
}
