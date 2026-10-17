package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// remoteStatus is the response for GET /remote-status.
// It aggregates the agent's own state, deployed tunnel services, reverse proxy
// rules, and local network info into a single snapshot for the iOS app.
type remoteStatus struct {
	OK      bool            `json:"ok"`
	Agent   agentInfo       `json:"agent"`
	Tunnels tunnelStatuses  `json:"tunnels"`
	Proxies []proxyEntry    `json:"proxies"`
	Network networkInfo     `json:"network"`
	Apps    []appAccessInfo `json:"apps"`
}

type agentInfo struct {
	Version string `json:"version"`
	Uptime  int64  `json:"uptime"` // seconds since process start
	Port    string `json:"port"`
}

type tunnelStatuses struct {
	Tailscale  *tunnelStatus `json:"tailscale"`
	Cloudflare *tunnelStatus `json:"cloudflared"`
}

type tunnelStatus struct {
	Deployed bool   `json:"deployed"`
	State    string `json:"state"` // up / down / missing / unknown
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
	TunnelID string `json:"tunnelId,omitempty"`
}

type networkInfo struct {
	LanIP      string `json:"lanIP"`
	DsmPort    string `json:"dsmPort"`
	AgentDirect string `json:"agentDirect"`
	AgentProxy  string `json:"agentProxy"`
}

type appAccessInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"` // same as id for now
	InternalPort int    `json:"internalPort,omitempty"`
	PathPrefix   string `json:"pathPrefix,omitempty"`
	State        string `json:"state"` // up/down/missing/unknown
	HasProxy     bool   `json:"hasProxy"`
	LanURL       string `json:"lanURL,omitempty"`
	RemoteURL    string `json:"remoteURL,omitempty"` // via reverse proxy path
}

// processStartTime records when the agent started for uptime calculation.
var processStartTime = time.Now()

// handleRemoteStatus returns a comprehensive snapshot of the NAS's remote
// access configuration: agent info, tunnel services, proxy rules, and
// per-app accessibility.
func (s *server) handleRemoteStatus(w http.ResponseWriter, r *http.Request) {
	lanIP := detectLanIP()

	resp := remoteStatus{
		OK: true,
		Agent: agentInfo{
			Version: s.cfg.Version,
			Uptime:  int64(time.Since(processStartTime).Seconds()),
			Port:    s.cfg.Port,
		},
		Network: networkInfo{
			LanIP:       lanIP,
			DsmPort:     "5001", // standard DSM HTTPS port
			AgentDirect: fmt.Sprintf("https://%s:%s", lanIP, s.cfg.Port),
			AgentProxy:  "/nashubs-agent/",
		},
	}

	// --- Tunnel statuses ---
	resp.Tunnels.Tailscale = s.probeTailscale()
	resp.Tunnels.Cloudflare = s.probeCloudflare()

	// --- Proxies (from nginx conf.d scan) ---
	resp.Proxies = s.listProxyEntries()

	// --- Per-app access info ---
	proxyMap := map[string]proxyEntry{}
	for _, p := range resp.Proxies {
		proxyMap[p.ID] = p
	}

	entries, err := os.ReadDir(s.cfg.DataDir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			id := e.Name()
			if !idSafe.MatchString(id) {
				continue
			}
			// Skip tunnel services from apps list (they're in tunnels)
			if id == "tailscale" || id == "cloudflared" || id == "cloudflared-quick" {
				continue
			}

			st, err := loadState(s.cfg.DataDir, id)
			if err != nil {
				resp.Apps = append(resp.Apps, appAccessInfo{
					ID:    id,
					Name:  id,
					State: stUnknown,
				})
				continue
			}

			state := s.probeState(id, st.HostPath)
			app := appAccessInfo{
				ID:           id,
				Name:         id,
				InternalPort: st.InternalPort,
				PathPrefix:   st.PathPrefix,
				State:        state,
			}

			if st.InternalPort > 0 {
				app.LanURL = fmt.Sprintf("http://%s:%d", lanIP, st.InternalPort)
			}

			if p, ok := proxyMap[id]; ok {
				app.HasProxy = true
				app.PathPrefix = p.PathPrefix
				app.RemoteURL = p.PathPrefix + "/"
			}

			resp.Apps = append(resp.Apps, app)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleConfigureAllProxies creates reverse proxy rules for ALL deployed
// mini-apps that have an internalPort, in a single batch. Idempotent.
func (s *server) handleConfigureAllProxies(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(s.cfg.DataDir)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("read data dir", err))
		return
	}

	var created []string
	var skipped []string
	var errors []string
	needReload := false

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !idSafe.MatchString(id) {
			continue
		}

		st, err := loadState(s.cfg.DataDir, id)
		if err != nil || st.InternalPort <= 0 {
			continue
		}

		prefix := st.PathPrefix
		if prefix == "" {
			prefix = "/" + id
		}
		if !validAppProxy(prefix, st.InternalPort) {
			errors = append(errors, fmt.Sprintf("%s: invalid proxy settings in state", id))
			continue
		}

		confFile := fmt.Sprintf("%s/dsm.nashubs-%s.conf", s.cfg.NginxConfDir, id)
		if _, err := os.Stat(confFile); err == nil {
			skipped = append(skipped, id)
			continue // already exists
		}

		conf := generateNginxConf(prefix, st.InternalPort)
		if err := os.WriteFile(confFile, []byte(conf), 0o644); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		created = append(created, id)
		needReload = true
	}

	if needReload {
		if err := s.testNginx(); err != nil {
			// Rollback all created configs
			for _, id := range created {
				confFile := fmt.Sprintf("%s/dsm.nashubs-%s.conf", s.cfg.NginxConfDir, id)
				_ = os.Remove(confFile)
			}
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"ok":     false,
				"error":  "nginx config test failed — rolled back all new configs",
				"detail": err.Error(),
			})
			return
		}
		_ = s.reloadNginx()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"created": created,
		"skipped": skipped,
		"errors":  errors,
	})
}

// ensureAllProxies creates proxy configs for all deployed apps on boot.
// Called once during startup, after ensureSelfProxy().
func (s *server) ensureAllProxies() {
	if s.cfg.NginxConfDir == "" {
		return
	}
	entries, err := os.ReadDir(s.cfg.DataDir)
	if err != nil {
		return
	}

	var written []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		if !idSafe.MatchString(id) {
			continue
		}
		st, err := loadState(s.cfg.DataDir, id)
		if err != nil || st.InternalPort <= 0 {
			continue
		}
		prefix := st.PathPrefix
		if prefix == "" {
			prefix = "/" + id
		}
		if !validAppProxy(prefix, st.InternalPort) {
			continue
		}
		confFile := fmt.Sprintf("%s/dsm.nashubs-%s.conf", s.cfg.NginxConfDir, id)
		if _, err := os.Stat(confFile); err == nil {
			continue // already exists
		}
		conf := generateNginxConf(prefix, st.InternalPort)
		if os.WriteFile(confFile, []byte(conf), 0o644) == nil {
			written = append(written, confFile)
		}
	}

	if len(written) > 0 {
		if s.testNginx() == nil {
			_ = s.reloadNginx()
		} else {
			// Never leave a config behind that would make DSM's nginx fail its next reload.
			for _, f := range written {
				_ = os.Remove(f)
			}
		}
	}
}

// --- Tunnel probing helpers ---

// probeTailscale checks if the tailscale container is deployed and running,
// and extracts its IP and hostname if possible.
func (s *server) probeTailscale() *tunnelStatus {
	st, err := loadState(s.cfg.DataDir, "tailscale")
	if err != nil {
		return &tunnelStatus{Deployed: false, State: stMissing}
	}
	state := s.probeState("tailscale", st.HostPath)
	ts := &tunnelStatus{Deployed: true, State: state}

	if state == stUp {
		// Try to get tailscale status from the running container
		cmd := exec.Command("docker", "exec", "nashubs-tailscale", "tailscale", "status", "--json")
		out, err := cmd.CombinedOutput()
		if err == nil {
			// Extract IP and hostname from JSON output (lightweight parsing)
			outStr := string(out)
			if ip := extractJSONString(outStr, "TailscaleIPs"); ip != "" {
				ts.IP = ip
			}
			// Try Self.HostName
			if hn := extractJSONString(outStr, "Self"); hn != "" {
				ts.Hostname = hn
			}
		}
		// Fallback: try `tailscale ip -4`
		if ts.IP == "" {
			cmd2 := exec.Command("docker", "exec", "nashubs-tailscale", "tailscale", "ip", "-4")
			if out2, err := cmd2.CombinedOutput(); err == nil {
				ts.IP = strings.TrimSpace(string(out2))
			}
		}
	}
	return ts
}

// probeCloudflare checks if the cloudflared container is deployed and running.
func (s *server) probeCloudflare() *tunnelStatus {
	// Check named tunnel first
	st, err := loadState(s.cfg.DataDir, "cloudflared")
	if err != nil {
		// Check quick tunnel
		st2, err2 := loadState(s.cfg.DataDir, "cloudflared-quick")
		if err2 != nil {
			return &tunnelStatus{Deployed: false, State: stMissing}
		}
		state := s.probeState("cloudflared-quick", st2.HostPath)
		return &tunnelStatus{Deployed: true, State: state}
	}
	state := s.probeState("cloudflared", st.HostPath)
	return &tunnelStatus{Deployed: true, State: state}
}

// listProxyEntries scans nginx conf.d for nashubs proxy rules.
func (s *server) listProxyEntries() []proxyEntry {
	entries, err := os.ReadDir(s.cfg.NginxConfDir)
	if err != nil {
		return nil
	}
	var proxies []proxyEntry
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "dsm.nashubs-") || !strings.HasSuffix(name, ".conf") {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "dsm.nashubs-"), ".conf")
		if id == "agent" {
			continue
		}
		data, err := os.ReadFile(fmt.Sprintf("%s/%s", s.cfg.NginxConfDir, name))
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
	return proxies
}

// --- Network helpers ---

// detectLanIP returns the first non-loopback IPv4 address on the host.
func detectLanIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "0.0.0.0"
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "0.0.0.0"
}

// extractJSONString does a quick substring search for a JSON key and returns
// the first string-like value after it. Not a full JSON parser — just enough
// for grabbing an IP or hostname from tailscale status output.
func extractJSONString(json, key string) string {
	idx := strings.Index(json, `"`+key+`"`)
	if idx < 0 {
		return ""
	}
	rest := json[idx+len(key)+3:]
	// Find the next quoted string value
	start := strings.IndexByte(rest, '"')
	if start < 0 {
		return ""
	}
	rest = rest[start+1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return ""
	}
	return rest[:end]
}
