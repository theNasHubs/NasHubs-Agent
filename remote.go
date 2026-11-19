package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	Deployed     bool   `json:"deployed"`
	State        string `json:"state"` // up / down / missing / unknown
	Hostname     string `json:"hostname,omitempty"`
	IP           string `json:"ip,omitempty"`
	TunnelID     string `json:"tunnelId,omitempty"`
	DNSName      string `json:"dnsName,omitempty"`      // tailscale MagicDNS name
	BackendState string `json:"backendState,omitempty"` // tailscale: Running / NeedsLogin / ...
	FunnelURL    string `json:"funnelURL,omitempty"`    // public URL of the agent via Tailscale Funnel
}

type networkInfo struct {
	LanIP       string `json:"lanIP"`
	DsmPort     string `json:"dsmPort"`
	AgentDirect string `json:"agentDirect"`
	AgentProxy  string `json:"agentProxy"`
}

type appAccessInfo struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"` // same as id for now
	InternalPort int         `json:"internalPort,omitempty"`
	PathPrefix   string      `json:"pathPrefix,omitempty"`
	State        string      `json:"state"` // up/down/missing/unknown
	HasProxy     bool        `json:"hasProxy"`
	LanURL       string      `json:"lanURL,omitempty"`
	RemoteURL    string      `json:"remoteURL,omitempty"`    // via reverse proxy path
	TailscaleURL string      `json:"tailscaleURL,omitempty"` // http://<tailnet IP>:<port>
	PublicURL    string      `json:"publicURL,omitempty"`    // Cloudflare hostname routed to this port
	AppDir       string      `json:"appDir,omitempty"`       // NAS folder that holds this app's data
	Mounts       []mountInfo `json:"mounts,omitempty"`       // NAS path ↔ container path
}

// mountInfo is one bind mount of a deployed app, for the "access info" screen.
type mountInfo struct {
	Service   string `json:"service"`
	Host      string `json:"host"`
	Container string `json:"container"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

// processStartTime records when the agent started for uptime calculation.
var processStartTime = time.Now()

// handleRemoteStatus returns a comprehensive snapshot of the NAS's remote
// access configuration: agent info, tunnel services, proxy rules, and
// per-app accessibility.
func (s *server) handleRemoteStatus(w http.ResponseWriter, r *http.Request) {
	lanIP := s.lanIP(r)

	resp := remoteStatus{
		OK: true,
		Agent: agentInfo{
			Version: s.cfg.Version,
			Uptime:  int64(time.Since(processStartTime).Seconds()),
			Port:    s.cfg.Port,
		},
		Network: networkInfo{
			LanIP:      lanIP,
			DsmPort:    "5001", // standard DSM HTTPS port
			AgentProxy: "/nashubs-agent/",
		},
	}

	if lanIP != "" {
		resp.Network.AgentDirect = fmt.Sprintf("https://%s:%s", lanIP, s.cfg.Port)
	}

	// --- Tunnel statuses ---
	resp.Tunnels.Tailscale = s.probeTailscale()
	resp.Tunnels.Cloudflare = s.probeCloudflare()
	publicByPort := map[int]string{}
	if resp.Tunnels.Cloudflare.Deployed {
		if rules, err := s.readCloudflareIngress(); err == nil {
			publicByPort = publicHostsByPort(rules)
		}
	}

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
				// Not an agent deployment (a legacy data dir may be the shared
				// docker folder itself, full of the user's own folders).
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
				if lanIP != "" {
					app.LanURL = fmt.Sprintf("http://%s:%d", lanIP, st.InternalPort)
				}
				if ts := resp.Tunnels.Tailscale; ts != nil && ts.IP != "" && ts.BackendState == "Running" {
					app.TailscaleURL = fmt.Sprintf("http://%s:%d", ts.IP, st.InternalPort)
				}
				if h := publicByPort[st.InternalPort]; h != "" {
					app.PublicURL = "https://" + h
				}
			}
			if s.cfg.AppsDir != "" {
				app.AppDir = s.cfg.AppsDir + "/" + id
			}
			app.Mounts = s.appMounts(id, st.Current)

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
	if !s.nginxEnabled() {
		writeJSON(w, http.StatusServiceUnavailable, errMap("reverse proxy disabled", errNginxDisabled))
		return
	}
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
		if info, err := s.tailscaleStatus(); err == nil {
			ts.IP = info.IPv4
			ts.Hostname = info.HostName
			ts.DNSName = info.DNSName
			ts.BackendState = info.BackendState
			if f := s.currentFunnel(info); f.Enabled {
				ts.FunnelURL = f.URL
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
	if !s.nginxEnabled() {
		return nil
	}
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

// lanIP returns the NAS LAN address to show to clients. The agent runs in a
// Docker bridge network, so its own interfaces only show the container
// address (172.17.x.x). Prefer the explicit NASHUBS_LAN_IP, then the private
// IPv4 the client used to reach us (Host header), and report nothing rather
// than a container-internal address.
func (s *server) lanIP(r *http.Request) string {
	if ip := net.ParseIP(s.cfg.LanIP); ip != nil && ip.To4() != nil {
		return ip.String()
	}
	if r != nil {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil && isLanIPv4(ip) {
			return ip.String()
		}
	}
	return ""
}

var _, cgnatNet, _ = net.ParseCIDR("100.64.0.0/10") // tailnet addresses

// isLanIPv4 reports a private IPv4 that is not a tailnet address. An address
// the client actually reached us on is routable from the client, so Docker-
// looking ranges (172.16/12) are kept: some home LANs use them too.
func isLanIPv4(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4.IsPrivate() && !cgnatNet.Contains(v4)
}

// appMounts lists the bind mounts of the app's current compose artifact so the
// app can show which NAS folder appears at which path inside the container.
func (s *server) appMounts(id, version string) []mountInfo {
	if !idSafe.MatchString(id) || !versionDirName.MatchString(version) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(s.cfg.DataDir, id, version, "docker-compose.yml"))
	if err != nil {
		return nil
	}
	return composeMounts(data)
}

func composeMounts(data []byte) []mountInfo {
	var doc struct {
		Services map[string]struct {
			Volumes []any `yaml:"volumes"`
		} `yaml:"services"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []mountInfo
	for _, n := range names {
		for _, v := range doc.Services[n].Volumes {
			switch v := v.(type) {
			case string:
				f := strings.Split(v, ":")
				if len(f) >= 2 && strings.HasPrefix(f[0], "/") {
					out = append(out, mountInfo{Service: n, Host: f[0], Container: f[1], ReadOnly: volumeIsRO(f[2:])})
				}
			case map[string]any:
				if t, _ := v["type"].(string); t == "bind" {
					src, _ := v["source"].(string)
					dst, _ := v["target"].(string)
					ro, _ := v["read_only"].(bool)
					if strings.HasPrefix(src, "/") {
						out = append(out, mountInfo{Service: n, Host: src, Container: dst, ReadOnly: ro})
					}
				}
			}
		}
	}
	return out
}

// publicHostsByPort maps a local port to the Cloudflare hostname routed to it
// (service http(s)://localhost:<port> or 127.0.0.1:<port>).
func publicHostsByPort(rules []ingressRule) map[int]string {
	out := map[int]string{}
	for _, r := range rules {
		if r.Hostname == "" {
			continue
		}
		u, err := url.Parse(r.Service)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			continue
		}
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" {
			continue
		}
		if p, err := strconv.Atoi(u.Port()); err == nil {
			if _, dup := out[p]; !dup {
				out[p] = r.Hostname
			}
		}
	}
	return out
}
