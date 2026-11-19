package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Tailscale runs as the "tailscale" mini-app (container nashubs-tailscale,
// host networking). The agent only ever runs fixed `tailscale` subcommands in
// that container; nothing from the request reaches a command line.

const tailscaleContainer = "nashubs-tailscale"

// funnelPublicPort is the public Funnel port that fronts the agent. Funnel
// only listens on 443, 8443 and 10000; 443/8443 may already be taken on the
// NAS (DSM, the agent's own published port), so 10000 is used.
const funnelPublicPort = "10000"

type tsSelf struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
}

type tsStatusJSON struct {
	BackendState string `json:"BackendState"`
	AuthURL      string `json:"AuthURL"`
	Self         tsSelf `json:"Self"`
}

// tsInfo is the parsed, client-facing view of `tailscale status --json`.
type tsInfo struct {
	BackendState string // Running, NeedsLogin, NeedsMachineAuth, Stopped, ...
	AuthURL      string
	IPv4         string
	DNSName      string // MagicDNS name without the trailing dot
	HostName     string
}

var authURLPattern = regexp.MustCompile(`^https://login\.tailscale\.com/a/[A-Za-z0-9]+$`)

func parseTailscaleStatus(out []byte) (tsInfo, error) {
	var st tsStatusJSON
	// `tailscale status --json` may print a warning line before the JSON.
	if i := strings.IndexByte(string(out), '{'); i > 0 {
		out = out[i:]
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return tsInfo{}, err
	}
	info := tsInfo{BackendState: st.BackendState, HostName: st.Self.HostName, DNSName: strings.TrimSuffix(st.Self.DNSName, ".")}
	for _, ip := range st.Self.TailscaleIPs {
		if strings.Count(ip, ".") == 3 {
			info.IPv4 = ip
			break
		}
	}
	if authURLPattern.MatchString(st.AuthURL) {
		info.AuthURL = st.AuthURL
	}
	return info, nil
}

// docker runs a fixed docker argv with a timeout (test seam: s.runCmd).
func (s *server) docker(args ...string) ([]byte, error) {
	if s.runCmd != nil {
		return s.runCmd(args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "docker", args...).CombinedOutput()
}

func (s *server) tailscaleStatus() (tsInfo, error) {
	out, err := s.docker("exec", tailscaleContainer, "tailscale", "status", "--json")
	if len(out) == 0 && err != nil {
		return tsInfo{}, err
	}
	// status exits non-zero while logged out but still prints valid JSON.
	return parseTailscaleStatus(out)
}

// handleTailscaleStatus reports login state, the NAS tailnet address and,
// while logged out, the login URL the app opens for the user (no auth key).
func (s *server) handleTailscaleStatus(w http.ResponseWriter, _ *http.Request) {
	info, err := s.tailscaleStatus()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deployed": false, "state": stMissing})
		return
	}
	resp := map[string]any{"ok": true, "deployed": true, "backendState": info.BackendState,
		"ip": info.IPv4, "dnsName": info.DNSName, "hostName": info.HostName}
	if info.BackendState != "Running" && info.AuthURL == "" {
		// Ask tailscaled for a fresh interactive login URL; it prints it and keeps
		// waiting, so bound the call and read the URL from the output.
		out, _ := s.docker("exec", tailscaleContainer, "timeout", "5", "tailscale", "up", "--reset=false", "--timeout=4s")
		if m := regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9]+`).Find(out); m != nil {
			info.AuthURL = string(m)
		}
	}
	if info.AuthURL != "" {
		resp["authURL"] = info.AuthURL
	}
	writeJSON(w, http.StatusOK, resp)
}

type funnelStatus struct {
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url,omitempty"`
	NeedsEnable string `json:"needsEnableURL,omitempty"` // admin console link to allow Funnel
	Error       string `json:"error,omitempty"`
}

var funnelEnablePattern = regexp.MustCompile(`https://login\.tailscale\.com/f/funnel\?node=[A-Za-z0-9]+`)

func (s *server) funnelURL(info tsInfo) string {
	if info.DNSName == "" {
		return ""
	}
	return "https://" + info.DNSName + ":" + funnelPublicPort
}

// currentFunnel reads `tailscale funnel status --json` and reports whether the
// agent's public port is funnelled.
func (s *server) currentFunnel(info tsInfo) funnelStatus {
	out, err := s.docker("exec", tailscaleContainer, "tailscale", "funnel", "status", "--json")
	if err != nil {
		return funnelStatus{}
	}
	var st struct {
		AllowFunnel map[string]bool `json:"AllowFunnel"`
	}
	if i := strings.IndexByte(string(out), '{'); i >= 0 {
		out = out[i:]
	}
	if json.Unmarshal(out, &st) != nil {
		return funnelStatus{}
	}
	key := info.DNSName + ":" + funnelPublicPort
	if st.AllowFunnel[key] {
		return funnelStatus{Enabled: true, URL: s.funnelURL(info)}
	}
	return funnelStatus{}
}

func (s *server) handleFunnelStatus(w http.ResponseWriter, _ *http.Request) {
	info, err := s.tailscaleStatus()
	if err != nil || info.BackendState != "Running" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "funnel": funnelStatus{Error: "TAILSCALE_NOT_RUNNING"}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "funnel": s.currentFunnel(info)})
}

// handleFunnel turns public access to the agent on or off. The agent is the
// only target: https://<magicdns>:10000 → https+insecure://localhost:<agent
// port>. Every request through it is still Ed25519-signed and role-checked.
func (s *server) handleFunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enable bool `json:"enable"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("bad request", err))
		return
	}
	info, err := s.tailscaleStatus()
	if err != nil || info.BackendState != "Running" || info.DNSName == "" {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "TAILSCALE_NOT_RUNNING"})
		return
	}
	target := fmt.Sprintf("https+insecure://localhost:%s", s.cfg.Port)
	var out []byte
	if req.Enable {
		out, err = s.docker("exec", tailscaleContainer, "tailscale", "funnel", "--bg", "--yes", "--https="+funnelPublicPort, target)
	} else {
		out, err = s.docker("exec", tailscaleContainer, "tailscale", "funnel", "--https="+funnelPublicPort, "off")
	}
	if err != nil {
		st := funnelStatus{Error: "FUNNEL_FAILED"}
		if m := funnelEnablePattern.Find(out); m != nil {
			st = funnelStatus{Error: "FUNNEL_NOT_ALLOWED", NeedsEnable: string(m)}
		} else if strings.Contains(strings.ToLower(string(out)), "https") && strings.Contains(strings.ToLower(string(out)), "not enabled") {
			st = funnelStatus{Error: "HTTPS_NOT_ENABLED", NeedsEnable: "https://login.tailscale.com/admin/dns"}
		}
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": st.Error, "funnel": st})
		return
	}
	st := s.currentFunnel(info)
	if req.Enable && !st.Enabled {
		// `funnel --bg` succeeded; status may lag a moment behind.
		st = funnelStatus{Enabled: true, URL: s.funnelURL(info)}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "funnel": st})
}
