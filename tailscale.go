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

type tsSelf struct {
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	UserID       int64    `json:"UserID"`
}

type tsStatusJSON struct {
	BackendState   string `json:"BackendState"`
	AuthURL        string `json:"AuthURL"`
	Self           tsSelf `json:"Self"`
	CurrentTailnet *struct {
		Name string `json:"Name"`
	} `json:"CurrentTailnet"`
	User map[string]struct {
		LoginName string `json:"LoginName"`
	} `json:"User"`
}

// tsInfo is the parsed, client-facing view of `tailscale status --json`.
type tsInfo struct {
	BackendState string // Running, NeedsLogin, NeedsMachineAuth, Stopped, ...
	AuthURL      string
	IPv4         string
	DNSName      string // MagicDNS name without the trailing dot
	HostName     string
	Tailnet      string // tailnet name, e.g. the owner's login or organisation
	LoginName    string // account the NAS node is signed in with
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
	if st.CurrentTailnet != nil {
		info.Tailnet = st.CurrentTailnet.Name
	}
	if u, ok := st.User[fmt.Sprint(st.Self.UserID)]; ok {
		info.LoginName = u.LoginName
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

// handleTailscaleStatus reports login state and the NAS tailnet identity, so
// the app can tell the user which account the NAS is in and check that the
// phone's Tailscale app uses the same one. The interactive login URL joins the
// NAS to whichever tailnet opens it, so only the owner receives it.
func (s *server) handleTailscaleStatus(w http.ResponseWriter, r *http.Request) {
	info, err := s.tailscaleStatus()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deployed": false, "state": stMissing})
		return
	}
	resp := tailscaleResponse(info)
	if authFrom(r).role == RoleAdmin && info.BackendState != "Running" {
		if url := s.tailscaleLoginURL(info); url != "" {
			resp["authURL"] = url
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func tailscaleResponse(info tsInfo) map[string]any {
	return map[string]any{"ok": true, "deployed": true, "backendState": info.BackendState,
		"ip": info.IPv4, "dnsName": info.DNSName, "hostName": info.HostName,
		"tailnet": info.Tailnet, "loginName": info.LoginName}
}

var loginURLInOutput = regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9]+`)

// tailscaleLoginURL returns the pending login URL, asking tailscaled for a new
// one when none is pending. `tailscale up` prints it and keeps waiting, so the
// call is bounded and the URL is read from the output.
func (s *server) tailscaleLoginURL(info tsInfo) string {
	if info.AuthURL != "" {
		return info.AuthURL
	}
	out, _ := s.docker("exec", tailscaleContainer, "timeout", "5", "tailscale", "up", "--reset=false", "--timeout=4s")
	if m := loginURLInOutput.Find(out); m != nil {
		return string(m)
	}
	if info, err := s.tailscaleStatus(); err == nil {
		return info.AuthURL
	}
	return ""
}

// handleTailscaleRelogin signs the NAS out of its tailnet and returns a fresh
// login URL, so the owner can move the NAS to the account the phones use.
// Owner only: it disconnects every device that reaches the NAS over Tailscale.
func (s *server) handleTailscaleRelogin(w http.ResponseWriter, _ *http.Request) {
	if _, err := s.tailscaleStatus(); err != nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "TAILSCALE_NOT_RUNNING"})
		return
	}
	if out, err := s.docker("exec", tailscaleContainer, "tailscale", "logout"); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "LOGOUT_FAILED", "detail": strings.TrimSpace(string(out))})
		return
	}
	info, err := s.tailscaleStatus()
	if err != nil {
		info = tsInfo{}
	}
	resp := tailscaleResponse(info)
	if url := s.tailscaleLoginURL(info); url != "" {
		resp["authURL"] = url
	}
	writeJSON(w, http.StatusOK, resp)
}
