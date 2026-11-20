package main

// DSM accounts are the source of truth for roles: a device paired by a DSM
// administrator is an admin, a device paired by an ordinary DSM user is a member.
// The agent reads accounts with allow-listed commands in the NAS's own namespaces
// (it has root through docker.sock) and confirms who owns a DSM session by asking
// DSM itself on the NAS.

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// hostCommands are the only programs the agent runs on the NAS host.
var hostCommands = map[string]bool{"id": true, "synouser": true, "synogroup": true, "synoshare": true}

const dsmHostPath = "/usr/syno/sbin:/usr/syno/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// host runs an allow-listed command on the NAS host through the pinned helper image.
func (s *server) host(args ...string) ([]byte, error) {
	if len(args) == 0 || !hostCommands[args[0]] {
		return nil, fmt.Errorf("host command not allowed")
	}
	// DSM keeps its tools in /usr/syno/sbin, which is not on the helper image's PATH.
	full := append([]string{"run", "--rm", "--pid=host", "--privileged", helperImage, "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--",
		"env", "PATH=" + dsmHostPath}, args...)
	return s.docker(full...)
}

// dsmUserName accepts the DSM account names the agent works with. It also keeps
// any name from being read as a command-line option.
var dsmUserName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

type dsmAccount struct {
	Name     string
	Exists   bool
	Admin    bool // member of the DSM "administrators" group
	Disabled bool // DSM reports the account as expired (disabled)
}

func (a dsmAccount) role() Role {
	if a.Admin {
		return RoleAdmin
	}
	return RoleMember
}

// lookupDSMUser reads one local DSM account. A missing account is not an error.
func (s *server) lookupDSMUser(name string) (dsmAccount, error) {
	a := dsmAccount{Name: name}
	if !dsmUserName.MatchString(name) {
		return a, fmt.Errorf("invalid DSM user name")
	}
	out, err := s.host("id", name)
	if err != nil {
		if strings.Contains(strings.ToLower(string(out)), "no such user") {
			return a, nil
		}
		return a, fmt.Errorf("read DSM user: %w: %s", err, firstLine(out))
	}
	a.Exists = true
	a.Admin = idInGroup(string(out), "administrators")
	out, err = s.host("synouser", "--get", name)
	if err != nil {
		return a, fmt.Errorf("read DSM user: %w: %s", err, firstLine(out))
	}
	a.Disabled = synouserExpired(string(out))
	return a, nil
}

// idInGroup reads `id` output: uid=1027(an) gid=100(users) groups=100(users),101(administrators)
func idInGroup(out, group string) bool {
	i := strings.Index(out, "groups=")
	if i < 0 {
		return false
	}
	for _, g := range strings.Split(strings.Fields(out[i+len("groups="):] + " ")[0], ",") {
		if strings.HasSuffix(g, "("+group+")") {
			return true
		}
	}
	return false
}

// synouserExpired reads `synouser --get`: "Expired     : [true]" marks a disabled account.
func synouserExpired(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Expired") {
			return strings.Contains(line, "[true]")
		}
	}
	return false
}

// dsmBaseURL is DSM's own HTTPS endpoint as the agent (bridge network) reaches it.
var dsmBaseURL = func() string {
	port := os.Getenv("NASHUBS_DSM_PORT")
	if port == "" {
		port = "5001"
	}
	return "https://" + hostGateway() + ":" + port
}

// dsmClient talks to DSM on this same NAS over the Docker bridge; DSM's certificate
// is issued for its public name, not the bridge address, so it is not verified here.
var dsmClient = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

// dsmSessionUser asks DSM which account a session belongs to. Several WebAPI
// calls are tried because their availability differs between DSM versions.
// dsmAuthCGI is DSM's own session check for add-ons: given the browser's cookie,
// SynoToken and address it prints the signed-in account name. DSM binds a session
// to the address it was opened from, so the check must carry the phone's address,
// not the agent's.
const dsmAuthCGI = "/usr/syno/synoman/webman/modules/authenticate.cgi"

var dsmSessionValue = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{1,512}$`)

// dsmCGIUser asks authenticate.cgi on the NAS host who owns the session.
func (s *server) dsmCGIUser(sid, synoToken, ip string) (string, error) {
	if !dsmSessionValue.MatchString(sid) || (synoToken != "" && !dsmSessionValue.MatchString(synoToken)) {
		return "", fmt.Errorf("cgi: malformed session")
	}
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("cgi: no client address")
	}
	args := []string{"run", "--rm", "--pid=host", "--privileged", helperImage, "nsenter", "-t", "1", "-m", "-u", "-n", "-i", "--",
		"env", "-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "REQUEST_METHOD=GET", "SERVER_PROTOCOL=HTTP/1.1",
		"REMOTE_ADDR=" + ip, "HTTP_COOKIE=id=" + sid, "QUERY_STRING=SynoToken=" + synoToken,
		"HTTP_X_SYNO_TOKEN=" + synoToken, dsmAuthCGI}
	out, err := s.docker(args...)
	if err != nil {
		return "", fmt.Errorf("cgi: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	name := strings.TrimSpace(lines[len(lines)-1])
	if !dsmUserName.MatchString(name) {
		return "", fmt.Errorf("cgi: session not accepted")
	}
	return name, nil
}

// dsmSessionUser names the DSM account that owns a session: first through DSM's
// add-on check on the host, then through the WebAPI (which only accepts the
// session when DSM skips its address check).
func (s *server) dsmSessionUser(sid, synoToken, ip string) (string, error) {
	if sid == "" || len(sid) > 512 || len(synoToken) > 256 {
		return "", fmt.Errorf("DSM session required")
	}
	name, err := s.dsmCGIUser(sid, synoToken, ip)
	if err == nil {
		return name, nil
	}
	reasons := []string{err.Error()}
	calls := []url.Values{
		{"api": {"SYNO.Core.NormalUser"}, "version": {"1"}, "method": {"get"}},
		{"api": {"SYNO.Core.Desktop.Initdata"}, "version": {"1"}, "method": {"get"}},
	}
	for _, q := range calls {
		api := q.Get("api")
		q.Set("_sid", sid)
		req, err := http.NewRequest("GET", dsmBaseURL()+"/webapi/entry.cgi?"+q.Encode(), nil)
		if err != nil {
			reasons = append(reasons, api+": bad request")
			continue
		}
		if synoToken != "" {
			req.Header.Set("X-SYNO-TOKEN", synoToken)
		}
		resp, err := dsmClient.Do(req)
		if err != nil {
			reasons = append(reasons, api+": unreachable")
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var r struct {
			Success bool           `json:"success"`
			Data    map[string]any `json:"data"`
			Error   struct {
				Code int `json:"code"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &r) != nil {
			reasons = append(reasons, fmt.Sprintf("%s: HTTP %d", api, resp.StatusCode))
			continue
		}
		if !r.Success {
			reasons = append(reasons, fmt.Sprintf("%s: code %d", api, r.Error.Code))
			continue
		}
		if name := sessionUserName(r.Data); name != "" {
			return name, nil
		}
		reasons = append(reasons, api+": no user name")
	}
	return "", fmt.Errorf("%s", strings.Join(reasons, "; "))
}

// dsmClientAddr is the address DSM saw the phone at. Behind DSM's nginx the agent
// sees nginx; nginx passes the phone's address in X-Real-IP.
func dsmClientAddr(r *http.Request) string {
	ip := net.ParseIP(clientIP(r))
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if real := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); real != nil {
			return real.String()
		}
	}
	if ip == nil {
		return ""
	}
	return ip.String()
}

// sessionUserName finds the account name in the WebAPI answers above.
func sessionUserName(data map[string]any) string {
	for _, k := range []string{"username", "user", "name"} {
		if v, ok := data[k].(string); ok && dsmUserName.MatchString(v) {
			return v
		}
	}
	if sess, ok := data["session"].(map[string]any); ok {
		return sessionUserName(sess)
	}
	return ""
}

// handleEnrollDSM pairs a device by its owner's DSM session: no invitation, no
// installer. The device signs the request with its own new key; the agent asks DSM
// who the session belongs to and gives that account's role.
func (s *server) handleEnrollDSM(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.pairLimiter.allow("enroll:"+clientIP(r)) || !s.pairLimiter.allow("enroll-global") {
		writeJSON(w, 429, errMap("too many pairing attempts", nil))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSON(w, 400, errMap("bad request", nil))
		return
	}
	auth, err := s.verifySignature(r, body, false)
	if err != nil {
		writeJSON(w, 401, errMap("auth failed", err))
		return
	}
	var req struct {
		SID       string `json:"sid"`
		SynoToken string `json:"synoToken"`
		Label     string `json:"label"`
	}
	if json.Unmarshal(body, &req) != nil || len(req.Label) > 80 {
		writeJSON(w, 400, errMap("bad request", nil))
		return
	}
	s.pairMu.Lock()
	defer s.pairMu.Unlock()
	if d := s.devices.lookup(auth.keyID); d != nil {
		if d.revoked() {
			writeJSON(w, 403, errMap("device revoked", nil))
			return
		}
		s.writePairedDevice(w, d)
		return
	}
	name, err := s.dsmSessionUser(req.SID, req.SynoToken, dsmClientAddr(r))
	if err != nil {
		log.Printf("DSM pairing refused: %v", err)
		writeJSON(w, 403, map[string]any{"ok": false, "error": "DSM_SESSION_REJECTED", "detail": err.Error()})
		return
	}
	acct, err := s.lookupDSMUser(name)
	if err != nil {
		log.Printf("DSM pairing: cannot read account %s: %v", name, err)
		writeJSON(w, 502, map[string]any{"ok": false, "error": "DSM_USER_UNREADABLE", "detail": err.Error()})
		return
	}
	if !acct.Exists || acct.Disabled {
		writeJSON(w, 403, map[string]any{"ok": false, "error": "DSM_USER_DISABLED"})
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = name
	}
	d, err := s.devices.enrollAs(auth.keyID, label, acct.role(), name)
	if err != nil {
		writeJSON(w, 500, errMap("enroll device failed", nil))
		return
	}
	s.writePairedDevice(w, d)
}

// syncDSMRoles follows DSM: a deleted or disabled account loses its devices, and a
// device follows its account into or out of the administrators group. Devices paired
// before 2.2 carry no DSM user and are left as they are.
func (s *server) syncDSMRoles() {
	seen := map[string]dsmAccount{}
	for _, d := range s.devices.list() {
		if d.revoked() || d.DSMUser == "" {
			continue
		}
		a, ok := seen[d.DSMUser]
		if !ok {
			var err error
			if a, err = s.lookupDSMUser(d.DSMUser); err != nil {
				continue // DSM unreadable right now: change nothing
			}
			seen[d.DSMUser] = a
		}
		switch {
		case !a.Exists || a.Disabled:
			if _, err := s.devices.revoke(d.DeviceID); err == nil {
				log.Printf("device %s revoked: DSM account %s removed or disabled", d.DeviceID, d.DSMUser)
			}
		case a.role() != d.Role:
			if err := s.devices.setRole(d.KeyID, a.role()); err == nil {
				log.Printf("device %s is now %s, following DSM account %s", d.DeviceID, a.role(), d.DSMUser)
			}
		}
	}
}

func (s *server) runDSMRoleSync(every time.Duration) {
	for {
		time.Sleep(every)
		s.syncDSMRoles()
	}
}

// firstLine keeps error details short.
func firstLine(out []byte) string {
	line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0])
	if len(line) > 160 {
		line = line[:160]
	}
	return line
}
