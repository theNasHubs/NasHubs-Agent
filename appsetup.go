package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// First-run setup of Jellyfin and Immich, done by the agent against the app's
// own HTTP API on the NAS, so the user never needs the app's web wizard.
// Credentials pass through the signed request only; the agent stores nothing.

// appBaseURL returns how the agent (in a bridge network) reaches a port the
// host publishes: through the bridge gateway. Overridden in tests.
var appBaseURL = func(port int) string {
	return fmt.Sprintf("http://%s:%d", hostGateway(), port)
}

// hostGateway reads the default route of the agent's network namespace
// (/proc/net/route) — the Docker bridge gateway, i.e. the NAS itself.
func hostGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "127.0.0.1"
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 2 && f[1] == "00000000" {
			b, err := hex.DecodeString(f[2])
			if err != nil || len(b) != 4 {
				continue
			}
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, binary.BigEndian.Uint32(b))
			return ip.String()
		}
	}
	return "127.0.0.1"
}

func (s *server) http() *http.Client {
	if s.httpc != nil {
		return s.httpc
	}
	return &http.Client{Timeout: 60 * time.Second}
}

type setupError struct {
	Code   string
	Status int
}

func (e setupError) Error() string { return e.Code }

// callJSON performs one API call; a non-2xx status becomes setupError(code).
func (s *server) callJSON(method, u string, headers map[string]string, body any, out any, code string) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return setupError{Code: code}
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := s.http().Do(req)
	if err != nil {
		return setupError{Code: "APP_UNREACHABLE"}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return setupError{Code: code, Status: resp.StatusCode}
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return setupError{Code: code}
		}
	}
	return nil
}

var (
	setupNamePattern = regexp.MustCompile(`^[\p{L}\p{N} ._-]{1,64}$`)
	langPattern      = regexp.MustCompile(`^[a-z]{2}(-[A-Z]{2})?$`)
	countryPattern   = regexp.MustCompile(`^[A-Z]{2}$`)
	jellyfinTypes    = map[string]bool{"movies": true, "tvshows": true, "music": true, "homevideos": true, "books": true, "mixed": true, "photos": true}
)

// validMediaPath accepts an absolute /volumeN/<share>/... path without
// traversal or system folders (the same rule as bind mounts).
func validMediaPath(p string) bool {
	if !strings.HasPrefix(p, "/volume") || strings.Contains(p, "..") || !isSafeMountPath(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, "@") || strings.HasPrefix(part, "#") {
			return false
		}
	}
	return len(strings.Split(strings.Trim(p, "/"), "/")) >= 2
}

func validPort(p int) bool { return p > 0 && p < 65536 }

func writeSetupError(w http.ResponseWriter, err error) {
	code, status := "SETUP_FAILED", http.StatusBadGateway
	if se, ok := err.(setupError); ok {
		code = se.Code
		switch se.Code {
		case "INVALID_REQUEST":
			status = http.StatusBadRequest
		case "ALREADY_SET_UP":
			status = http.StatusConflict
		}
	}
	writeJSON(w, status, map[string]any{"ok": false, "error": code})
}

// ---- Jellyfin ----

type jellyfinLibrary struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"` // movies, tvshows, music, homevideos, books, mixed, photos
	Paths []string `json:"paths"`
}

type jellyfinSetupReq struct {
	Port      int               `json:"port"`
	Username  string            `json:"username"`
	Password  string            `json:"password"`
	Language  string            `json:"language"` // UI culture, e.g. "en-US", "vi"
	Country   string            `json:"country"`  // metadata country, e.g. "US", "VN"
	Libraries []jellyfinLibrary `json:"libraries"`
}

func (r jellyfinSetupReq) valid() bool {
	if !validPort(r.Port) || !setupNamePattern.MatchString(r.Username) || len(r.Password) < 4 || len(r.Password) > 256 {
		return false
	}
	if (r.Language != "" && !langPattern.MatchString(r.Language)) || (r.Country != "" && !countryPattern.MatchString(r.Country)) {
		return false
	}
	if len(r.Libraries) > 20 {
		return false
	}
	for _, l := range r.Libraries {
		if !setupNamePattern.MatchString(l.Name) || !jellyfinTypes[l.Type] || len(l.Paths) == 0 || len(l.Paths) > 20 {
			return false
		}
		for _, p := range l.Paths {
			if !validMediaPath(p) {
				return false
			}
		}
	}
	return true
}

const jellyfinClientAuth = `MediaBrowser Client="NasHubs", Device="NasHubs Agent", DeviceId="nashubs-agent-setup", Version="2.2.0"`

func (s *server) setupJellyfin(req jellyfinSetupReq) (map[string]any, error) {
	base := appBaseURL(req.Port)
	h := map[string]string{"Authorization": jellyfinClientAuth}
	var info struct {
		StartupWizardCompleted bool   `json:"StartupWizardCompleted"`
		Version                string `json:"Version"`
		ServerName             string `json:"ServerName"`
	}
	if err := s.callJSON("GET", base+"/System/Info/Public", h, nil, &info, "APP_NOT_READY"); err != nil {
		return nil, err
	}
	if info.StartupWizardCompleted {
		return nil, setupError{Code: "ALREADY_SET_UP"}
	}
	lang, country := req.Language, req.Country
	if lang == "" {
		lang = "en-US"
	}
	if country == "" {
		country = "US"
	}
	metaLang := strings.SplitN(lang, "-", 2)[0]
	if err := s.callJSON("POST", base+"/Startup/Configuration", h, map[string]any{
		"UICulture": lang, "MetadataCountryCode": country, "PreferredMetadataLanguage": metaLang,
	}, nil, "STARTUP_CONFIG_FAILED"); err != nil {
		return nil, err
	}
	// Jellyfin creates the first user lazily; GET initialises it.
	_ = s.callJSON("GET", base+"/Startup/User", h, nil, nil, "STARTUP_USER_FAILED")
	if err := s.callJSON("POST", base+"/Startup/User", h, map[string]any{"Name": req.Username, "Password": req.Password}, nil, "STARTUP_USER_FAILED"); err != nil {
		return nil, err
	}
	_ = s.callJSON("POST", base+"/Startup/RemoteAccess", h, map[string]any{"EnableRemoteAccess": true, "EnableAutomaticPortMapping": false}, nil, "STARTUP_REMOTE_FAILED")
	if err := s.callJSON("POST", base+"/Startup/Complete", h, nil, nil, "STARTUP_COMPLETE_FAILED"); err != nil {
		return nil, err
	}
	var auth struct {
		AccessToken string `json:"AccessToken"`
	}
	if err := s.callJSON("POST", base+"/Users/AuthenticateByName", h, map[string]any{"Username": req.Username, "Pw": req.Password}, &auth, "LOGIN_FAILED"); err != nil {
		return nil, err
	}
	th := map[string]string{"Authorization": jellyfinClientAuth + `, Token="` + auth.AccessToken + `"`}
	var created []string
	for _, l := range req.Libraries {
		q := url.Values{"name": {l.Name}, "collectionType": {l.Type}, "refreshLibrary": {"true"}}
		for _, p := range l.Paths {
			// Folders such as Jellyfin/Movies are created inside the app's shared folder.
			if insideExistingShare(p) {
				_, _ = s.host("mkdir", "-p", p)
			}
			q.Add("paths", p)
		}
		if err := s.callJSON("POST", base+"/Library/VirtualFolders?"+q.Encode(), th, map[string]any{"LibraryOptions": map[string]any{}}, nil, "LIBRARY_FAILED"); err != nil {
			return map[string]any{"ok": false, "error": "LIBRARY_FAILED", "createdLibraries": created, "wizardCompleted": true, "_token": auth.AccessToken}, nil
		}
		created = append(created, l.Name)
	}
	return map[string]any{"ok": true, "serverName": info.ServerName, "version": info.Version, "createdLibraries": created, "_token": auth.AccessToken}, nil
}

func (s *server) handleJellyfinSetup(w http.ResponseWriter, r *http.Request) {
	var req jellyfinSetupReq
	if err := decodeBody(r, &req); err != nil || !req.valid() {
		writeSetupError(w, setupError{Code: "INVALID_REQUEST"})
		return
	}
	res, err := s.setupJellyfin(req)
	if err != nil {
		writeSetupError(w, err)
		return
	}
	if token, _ := res["_token"].(string); token != "" {
		if link, err := s.jellyfinLink(req.Port, token); err == nil {
			s.saveLink("jellyfin", link, "", "")
			res["members"] = true
		}
	}
	delete(res, "_token")
	writeJSON(w, http.StatusOK, res)
}

// ---- Immich ----

type immichSetupReq struct {
	Port      int    `json:"port"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Name      string `json:"name"`
	Libraries []struct {
		Name  string   `json:"name"`
		Paths []string `json:"paths"`
	} `json:"libraries"` // external libraries (read-only photo folders)
}

var emailPattern = regexp.MustCompile(`^[^@\s]{1,64}@[^@\s]{1,190}$`)

func (r immichSetupReq) valid() bool {
	if !validPort(r.Port) || !emailPattern.MatchString(r.Email) || len(r.Password) < 8 || len(r.Password) > 256 || !setupNamePattern.MatchString(r.Name) {
		return false
	}
	if len(r.Libraries) > 20 {
		return false
	}
	for _, l := range r.Libraries {
		if !setupNamePattern.MatchString(l.Name) || len(l.Paths) == 0 || len(l.Paths) > 20 {
			return false
		}
		for _, p := range l.Paths {
			if !validMediaPath(p) {
				return false
			}
		}
	}
	return true
}

func (s *server) setupImmich(req immichSetupReq) (map[string]any, error) {
	base := appBaseURL(req.Port) + "/api"
	var cfg struct {
		IsInitialized bool `json:"isInitialized"`
	}
	if err := s.callJSON("GET", base+"/server/config", nil, nil, &cfg, "APP_NOT_READY"); err != nil {
		return nil, err
	}
	if cfg.IsInitialized {
		return nil, setupError{Code: "ALREADY_SET_UP"}
	}
	if err := s.callJSON("POST", base+"/auth/admin-sign-up", nil, map[string]any{"email": req.Email, "password": req.Password, "name": req.Name}, nil, "ADMIN_SIGNUP_FAILED"); err != nil {
		return nil, err
	}
	var login struct {
		AccessToken string `json:"accessToken"`
		UserID      string `json:"userId"`
	}
	if err := s.callJSON("POST", base+"/auth/login", nil, map[string]any{"email": req.Email, "password": req.Password}, &login, "LOGIN_FAILED"); err != nil {
		return nil, err
	}
	th := map[string]string{"Authorization": "Bearer " + login.AccessToken}
	var created []string
	for _, l := range req.Libraries {
		var lib struct {
			ID string `json:"id"`
		}
		if err := s.callJSON("POST", base+"/libraries", th, map[string]any{"ownerId": login.UserID, "name": l.Name, "importPaths": l.Paths}, &lib, "LIBRARY_FAILED"); err != nil || lib.ID == "" {
			return map[string]any{"ok": false, "error": "LIBRARY_FAILED", "createdLibraries": created, "adminCreated": true, "_token": login.AccessToken, "_userId": login.UserID}, nil
		}
		_ = s.callJSON("POST", base+"/libraries/"+url.PathEscape(lib.ID)+"/scan", th, map[string]any{}, nil, "SCAN_FAILED")
		created = append(created, l.Name)
	}
	return map[string]any{"ok": true, "createdLibraries": created, "_token": login.AccessToken, "_userId": login.UserID}, nil
}

func (s *server) handleImmichSetup(w http.ResponseWriter, r *http.Request) {
	var req immichSetupReq
	if err := decodeBody(r, &req); err != nil || !req.valid() {
		writeSetupError(w, setupError{Code: "INVALID_REQUEST"})
		return
	}
	res, err := s.setupImmich(req)
	if err != nil {
		writeSetupError(w, err)
		return
	}
	if token, _ := res["_token"].(string); token != "" {
		if link, err := s.immichLink(req.Port, token); err == nil {
			userID, _ := res["_userId"].(string)
			s.saveLink("immich", link, s.requesterDSMUser(r), userID)
			res["members"] = true
		}
	}
	delete(res, "_token")
	delete(res, "_userId")
	writeJSON(w, http.StatusOK, res)
}
