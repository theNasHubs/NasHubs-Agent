package main

// Members get their own accounts in the shared apps (Immich, Jellyfin).
//
// DSM stays the source of truth: every active local DSM user gets
//   - a Photos folder in their DSM home (created once, owned by the user),
//   - an Immich account whose external library is their own Photos folder,
//     bound read-only under {{APP_DIR}}/users/<user> on the host (the Immich
//     container mounts that parent with rslave, so a new user needs no restart),
//   - a Jellyfin account that sees only the libraries whose folders the DSM
//     account can read.
// The agent keeps one API key per app (created at setup or link time, never a
// password) in members.json under its private data directory.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const dsmHomes = "/var/services/homes"

// memberEmailDomain names Immich accounts after DSM users: <user>@nashubs.local.
const memberEmailDomain = "nashubs.local"

var memberMu sync.Mutex

type appLink struct {
	Port      int               `json:"port"`
	Key       string            `json:"key"`
	Users     map[string]string `json:"users,omitempty"`     // DSM user -> app user id
	Libraries map[string]string `json:"libraries,omitempty"` // DSM user -> Immich library id
}

type memberState struct {
	Immich   *appLink `json:"immich,omitempty"`
	Jellyfin *appLink `json:"jellyfin,omitempty"`
	Bound    []string `json:"bound,omitempty"` // DSM users whose Photos are bound for Immich
}

func (s *server) membersPath() string { return filepath.Join(s.cfg.DataDir, "members.json") }

func (s *server) loadMembers() memberState {
	var st memberState
	if data, err := os.ReadFile(s.membersPath()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func (s *server) saveMembers(st memberState) error {
	data, _ := json.MarshalIndent(st, "", "  ")
	return writePrivateFile(s.membersPath(), data)
}

func randomPassword() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---- DSM side ----

// dsmMembers lists the active local DSM accounts (guest and disabled accounts excluded).
func (s *server) dsmMembers() ([]dsmAccount, error) {
	out, err := s.host("synouser", "--enum", "local")
	if err != nil {
		return nil, fmt.Errorf("list DSM users: %w: %s", err, firstLine(out))
	}
	var list []dsmAccount
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		name := strings.TrimSpace(line)
		if name == "" || strings.EqualFold(name, "guest") || !dsmUserName.MatchString(name) {
			continue
		}
		a, err := s.lookupDSMUser(name)
		if err != nil {
			return nil, err
		}
		if a.Exists && !a.Disabled {
			list = append(list, a)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// ensurePhotos creates homes/<user>/Photos once, owned by the user. A user
// without a DSM home (User Home disabled) is skipped.
func (s *server) ensurePhotos(name string) (string, bool) {
	home := dsmHomes + "/" + name
	if _, err := s.host("test", "-d", home); err != nil {
		return "", false
	}
	photos := home + "/Photos"
	if _, err := s.host("test", "-d", photos); err != nil {
		if _, err := s.host("mkdir", "-p", photos); err != nil {
			return "", false
		}
		_, _ = s.host("chown", name+":users", photos)
	}
	return photos, true
}

// appShareName is the DSM shared folder that holds what an app manages itself:
// "immich" -> "Immich".
func appShareName(appID string) string {
	r := []rune(appID)
	if len(r) == 0 {
		return ""
	}
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

var appShareVolume = regexp.MustCompile(`^/volume[0-9]+`)

// ensureAppShare creates the app's own DSM shared folder on the volume of the
// apps directory and returns its path. Administrators get read/write; with
// membersRead every DSM user (group users) can read it too, e.g. Jellyfin's media.
// DSM gives the strongest of a user's grants, so admins keep read/write.
func (s *server) ensureAppShare(appID string, membersRead bool) (string, error) {
	vol := appShareVolume.FindString(s.cfg.AppsDir)
	name := appShareName(appID)
	if vol == "" || !validAppID(appID) {
		return "", fmt.Errorf("no volume for the app share")
	}
	path := vol + "/" + name
	if _, err := s.host("synoshare", "--get", name); err != nil {
		if out, err := s.host("synoshare", "--add", name, "NasHubs "+name, path, "", "", "", "1", "0"); err != nil {
			return "", fmt.Errorf("create shared folder %s: %w: %s", name, err, firstLine(out))
		}
		// RW for administrators. Never an NA rule on @users: it would also deny admins.
		if out, err := s.host("synoshare", "--setuser", name, "RW", "+", "@administrators"); err != nil {
			return "", fmt.Errorf("share %s permissions: %w: %s", name, err, firstLine(out))
		}
	}
	if membersRead {
		if out, err := s.host("synoshare", "--setuser", name, "RO", "+", "@users"); err != nil {
			return "", fmt.Errorf("share %s read access: %w: %s", name, err, firstLine(out))
		}
	}
	return path, nil
}

// bindPhotos binds each user's Photos read-only at {{APP_DIR}}/users/<user> on the
// host and removes binds of users that are gone. Returns the users bound now.
func (s *server) bindPhotos(appID string, photos map[string]string, previous []string) []string {
	root := filepath.Join(s.cfg.AppsDir, appID, "users")
	var bound []string
	for name, src := range photos {
		target := root + "/" + name
		if _, err := s.host("mkdir", "-p", target); err != nil {
			continue
		}
		if _, err := s.host("mountpoint", "-q", target); err != nil {
			if out, err := s.host("mount", "--bind", src, target); err != nil {
				log.Printf("bind Photos of %s: %v: %s", name, err, firstLine(out))
				continue
			}
			_, _ = s.host("mount", "-o", "remount,bind,ro", target)
		}
		bound = append(bound, name)
	}
	for _, name := range previous {
		if _, ok := photos[name]; !ok && dsmUserName.MatchString(name) {
			_, _ = s.host("umount", root+"/"+name)
		}
	}
	sort.Strings(bound)
	return bound
}

var readablePath = regexp.MustCompile(`^/volume[0-9]+/[^'"\x60$\\\n]+$`)

// dsmCanRead reports whether a DSM account may read a folder in a shared folder,
// by DSM's own share permissions (what File Station and SMB enforce): a deny (NA)
// for the user or one of their groups wins, then read/write or read-only allows.
// When the share's permissions cannot be read it falls back to trying as the account.
func (s *server) dsmCanRead(name, path string) bool {
	if !dsmUserName.MatchString(name) || !readablePath.MatchString(path) || strings.Contains(path, "..") {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 3)
	if len(parts) >= 2 && parts[1] != "" {
		if lists, ok := s.sharePermissions(parts[1]); ok {
			who := map[string]bool{strings.ToLower(name): true}
			if out, err := s.host("id", "-Gn", name); err == nil {
				for _, g := range strings.Fields(string(out)) {
					who["@"+strings.ToLower(g)] = true
				}
			}
			has := func(list []string) bool {
				for _, x := range list {
					if who[strings.ToLower(x)] {
						return true
					}
				}
				return false
			}
			if has(lists["NA"]) {
				return false
			}
			return has(lists["RW"]) || has(lists["RO"])
		}
	}
	_, err := s.host("su", "-s", "/bin/sh", name, "-c", "test -r '"+path+"' && test -x '"+path+"'")
	return err == nil
}

var shareListLine = regexp.MustCompile(`(?i)^\s*(RW|RO|NA|Deny) list[ .:]*\[(.*)\]\s*$`)

// sharePermissions reads the RW/RO/NA lists of a DSM shared folder (synoshare --get).
func (s *server) sharePermissions(share string) (map[string][]string, bool) {
	if !dsmUserName.MatchString(share) {
		return nil, false
	}
	out, err := s.host("synoshare", "--get", share)
	if err != nil {
		return nil, false
	}
	lists := map[string][]string{}
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		m := shareListLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		found = true
		kind := strings.ToUpper(m[1])
		if kind == "DENY" {
			kind = "NA" // DSM prints the no-access list as "Deny list"
		}
		for _, x := range strings.Split(m[2], ",") {
			if x = strings.TrimSpace(x); x != "" {
				lists[kind] = append(lists[kind], x)
			}
		}
	}
	return lists, found
}

// ---- sync ----

// syncMembers brings Immich and Jellyfin accounts in line with DSM users.
func (s *server) syncMembers() {
	memberMu.Lock()
	defer memberMu.Unlock()
	st := s.loadMembers()
	if st.Immich == nil && st.Jellyfin == nil {
		return
	}
	users, err := s.dsmMembers()
	if err != nil {
		log.Printf("member sync: %v", err)
		return
	}
	if st.Immich != nil {
		photos := map[string]string{}
		for _, u := range users {
			if p, ok := s.ensurePhotos(u.Name); ok {
				photos[u.Name] = p
			}
		}
		st.Bound = s.bindPhotos("immich", photos, st.Bound)
		if err := s.syncImmich(st.Immich, st.Bound); err != nil {
			log.Printf("member sync, Immich: %v", err)
		}
	}
	if st.Jellyfin != nil {
		if err := s.syncJellyfin(st.Jellyfin, users); err != nil {
			log.Printf("member sync, Jellyfin: %v", err)
		}
	}
	if err := s.saveMembers(st); err != nil {
		log.Printf("member sync: save: %v", err)
	}
}

func (s *server) runMemberSync(every time.Duration) {
	time.Sleep(30 * time.Second) // after a reboot: re-create the Photos binds
	for {
		s.syncMembers()
		time.Sleep(every)
	}
}

// ---- Immich ----

func immichHeaders(key string) map[string]string { return map[string]string{"x-api-key": key} }

type immichUser struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	StorageLabel string `json:"storageLabel"`
}

func (s *server) syncImmich(link *appLink, bound []string) error {
	base := appBaseURL(link.Port) + "/api"
	h := immichHeaders(link.Key)
	var existing []immichUser
	if err := s.callJSON("GET", base+"/admin/users", h, nil, &existing, "IMMICH_USERS_FAILED"); err != nil {
		return err
	}
	byEmail := map[string]string{}
	for _, u := range existing {
		byEmail[strings.ToLower(u.Email)] = u.ID
	}
	if link.Users == nil {
		link.Users = map[string]string{}
	}
	if link.Libraries == nil {
		link.Libraries = map[string]string{}
	}
	for _, name := range bound {
		id := link.Users[name]
		if id == "" {
			id = byEmail[strings.ToLower(name+"@"+memberEmailDomain)]
		}
		if id == "" {
			var created immichUser
			if err := s.callJSON("POST", base+"/admin/users", h, map[string]any{
				"email": name + "@" + memberEmailDomain, "name": name, "password": randomPassword(),
				"storageLabel": name, "shouldChangePassword": false,
			}, &created, "IMMICH_USER_FAILED"); err != nil || created.ID == "" {
				log.Printf("Immich account for %s: %v", name, err)
				continue
			}
			id = created.ID
		}
		link.Users[name] = id
		if link.Libraries[name] == "" {
			var lib struct {
				ID string `json:"id"`
			}
			if err := s.callJSON("POST", base+"/libraries", h, map[string]any{
				"ownerId": id, "name": "Photos", "importPaths": []string{"/external/" + name},
			}, &lib, "IMMICH_LIBRARY_FAILED"); err != nil || lib.ID == "" {
				log.Printf("Immich library for %s: %v", name, err)
				continue
			}
			link.Libraries[name] = lib.ID
			// Immich rescans external libraries on its own schedule after this first scan.
			_ = s.callJSON("POST", base+"/libraries/"+url.PathEscape(lib.ID)+"/scan", h, map[string]any{}, nil, "SCAN_FAILED")
		}
	}
	return nil
}

// immichLink creates the agent's API key with the admin's login.
func (s *server) immichLink(port int, token string) (*appLink, error) {
	var key struct {
		Secret string `json:"secret"`
	}
	if err := s.callJSON("POST", appBaseURL(port)+"/api/api-keys", map[string]string{"Authorization": "Bearer " + token},
		map[string]any{"name": "NasHubs Agent", "permissions": []string{"all"}}, &key, "IMMICH_KEY_FAILED"); err != nil {
		return nil, err
	}
	if key.Secret == "" {
		return nil, setupError{Code: "IMMICH_KEY_FAILED"}
	}
	return &appLink{Port: port, Key: key.Secret}, nil
}

// ---- Jellyfin ----

func jellyfinHeaders(key string) map[string]string {
	return map[string]string{"Authorization": jellyfinClientAuth + `, Token="` + key + `"`}
}

func (s *server) syncJellyfin(link *appLink, users []dsmAccount) error {
	base := appBaseURL(link.Port)
	h := jellyfinHeaders(link.Key)
	var existing []struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	}
	if err := s.callJSON("GET", base+"/Users", h, nil, &existing, "JELLYFIN_USERS_FAILED"); err != nil {
		return err
	}
	byName := map[string]string{}
	for _, u := range existing {
		byName[strings.ToLower(u.Name)] = u.ID
	}
	var folders []struct {
		ItemID    string   `json:"ItemId"`
		Locations []string `json:"Locations"`
	}
	if err := s.callJSON("GET", base+"/Library/VirtualFolders", h, nil, &folders, "JELLYFIN_LIBRARIES_FAILED"); err != nil {
		return err
	}
	if link.Users == nil {
		link.Users = map[string]string{}
	}
	for _, u := range users {
		id := link.Users[u.Name]
		if id == "" {
			id = byName[strings.ToLower(u.Name)]
		}
		if id == "" {
			var created struct {
				ID string `json:"Id"`
			}
			if err := s.callJSON("POST", base+"/Users/New", h, map[string]any{"Name": u.Name, "Password": randomPassword()}, &created, "JELLYFIN_USER_FAILED"); err != nil || created.ID == "" {
				log.Printf("Jellyfin account for %s: %v", u.Name, err)
				continue
			}
			id = created.ID
		}
		link.Users[u.Name] = id
		var user struct {
			Policy map[string]any `json:"Policy"`
		}
		if err := s.callJSON("GET", base+"/Users/"+url.PathEscape(id), h, nil, &user, "JELLYFIN_USER_FAILED"); err != nil || user.Policy == nil {
			continue
		}
		if admin, _ := user.Policy["IsAdministrator"].(bool); admin {
			continue // Jellyfin's own administrators keep every library
		}
		enabled := []string{}
		for _, f := range folders {
			ok := len(f.Locations) > 0
			for _, p := range f.Locations {
				if !s.dsmCanRead(u.Name, p) {
					ok = false
					break
				}
			}
			if ok && f.ItemID != "" {
				enabled = append(enabled, f.ItemID)
			}
		}
		sort.Strings(enabled)
		if all, _ := user.Policy["EnableAllFolders"].(bool); !all && sameStrings(user.Policy["EnabledFolders"], enabled) {
			continue
		}
		user.Policy["EnableAllFolders"] = false
		user.Policy["EnabledFolders"] = enabled
		_ = s.callJSON("POST", base+"/Users/"+url.PathEscape(id)+"/Policy", h, user.Policy, nil, "JELLYFIN_POLICY_FAILED")
	}
	return nil
}

func sameStrings(v any, want []string) bool {
	list, _ := v.([]any)
	got := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			got = append(got, s)
		}
	}
	sort.Strings(got)
	return strings.Join(got, ",") == strings.Join(want, ",")
}

// jellyfinLink creates the agent's API key with the admin's login.
func (s *server) jellyfinLink(port int, token string) (*appLink, error) {
	base := appBaseURL(port)
	h := map[string]string{"Authorization": jellyfinClientAuth + `, Token="` + token + `"`}
	if err := s.callJSON("POST", base+"/Auth/Keys?app="+url.QueryEscape("NasHubs Agent"), h, nil, nil, "JELLYFIN_KEY_FAILED"); err != nil {
		return nil, err
	}
	var keys struct {
		Items []struct {
			AccessToken string `json:"AccessToken"`
			AppName     string `json:"AppName"`
		} `json:"Items"`
	}
	if err := s.callJSON("GET", base+"/Auth/Keys", h, nil, &keys, "JELLYFIN_KEY_FAILED"); err != nil {
		return nil, err
	}
	for i := len(keys.Items) - 1; i >= 0; i-- {
		if keys.Items[i].AppName == "NasHubs Agent" && keys.Items[i].AccessToken != "" {
			return &appLink{Port: port, Key: keys.Items[i].AccessToken}, nil
		}
	}
	return nil, setupError{Code: "JELLYFIN_KEY_FAILED"}
}

// saveLink stores an app's key (keeping known users) and starts a sync.
func (s *server) saveLink(app string, link *appLink, requester string, appUserID string) {
	memberMu.Lock()
	st := s.loadMembers()
	old := st.Immich
	if app == "jellyfin" {
		old = st.Jellyfin
	}
	if old != nil && old.Port == link.Port {
		link.Users, link.Libraries = old.Users, old.Libraries
	}
	if requester != "" && appUserID != "" {
		if link.Users == nil {
			link.Users = map[string]string{}
		}
		link.Users[requester] = appUserID
	}
	if app == "jellyfin" {
		st.Jellyfin = link
	} else {
		st.Immich = link
	}
	err := s.saveMembers(st)
	memberMu.Unlock()
	if err != nil {
		log.Printf("save %s link: %v", app, err)
		return
	}
	go s.syncMembers()
}

func (s *server) requesterDSMUser(r *http.Request) string {
	if d := s.devices.lookup(authFrom(r).keyID); d != nil {
		return d.DSMUser
	}
	return ""
}

// ---- handlers ----

type linkReq struct {
	Port     int    `json:"port"`
	Username string `json:"username"` // Jellyfin user name or Immich email
	Password string `json:"password"`
}

// handleAppLink gives the agent its key for an app set up before this version.
func (s *server) handleAppLink(w http.ResponseWriter, r *http.Request) {
	app := r.PathValue("app")
	var req linkReq
	if err := decodeBody(r, &req); err != nil || !validPort(req.Port) || req.Username == "" || len(req.Username) > 254 || req.Password == "" || len(req.Password) > 256 || (app != "immich" && app != "jellyfin") {
		writeSetupError(w, setupError{Code: "INVALID_REQUEST"})
		return
	}
	var link *appLink
	var userID string
	var err error
	if app == "immich" {
		var login struct {
			AccessToken string `json:"accessToken"`
			UserID      string `json:"userId"`
		}
		if err = s.callJSON("POST", appBaseURL(req.Port)+"/api/auth/login", nil, map[string]any{"email": req.Username, "password": req.Password}, &login, "LOGIN_FAILED"); err == nil {
			link, err = s.immichLink(req.Port, login.AccessToken)
			userID = login.UserID
		}
	} else {
		var auth struct {
			AccessToken string `json:"AccessToken"`
		}
		h := map[string]string{"Authorization": jellyfinClientAuth}
		if err = s.callJSON("POST", appBaseURL(req.Port)+"/Users/AuthenticateByName", h, map[string]any{"Username": req.Username, "Pw": req.Password}, &auth, "LOGIN_FAILED"); err == nil {
			link, err = s.jellyfinLink(req.Port, auth.AccessToken)
		}
	}
	if err != nil {
		writeSetupError(w, err)
		return
	}
	s.saveLink(app, link, s.requesterDSMUser(r), userID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// memberLogin is the name a DSM user signs in to an app with.
func memberLogin(app, name string) string {
	if app == "immich" {
		return name + "@" + memberEmailDomain
	}
	return name
}

// handleMemberApps tells a device which shared apps give its DSM account a login.
func (s *server) handleMemberApps(w http.ResponseWriter, r *http.Request) {
	name := s.requesterDSMUser(r)
	st := s.loadMembers()
	out := map[string]any{"ok": true, "dsmUser": name}
	for app, link := range map[string]*appLink{"immich": st.Immich, "jellyfin": st.Jellyfin} {
		entry := map[string]any{"linked": link != nil}
		if link != nil && name != "" && link.Users[name] != "" {
			entry["login"] = memberLogin(app, name)
		}
		out[app] = entry
	}
	writeJSON(w, http.StatusOK, out)
}

// handleMemberPassword lets the owner of a DSM account choose the password of
// their own app account. The account comes from the device, never the request.
func (s *server) handleMemberPassword(w http.ResponseWriter, r *http.Request) {
	app := r.PathValue("app")
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &req); err != nil || (app != "immich" && app != "jellyfin") || len(req.Password) < 8 || len(req.Password) > 256 {
		writeSetupError(w, setupError{Code: "INVALID_REQUEST"})
		return
	}
	name := s.requesterDSMUser(r)
	if name == "" {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "NO_DSM_ACCOUNT"})
		return
	}
	st := s.loadMembers()
	link := st.Immich
	if app == "jellyfin" {
		link = st.Jellyfin
	}
	if link == nil {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "APP_NOT_LINKED"})
		return
	}
	id := link.Users[name]
	if id == "" {
		s.syncMembers()
		st = s.loadMembers()
		if app == "jellyfin" {
			link = st.Jellyfin
		} else {
			link = st.Immich
		}
		if link != nil {
			id = link.Users[name]
		}
	}
	if id == "" {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": "MEMBER_ACCOUNT_PENDING"})
		return
	}
	var err error
	if app == "immich" {
		err = s.callJSON("PUT", appBaseURL(link.Port)+"/api/admin/users/"+url.PathEscape(id), immichHeaders(link.Key), map[string]any{"password": req.Password}, nil, "PASSWORD_FAILED")
	} else {
		err = s.callJSON("POST", appBaseURL(link.Port)+"/Users/"+url.PathEscape(id)+"/Password", jellyfinHeaders(link.Key), map[string]any{"CurrentPw": "", "NewPw": req.Password}, nil, "PASSWORD_FAILED")
	}
	if err != nil {
		writeSetupError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "login": memberLogin(app, name)})
}
