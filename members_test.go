package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// memberHost fakes the NAS host: three DSM users (admin disabled), homes for
// duconmang and thanhvien, thanhvien without a Photos folder yet, and a share
// "video" that only duconmang can read.
func memberHost(t *testing.T) (func(...string) ([]byte, error), func() []string) {
	var mu sync.Mutex
	var log []string
	dirs := map[string]bool{dsmHomes + "/duconmang": true, dsmHomes + "/duconmang/Photos": true, dsmHomes + "/thanhvien": true}
	mounted := map[string]bool{}
	base := fakeHost(testAccounts, new([][]string))
	return func(args ...string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			cmd := args[indexOf(args, "--")+3:]
			log = append(log, strings.Join(cmd, " "))
			switch cmd[0] {
			case "synouser":
				if cmd[1] == "--enum" {
					return []byte("4 User Listed:\nadmin\nduconmang\nguest\nthanhvien\n"), nil
				}
			case "test":
				if dirs[cmd[2]] {
					return nil, nil
				}
				return nil, errExit1
			case "mkdir":
				dirs[cmd[2]] = true
				return nil, nil
			case "chown":
				return nil, nil
			case "mountpoint":
				if mounted[cmd[2]] {
					return nil, nil
				}
				return nil, errExit1
			case "mount":
				if cmd[1] == "--bind" {
					mounted[cmd[3]] = true
				}
				return nil, nil
			case "umount":
				delete(mounted, cmd[1])
				return nil, nil
			case "su":
				if cmd[3] == "duconmang" && strings.Contains(cmd[5], "/volume1/video") {
					return nil, nil
				}
				return nil, errExit1
			}
			return base(args...)
		}, func() []string {
			mu.Lock()
			defer mu.Unlock()
			return append([]string(nil), log...)
		}
}

type fakeApps struct {
	mu       sync.Mutex
	immich   []map[string]any
	libs     map[string]string // ownerId -> importPath
	jfUsers  map[string]string // id -> name
	policies map[string][]string
	pw       map[string]string
}

func (f *fakeApps) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		p := r.Method + " " + r.URL.Path
		switch {
		case strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("x-api-key") != "ikey":
			w.WriteHeader(401)
		case p == "GET /api/admin/users":
			json.NewEncoder(w).Encode(f.immich)
		case p == "POST /api/admin/users":
			if body["storageLabel"] != body["name"] {
				t.Error("storage label", body)
			}
			u := map[string]any{"id": "im-" + body["name"].(string), "email": body["email"]}
			f.immich = append(f.immich, u)
			json.NewEncoder(w).Encode(u)
		case p == "POST /api/libraries":
			f.libs[body["ownerId"].(string)] = body["importPaths"].([]any)[0].(string)
			w.Write([]byte(`{"id":"lib-` + body["ownerId"].(string) + `"}`))
		case strings.HasPrefix(p, "PUT /api/admin/users/"):
			f.pw[strings.TrimPrefix(r.URL.Path, "/api/admin/users/")] = body["password"].(string)
			w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/"):
			w.WriteHeader(201)
		case !strings.Contains(r.Header.Get("Authorization"), `Token="jkey"`):
			w.WriteHeader(401)
		case p == "GET /Users":
			list := []map[string]any{{"Id": "jf-admin", "Name": "Boss"}}
			for id, n := range f.jfUsers {
				list = append(list, map[string]any{"Id": id, "Name": n})
			}
			json.NewEncoder(w).Encode(list)
		case p == "POST /Users/New":
			id := "jf-" + body["Name"].(string)
			f.jfUsers[id] = body["Name"].(string)
			w.Write([]byte(`{"Id":"` + id + `"}`))
		case p == "GET /Library/VirtualFolders":
			w.Write([]byte(`[{"ItemId":"lib-movies","Locations":["/volume1/video/Movies"]},{"ItemId":"lib-music","Locations":["/volume1/music"]}]`))
		case p == "GET /Users/jf-admin":
			w.Write([]byte(`{"Policy":{"IsAdministrator":true,"EnableAllFolders":true}}`))
		case strings.HasPrefix(p, "GET /Users/"):
			w.Write([]byte(`{"Policy":{"IsAdministrator":false,"EnableAllFolders":true,"AuthenticationProviderId":"x"}}`))
		case strings.HasSuffix(p, "/Policy"):
			if body["AuthenticationProviderId"] != "x" || body["EnableAllFolders"] != false {
				t.Error("policy lost fields", body)
			}
			var ids []string
			for _, x := range body["EnabledFolders"].([]any) {
				ids = append(ids, x.(string))
			}
			f.policies[strings.Split(r.URL.Path, "/")[2]] = ids
			w.WriteHeader(204)
		case strings.HasSuffix(p, "/Password"):
			f.pw[strings.Split(r.URL.Path, "/")[2]] = body["NewPw"].(string)
			w.WriteHeader(204)
		default:
			io.WriteString(w, "{}")
		}
	}
}

func TestMemberSyncCreatesAccountsPhotosAndLibraries(t *testing.T) {
	fakeDSM(t, map[string]string{"sid-member": "thanhvien"})
	s, ts := enrollmentServer(t, t.TempDir())
	host, calls := memberHost(t)
	s.runCmd = host
	s.cfg.AppsDir = "/volume1/docker"
	apps := &fakeApps{libs: map[string]string{}, jfUsers: map[string]string{}, policies: map[string][]string{}, pw: map[string]string{}}
	app := httptest.NewServer(apps.handler(t))
	t.Cleanup(app.Close)
	old := appBaseURL
	appBaseURL = func(int) string { return app.URL }
	t.Cleanup(func() { appBaseURL = old })

	if err := s.saveMembers(memberState{Immich: &appLink{Port: 2283, Key: "ikey"}, Jellyfin: &appLink{Port: 8096, Key: "jkey"}}); err != nil {
		t.Fatal(err)
	}
	s.syncMembers()

	got := strings.Join(calls(), "\n")
	for _, want := range []string{
		"mkdir -p " + dsmHomes + "/thanhvien/Photos",
		"chown thanhvien:users " + dsmHomes + "/thanhvien/Photos",
		"mount --bind " + dsmHomes + "/thanhvien/Photos /volume1/docker/immich/users/thanhvien",
		"mount -o remount,bind,ro /volume1/docker/immich/users/thanhvien",
		"mount --bind " + dsmHomes + "/duconmang/Photos /volume1/docker/immich/users/duconmang",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(got, "chown duconmang") || strings.Contains(got, "users/admin") {
		t.Fatalf("touched an existing folder or a disabled account:\n%s", got)
	}
	if apps.libs["im-thanhvien"] != "/external/thanhvien" || apps.libs["im-duconmang"] != "/external/duconmang" || len(apps.immich) != 2 {
		t.Fatal(apps.libs, apps.immich)
	}
	if strings.Join(apps.policies["jf-duconmang"], ",") != "lib-movies" || len(apps.policies["jf-thanhvien"]) != 0 || apps.policies["jf-admin"] != nil {
		t.Fatal(apps.policies)
	}
	if _, ok := apps.policies["jf-thanhvien"]; !ok {
		t.Fatal("thanhvien kept every library")
	}

	// A second run changes nothing: no new accounts, binds kept.
	before := len(apps.immich)
	s.syncMembers()
	if len(apps.immich) != before || strings.Count(strings.Join(calls(), "\n"), "mount --bind "+dsmHomes+"/thanhvien") != 1 {
		t.Fatal("second sync repeated work")
	}

	// The member sets the password of their own accounts, and only theirs.
	member := freshKey(t)
	assertStatus(t, enrollRequest(t, ts, member, "/devices/enroll-dsm", map[string]string{"sid": "sid-member"}), 200)
	resp := enrollRequest(t, ts, member, "/apps/immich/me/password", map[string]string{"password": "member-secret"})
	assertStatus(t, resp, 200)
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	if out["login"] != "thanhvien@"+memberEmailDomain || apps.pw["im-thanhvien"] != "member-secret" || apps.pw["im-duconmang"] != "" {
		t.Fatal(out, apps.pw)
	}
	assertStatus(t, enrollRequest(t, ts, member, "/apps/jellyfin/me/password", map[string]string{"password": "member-secret"}), 200)
	if apps.pw["jf-thanhvien"] != "member-secret" {
		t.Fatal(apps.pw)
	}
	assertStatus(t, enrollRequest(t, ts, member, "/apps/immich/me/password", map[string]string{"password": "short"}), 400)
	assertStatus(t, enrollRequest(t, ts, member, "/apps/immich/link", map[string]any{"port": 2283, "username": "a@b.c", "password": "x"}), 403)
	assertStatus(t, enrollRequest(t, ts, member, "/apps/members", nil), 200)
}

func TestDSMCanReadRejectsQuotes(t *testing.T) {
	var calls [][]string
	s := &server{runCmd: fakeHost(testAccounts, &calls)}
	if s.dsmCanRead("thanhvien", "/volume1/x'; rm -rf /'") || s.dsmCanRead("-x", "/volume1/video") || s.dsmCanRead("thanhvien", "/etc") {
		t.Fatal("unsafe path accepted")
	}
	if len(calls) != 0 {
		t.Fatal(calls)
	}
}

func TestEnsureAppShareMediaIsReadableByUsers(t *testing.T) {
	var log []string
	exists := false
	s := &server{runCmd: func(args ...string) ([]byte, error) {
		cmd := args[indexOf(args, "--")+3:]
		log = append(log, strings.Join(cmd, " "))
		if cmd[0] == "synoshare" && cmd[1] == "--get" && !exists {
			return nil, errExit1
		}
		if cmd[0] == "synoshare" && cmd[1] == "--add" {
			exists = true
		}
		return nil, nil
	}}
	s.cfg.AppsDir = "/volume1/docker"
	path, err := s.ensureAppShare("jellyfin", true)
	if err != nil || path != "/volume1/Jellyfin" {
		t.Fatal(path, err)
	}
	got := strings.Join(log, "\n")
	for _, want := range []string{"synoshare --setuser Jellyfin RW + @administrators", "synoshare --setuser Jellyfin RO + @users"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "NA") {
		t.Fatal("deny rule would also block administrators")
	}
	log = nil
	if _, err := s.ensureAppShare("immich", false); err != nil || strings.Contains(strings.Join(log, "\n"), "@users") {
		t.Fatal("admin-only share opened to users", log)
	}
}
