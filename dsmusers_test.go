package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeHost answers the allow-listed host commands for a small set of DSM accounts.
func fakeHost(accounts map[string]string, calls *[][]string) func(...string) ([]byte, error) {
	return func(args ...string) ([]byte, error) {
		*calls = append(*calls, args)
		i := 0
		for i < len(args) && args[i] != "--" {
			i++
		}
		cmd := args[i+1:]
		switch {
		case len(cmd) == 2 && cmd[0] == "id":
			if line, ok := accounts[cmd[1]]; ok {
				return []byte(strings.Split(line, "|")[0] + "\n"), nil
			}
			return []byte("id: '" + cmd[1] + "': no such user\n"), errExit1
		case len(cmd) > 0 && cmd[0] == "env":
			// authenticate.cgi: "sid-cgi" is a session opened from 203.0.113.7.
			if cmd[len(cmd)-1] == dsmAuthCGI && indexOf(cmd, "HTTP_COOKIE=id=sid-cgi") > 0 && indexOf(cmd, "REMOTE_ADDR=203.0.113.7") > 0 {
				return []byte("thanhvien\n"), nil
			}
			return []byte("\n"), nil
		case len(cmd) == 3 && cmd[0] == "synouser" && cmd[1] == "--get":
			return []byte("User uid    : [1027]\nExpired     : [" + strings.Split(accounts[cmd[2]], "|")[1] + "]\n"), nil
		}
		return nil, errExit1
	}
}

type exitErr struct{}

func (exitErr) Error() string { return "exit status 1" }

var errExit1 = exitErr{}

var testAccounts = map[string]string{
	"duconmang": "uid=1026(duconmang) gid=100(users) groups=100(users),101(administrators)|false",
	"thanhvien": "uid=1027(thanhvien) gid=100(users) groups=100(users)|false",
	"admin":     "uid=1024(admin) gid=100(users) groups=100(users),101(administrators)|true",
}

func TestLookupDSMUser(t *testing.T) {
	var calls [][]string
	s := &server{runCmd: fakeHost(testAccounts, &calls)}
	for name, want := range map[string]dsmAccount{
		"duconmang": {Name: "duconmang", Exists: true, Admin: true},
		"thanhvien": {Name: "thanhvien", Exists: true},
		"admin":     {Name: "admin", Exists: true, Admin: true, Disabled: true},
		"ghost":     {Name: "ghost"},
	} {
		got, err := s.lookupDSMUser(name)
		if err != nil || got != want {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
	}
	if _, err := s.lookupDSMUser("-rf"); err == nil {
		t.Fatal("option-like name accepted")
	}
	for _, c := range calls {
		if c[0] != "run" || c[len(c)-2] == "" || !hostCommands[c[indexOf(c, "--")+1]] {
			t.Fatal(c)
		}
	}
	if _, err := s.host("sh", "-c", "id"); err == nil {
		t.Fatal("non allow-listed host command ran")
	}
}

func indexOf(xs []string, v string) int {
	for i, x := range xs {
		if x == v {
			return i
		}
	}
	return -1
}

// fakeDSM answers SYNO.Core.NormalUser for known sessions.
func fakeDSM(t *testing.T, sessions map[string]string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := sessions[r.URL.Query().Get("_sid")]
		if r.URL.Query().Get("api") != "SYNO.Core.NormalUser" || !ok {
			w.Write([]byte(`{"success":false,"error":{"code":119}}`))
			return
		}
		w.Write([]byte(`{"success":true,"data":{"username":"` + user + `","fullname":"x"}}`))
	}))
	t.Cleanup(ts.Close)
	oldURL, oldClient := dsmBaseURL, dsmClient
	dsmBaseURL = func() string { return ts.URL }
	dsmClient = ts.Client()
	t.Cleanup(func() { dsmBaseURL, dsmClient = oldURL, oldClient })
}

func TestEnrollDSMGivesTheAccountRole(t *testing.T) {
	fakeDSM(t, map[string]string{"sid-member": "thanhvien", "sid-admin": "duconmang", "sid-disabled": "admin"})
	s, ts := enrollmentServer(t, t.TempDir())
	var calls [][]string
	s.runCmd = fakeHost(testAccounts, &calls)

	member := freshKey(t)
	assertStatus(t, enrollRequest(t, ts, member, "/devices/enroll-dsm", map[string]string{"sid": "sid-member", "label": "Pixel"}), 200)
	if d := s.devices.lookup(keyID(member)); d == nil || d.Role != RoleMember || d.DSMUser != "thanhvien" {
		t.Fatalf("%+v", d)
	}
	admin := freshKey(t)
	assertStatus(t, enrollRequest(t, ts, admin, "/devices/enroll-dsm", map[string]string{"sid": "sid-admin"}), 200)
	if d := s.devices.lookup(keyID(admin)); d == nil || d.Role != RoleAdmin || d.DSMUser != "duconmang" {
		t.Fatalf("%+v", d)
	}
	assertStatus(t, enrollRequest(t, ts, freshKey(t), "/devices/enroll-dsm", map[string]string{"sid": "sid-disabled"}), 403)
	assertStatus(t, enrollRequest(t, ts, freshKey(t), "/devices/enroll-dsm", map[string]string{"sid": "forged"}), 403)
	assertStatus(t, enrollRequest(t, ts, freshKey(t), "/devices/enroll-dsm", map[string]string{}), 403)
	// A member reaches app status but nothing that manages the Agent.
	assertStatus(t, enrollRequest(t, ts, member, "/state", nil), 200)
	assertStatus(t, enrollRequest(t, ts, member, "/devices", nil), 403)
}

func TestSyncDSMRolesFollowsAccounts(t *testing.T) {
	dir := t.TempDir()
	accounts := map[string]string{
		"duconmang": testAccounts["duconmang"],
		"thanhvien": "uid=1027(thanhvien) gid=100(users) groups=100(users),101(administrators)|false", // promoted
		"ban":       "uid=1030(ban) gid=100(users) groups=100(users)|true",                            // disabled
	}
	var calls [][]string
	s := &server{devices: newDeviceStore(dir), runCmd: fakeHost(accounts, &calls)}
	s.devices.enrollAs("k1", "admin", RoleAdmin, "duconmang")
	s.devices.enrollAs("k2", "member", RoleMember, "thanhvien")
	s.devices.enrollAs("k3", "disabled", RoleMember, "ban")
	s.devices.enrollAs("k4", "deleted", RoleMember, "gone")
	s.devices.enroll("k5", "legacy", RoleMember)
	s.syncDSMRoles()
	if d := s.devices.lookup("k2"); d.Role != RoleAdmin {
		t.Fatalf("promotion not followed: %+v", d)
	}
	if !s.devices.lookup("k3").revoked() || !s.devices.lookup("k4").revoked() {
		t.Fatal("disabled or deleted account kept its device")
	}
	if s.devices.lookup("k1").revoked() || s.devices.lookup("k5").revoked() {
		t.Fatal("unrelated device changed")
	}
}

func TestSessionUserName(t *testing.T) {
	for _, c := range []struct {
		data map[string]any
		want string
	}{
		{map[string]any{"username": "an"}, "an"},
		{map[string]any{"session": map[string]any{"user": "binh"}}, "binh"},
		{map[string]any{"username": "-x"}, ""},
		{map[string]any{}, ""},
	} {
		if got := sessionUserName(c.data); got != c.want {
			t.Fatalf("%v: %q", c.data, got)
		}
	}
	if idInGroup("uid=1(a) gid=100(users) groups=100(users),101(administrators)", "administrators") != true ||
		idInGroup("uid=1(a) gid=100(users) groups=100(users)", "administrators") != false {
		t.Fatal("idInGroup")
	}
}

func TestDSMSessionUserUsesHostCheckWithPhoneAddress(t *testing.T) {
	fakeDSM(t, map[string]string{"sid-http": "duconmang"})
	var calls [][]string
	s := &server{runCmd: fakeHost(testAccounts, &calls)}
	if name, err := s.dsmSessionUser("sid-cgi", "tok", "203.0.113.7"); err != nil || name != "thanhvien" {
		t.Fatalf("%q %v", name, err)
	}
	// DSM binds the session to its address: another address is refused by the host check.
	if _, err := s.dsmSessionUser("sid-cgi", "tok", "198.51.100.1"); err == nil || !strings.Contains(err.Error(), "code 119") {
		t.Fatalf("%v", err)
	}
	// Falls back to the WebAPI when DSM skips the address check.
	if name, err := s.dsmSessionUser("sid-http", "", "198.51.100.1"); err != nil || name != "duconmang" {
		t.Fatalf("%q %v", name, err)
	}
	if _, err := s.dsmSessionUser("a b;rm", "", "203.0.113.7"); err == nil {
		t.Fatal("malformed session accepted")
	}
}

func TestDSMClientAddrTrustsNginxOnlyFromLocal(t *testing.T) {
	r := httptest.NewRequest("POST", "/devices/enroll-dsm", nil)
	r.RemoteAddr = "172.17.0.1:40000"
	r.Header.Set("X-Real-IP", "203.0.113.7")
	if got := dsmClientAddr(r); got != "203.0.113.7" {
		t.Fatal(got)
	}
	r.RemoteAddr = "198.51.100.9:40000"
	if got := dsmClientAddr(r); got != "198.51.100.9" {
		t.Fatal(got)
	}
}
