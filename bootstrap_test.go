package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func bootstrapFixture() bootstrapRequest {
	return bootstrapRequest{KeyID: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Secret: "random-pairing-secret-12345678", Image: "ghcr.io/thenashubs/nashubs-agent:sha-" + strings.Repeat("a", 40), DataDir: "/volume2/docker/nashubs-agent/data", Volumes: []string{"/volume1", "/volume2"}}
}
func TestBootstrapRejectsUnsafeSpecificationsBeforeDocker(t *testing.T) {
	for _, change := range []func(*bootstrapRequest){
		func(r *bootstrapRequest) { r.Image = "ghcr.io/thenashubs/nashubs-agent:latest" },
		func(r *bootstrapRequest) { r.Image = "evil.example/agent:sha-" + strings.Repeat("a", 40) },
		func(r *bootstrapRequest) { r.DataDir = "/etc" },
		func(r *bootstrapRequest) { r.Volumes = []string{"/volume1/../etc"} },
		func(r *bootstrapRequest) { r.Volumes = []string{"/volume2", "/volume2"} },
		func(r *bootstrapRequest) { r.KeyID = "invalid" },
		func(r *bootstrapRequest) { r.Secret = "bad\nsecret" },
	} {
		r := bootstrapFixture()
		change(&r)
		called := false
		_, err := bootstrapAgent(r, func(...string) ([]byte, error) { called = true; return nil, nil }, func() {})
		if err == nil || called {
			t.Fatalf("unsafe request reached Docker: %+v", r)
		}
	}
}
func TestBootstrapCreatesAgentWithPersistentSamePathVolumesAndLiveOwnerEnrollment(t *testing.T) {
	r := bootstrapFixture()
	var calls [][]string
	out, err := bootstrapAgent(r, func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		switch args[0] {
		case "ps":
			return nil, nil
		case "run":
			return []byte("container-id"), nil
		case "exec":
			if args[3] == "bootstrap-identity" {
				return []byte(`{"certFingerprint":"public-certificate","hasOwner":false}`), nil
			}
			return []byte(`{"ok":true,"code":"one-use-code"}`), nil
		}
		return nil, errors.New("unexpected command")
	}, func() {})
	if err != nil || !out.OK || !out.Created || out.Invitation != "one-use-code" {
		t.Fatalf("result=%+v err=%v", out, err)
	}
	run := calls[1]
	for _, value := range []string{"/volume1:/volume1", "/volume2:/volume2", "NASHUBS_DATA_DIR=" + r.DataDir, "NASHUBS_HOST_DATA_DIR=" + r.DataDir, "NASHUBS_NGINX_CONF_DIR=none", "8443:8443"} {
		if !strings.Contains(strings.Join(run, " "), value) {
			t.Errorf("missing %s", value)
		}
	}
	if run[len(run)-1] != r.Image {
		t.Fatal("wrong image")
	}
	if !reflect.DeepEqual(calls[len(calls)-1], []string{"exec", "nashubs-agent", "nashubs-agent", "invite", "--role", "owner"}) {
		t.Fatal(calls)
	}
}
func TestBootstrapExistingAgentNeverChangesImageRestartsOrRewritesData(t *testing.T) {
	for _, enrolled := range []bool{true, false} {
		var calls [][]string
		out, err := bootstrapAgent(bootstrapFixture(), func(args ...string) ([]byte, error) {
			calls = append(calls, args)
			if args[0] == "ps" {
				return []byte("other-app\nnashubs-agent\n"), nil
			}
			if args[0] != "exec" {
				t.Fatal("existing Agent mutated", args)
			}
			if args[3] == "bootstrap-identity" {
				b, _ := json.Marshal(bootstrapIdentity{Certificate: "public-certificate", Enrolled: enrolled, HasOwner: true})
				return b, nil
			}
			if args[len(args)-1] != "admin" {
				t.Fatal("attempted to replace owner")
			}
			return []byte(`{"ok":true,"code":"admin-code"}`), nil
		}, func() {})
		if err != nil || out.Created {
			t.Fatalf("%+v %v", out, err)
		}
		if enrolled && len(calls) != 2 {
			t.Fatal("enrolled device requested a new invitation")
		}
	}
}
func TestBootstrapPreservesLegacyAndRevokedDevices(t *testing.T) {
	for _, legacy := range []bool{true, false} {
		_, err := bootstrapAgent(bootstrapFixture(), func(args ...string) ([]byte, error) {
			if args[0] == "ps" {
				if legacy {
					return []byte("nasdeck-agent"), nil
				}
				return []byte("nashubs-agent"), nil
			}
			if args[0] != "exec" || args[3] != "bootstrap-identity" {
				t.Fatal("unexpected mutation", args)
			}
			return []byte(`{"certFingerprint":"public-certificate","revoked":true}`), nil
		}, func() {})
		if err == nil {
			t.Fatal("expected rejection")
		}
	}
}
func TestBootstrapDoesNotDeleteAnythingAfterDaemonFailure(t *testing.T) {
	_, err := bootstrapAgent(bootstrapFixture(), func(args ...string) ([]byte, error) {
		if args[0] == "ps" {
			return nil, nil
		}
		if args[0] != "run" {
			t.Fatal(args)
		}
		return nil, errors.New("sensitive daemon output must not be returned")
	}, func() {})
	if err == nil || err.Error() != "CREATE_FAILED" {
		t.Fatal(err)
	}
}
