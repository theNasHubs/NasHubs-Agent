package main

import "testing"

// state_test pins the pure classification logic with real docker-compose v1
// (python, DSM 7.0) and v2 (Go, Container Manager) stdout shapes — no daemon.
// The header/separator strings are captured as constants so a future compose
// format change is a one-line fixture update.

const (
	// v2 (Go) table output for a running container.
	v2Running = "NAME                IMAGE               COMMAND             SERVICE      CREATED          STATUS                  PORTS\n" +
		"qbt-qbittorrent-1   lscr.io/linuxser..   \"/init\"             qbittorrent  24 minutes ago   Up 24 minutes           0.0.0.0:8080->8080/tcp\n"

	// v2 table output for a stopped container (only visible via `ps -a`).
	v2Stopped = "NAME                IMAGE               COMMAND             SERVICE      CREATED         STATUS\n" +
		"qbt-qbittorrent-1   lscr.io/linuxser..   \"/init\"             qbittorrent  5 minutes ago   Exited (0) 5 minutes ago\n"

	// v1 (python) header + dashed separator, NO data row (empty project).
	v1HeaderOnly = "       Name                      Command                  State               Ports\n" +
		"------------------------------------------------------------------------------------------------\n"

	// v1 header + separator + a running container data row.
	v1Running = "       Name                      Command                  State               Ports\n" +
		"------------------------------------------------------------------------------------------------\n" +
		"qbt_qbittorrent_1   /init                       Up                  0.0.0.0:8080->8080/tcp\n"
)

func TestClassifyState(t *testing.T) {
	cases := []struct {
		name    string
		running string
		all     string
		want    string
	}{
		{"v2 running", v2Running, v2Running, stUp},
		{"v2 stopped (ps empty, -a has Exited)", "", v2Stopped, stDown},
		{"both empty", "", "", stMissing},
		{"v1 'no containers' marker", "no containers", "no containers", stMissing},
		{"v1 'No containers found'", "No containers found", "No containers found", stMissing},
		{"v1 header-only (both)", v1HeaderOnly, v1HeaderOnly, stMissing},
		{"v1 header-only in -a", "", v1HeaderOnly, stMissing},
		{"v1 running", v1Running, v1Running, stUp},
		{"mixed running+stopped siblings (ps shows the Up row)", v2Running, v2Running + v2Stopped, stUp},
		{"v2 running column alone (Up line)", " Up 5 minutes \n", " Up 5 minutes \n", stUp},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyState(c.running, c.all)
			if got != c.want {
				t.Fatalf("classifyState want %q got %q\nrunning=%q\nall=%q", c.want, got, c.running, c.all)
			}
		})
	}
}

func TestHasData(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"empty", "", false},
		{"whitespace only", "   \n  \n", false},
		{"v2 running table", v2Running, true},
		{"v2 stopped table", v2Stopped, true},
		{"v1 header only (no data)", v1HeaderOnly, false},
		{"v1 running", v1Running, true},
		{"v2 header line only (CREATED+STATUS columns)", "NAME   IMAGE   COMMAND   SERVICE   CREATED   STATUS   PORTS", false},
		{"header with CONTAINER ID (hex-looking word)", "CONTAINER ID   IMAGE   COMMAND   STATUS", false},
		{"no-container marker", "No containers found\n", false},
		{"hex-only data row (no status word)", "a1b2c3d4e5f6", true},
		{"single Up row", "Up 3 hours", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasData(c.out); got != c.want {
				t.Fatalf("hasData(%q) want %v got %v", c.out, c.want, got)
			}
		})
	}
}

func TestValidAppIDRejectsAgentOwnName(t *testing.T) {
	if validAppID("agent") {
		t.Fatal(`"agent" maps to the agent's own container and must be rejected`)
	}
	for _, id := range []string{"jellyfin", "cloudflared-quick", "hello-world", "Agent2"} {
		if !validAppID(id) {
			t.Errorf("expected %q to be accepted", id)
		}
	}
	for _, id := range []string{"", "../x", "a b", "a/b"} {
		if validAppID(id) {
			t.Errorf("expected %q to be rejected", id)
		}
	}
}
