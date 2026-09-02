package main

import "testing"

func TestMediaStatusFrom(t *testing.T) {
	st := deployState{InternalPort: 8096, PathPrefix: "/jellyfin"}

	missing := mediaStatusFrom(stMissing, st, nil)
	if missing.Installed || missing.Running || missing.Ready {
		t.Fatalf("missing deployment reported available: %+v", missing)
	}

	starting := mediaStatusFrom(stUp, st, nil)
	if !starting.Installed || !starting.Running || starting.Ready {
		t.Fatalf("starting deployment state is wrong: %+v", starting)
	}

	ready := mediaStatusFrom(stUp, st, &jellyfinPublicInfo{
		ServerName: "My NAS", Version: "10.10.7", StartupWizardCompleted: true,
	})
	if !ready.Ready || !ready.Configured || ready.ServerName != "My NAS" || ready.Version != "10.10.7" {
		t.Fatalf("ready deployment state is wrong: %+v", ready)
	}
}

func TestMediaStatusSetupRequired(t *testing.T) {
	status := mediaStatusFrom(stUp, deployState{InternalPort: 8096}, &jellyfinPublicInfo{
		ServerName: "NasHubs", StartupWizardCompleted: false,
	})
	if !status.Ready || status.Configured {
		t.Fatalf("setup-required state is wrong: %+v", status)
	}
}
