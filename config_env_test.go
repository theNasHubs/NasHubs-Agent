package main

import "testing"

func clearAgentEnv(t *testing.T) {
	for _, p := range []string{"NASHUBS_", "NASDECK_"} {
		for _, n := range []string{"PORT", "DATA_DIR", "HOST_DATA_DIR", "NGINX_CONF_DIR", "PAIRING_SECRET", "VERSION", "AGENT_IMAGE", "TRUSTED_PUBKEY"} {
			t.Setenv(p+n, "")
		}
	}
}

// A container installed by the Nasdeck-era app only has NASDECK_* variables.
func TestLoadConfigLegacyNasdeckEnv(t *testing.T) {
	clearAgentEnv(t)
	t.Setenv("NASDECK_TRUSTED_PUBKEY", "oldkey1,oldkey2")
	t.Setenv("NASDECK_PAIRING_SECRET", "s")
	t.Setenv("NASDECK_DATA_DIR", "/volume1/docker")
	t.Setenv("NASDECK_HOST_DATA_DIR", "/volume1/docker")
	c := loadConfig()
	if !c.TrustedPublicKeys["oldkey1"] || !c.TrustedPublicKeys["oldkey2"] || len(c.TrustedPublicKeys) != 2 {
		t.Fatalf("trusted keys = %v", c.TrustedPublicKeys)
	}
	if c.PairingSecret != "s" || c.DataDir != "/volume1/docker" || c.HostDataDir != "/volume1/docker" {
		t.Fatalf("config = %+v", c)
	}
}

func TestLoadConfigNasHubsWinsAndKeysMerge(t *testing.T) {
	clearAgentEnv(t)
	t.Setenv("NASHUBS_TRUSTED_PUBKEY", "newkey")
	t.Setenv("NASDECK_TRUSTED_PUBKEY", "oldkey")
	t.Setenv("NASHUBS_DATA_DIR", "/new")
	t.Setenv("NASDECK_DATA_DIR", "/old")
	t.Setenv("NASHUBS_PAIRING_SECRET", "new")
	t.Setenv("NASDECK_PAIRING_SECRET", "old")
	c := loadConfig()
	if !c.TrustedPublicKeys["newkey"] || !c.TrustedPublicKeys["oldkey"] {
		t.Fatalf("trusted keys = %v", c.TrustedPublicKeys)
	}
	if c.DataDir != "/new" || c.PairingSecret != "new" || c.HostDataDir != "/new" {
		t.Fatalf("config = %+v", c)
	}
	if c.Port != "8443" {
		t.Fatalf("default port = %q", c.Port)
	}
}
