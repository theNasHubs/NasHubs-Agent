package main

import (
	"os"
	"strings"
)

// version is set at build time via: -ldflags "-X main.version=..."
// Falls back to "dev" if not set (go run / untagged build).
var version = "dev"

// Config holds all runtime configuration sourced from environment variables.
//
// Bootstrap (app → SYNO.Core.TaskScheduler) runs the agent container with:
//   NASHUBS_TRUSTED_PUBKEY  = base64 Ed25519 public key of the pairing iPhone
//   NASHUBS_PAIRING_SECRET  = one-time secret confirmed via POST /pair
//   NASHUBS_DATA_DIR        = path inside this container where compose files are written
//                             (mounted from the NAS host share)
//   NASHUBS_HOST_DATA_DIR   = the SAME directory as seen by the host Docker daemon,
//                             needed because `docker compose -f <path>` is resolved on the host.
type Config struct {
	Port              string
	DataDir           string // container view (writable mount)
	HostDataDir       string // host view, for `docker compose -f`
	NginxConfDir      string // DSM nginx conf.d path (for reverse proxy rules)
	TrustedPublicKeys map[string]bool
	PairingSecret     string
	Version           string
	AgentImage        string // image pulled by the typed self-update endpoint
}

func loadConfig() Config {
	c := Config{
		Port:          envOr("PORT", "8443"),
		DataDir:       envOr("DATA_DIR", "/data"),
		NginxConfDir:  envOr("NGINX_CONF_DIR", "/etc/nginx/conf.d"),
		PairingSecret: getenv("PAIRING_SECRET"),
		Version:       envOr("VERSION", version),
		AgentImage:    envOr("AGENT_IMAGE", "ghcr.io/thenashubs/nashubs-agent:latest"),
	}
	// The `docker compose` CLI reads the compose file from ITS OWN filesystem
	// (the CLI parses the YAML client-side), so the "-f" path must be the path
	// the CLI process sees — which is the same mount the agent wrote to. Default
	// HOST_DATA_DIR to DATA_DIR (override only for unusual split-mount setups).
	c.HostDataDir = envOr("HOST_DATA_DIR", c.DataDir)
	// NASHUBS_NGINX_CONF_DIR=none turns the DSM reverse-proxy integration off
	// entirely: no conf files are written and no privileged helper container is
	// started to test/reload nginx. Use it when the agent does not run on DSM.
	if nginxDisabledValue(c.NginxConfDir) {
		c.NginxConfDir = ""
	}
	c.TrustedPublicKeys = map[string]bool{}
	// Keys from both names are trusted, so a container upgraded in place from
	// the Nasdeck agent keeps the devices that installed it.
	keys := os.Getenv("NASHUBS_TRUSTED_PUBKEY") + "," + os.Getenv("NASDECK_TRUSTED_PUBKEY")
	for _, k := range strings.Split(keys, ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.TrustedPublicKeys[k] = true
		}
	}
	return c
}

// getenv reads NASHUBS_<name>, falling back to the legacy NASDECK_<name> that
// containers installed by the Nasdeck-era app (still in production) carry.
func getenv(name string) string {
	if v := os.Getenv("NASHUBS_" + name); v != "" {
		return v
	}
	return os.Getenv("NASDECK_" + name)
}

func envOr(name, def string) string {
	if v := getenv(name); v != "" {
		return v
	}
	return def
}
