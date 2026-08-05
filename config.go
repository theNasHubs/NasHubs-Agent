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
		Port:          envOr("NASHUBS_PORT", "8443"),
		DataDir:       envOr("NASHUBS_DATA_DIR", "/data"),
		NginxConfDir:  envOr("NASHUBS_NGINX_CONF_DIR", "/etc/nginx/conf.d"),
		PairingSecret: os.Getenv("NASHUBS_PAIRING_SECRET"),
		Version:       envOr("NASHUBS_VERSION", version),
		AgentImage:    envOr("NASHUBS_AGENT_IMAGE", "ghcr.io/thenashubs/nashubs-agent:latest"),
	}
	// The `docker compose` CLI reads the compose file from ITS OWN filesystem
	// (the CLI parses the YAML client-side), so the "-f" path must be the path
	// the CLI process sees — which is the same mount the agent wrote to. Default
	// HOST_DATA_DIR to DATA_DIR (override only for unusual split-mount setups).
	c.HostDataDir = envOr("NASHUBS_HOST_DATA_DIR", c.DataDir)
	c.TrustedPublicKeys = map[string]bool{}
	for _, k := range strings.Split(os.Getenv("NASHUBS_TRUSTED_PUBKEY"), ",") {
		if k = strings.TrimSpace(k); k != "" {
			c.TrustedPublicKeys[k] = true
		}
	}
	return c
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
