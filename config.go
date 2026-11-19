package main

import (
	"os"
	"regexp"
	"strings"
)

// version is set at build time via: -ldflags "-X main.version=..."
// Falls back to "dev" if not set (go run / untagged build).
var version = "dev"

// Config holds all runtime configuration sourced from environment variables.
//
// Bootstrap (app → SYNO.Core.TaskScheduler) runs the agent container with:
//
//	NASHUBS_TRUSTED_PUBKEY  = base64 Ed25519 public key of the pairing iPhone
//	NASHUBS_PAIRING_SECRET  = one-time secret confirmed via POST /pair
//	NASHUBS_DATA_DIR        = path inside this container where compose files are written
//	                          (mounted from the NAS host share)
//	NASHUBS_HOST_DATA_DIR   = the SAME directory as seen by the host Docker daemon,
//	                          needed because `docker compose -f <path>` is resolved on the host.
type Config struct {
	AutoProxy         bool
	Port              string
	DataDir           string // container view (writable mount)
	HostDataDir       string // host view, for `docker compose -f`
	NginxConfDir      string // DSM nginx conf.d path (for reverse proxy rules)
	TrustedPublicKeys map[string]bool
	PairingSecret     string
	Version           string
	AgentImage        string // image pulled by the typed self-update endpoint
	// AppsDir is the host directory that holds one sub-directory per mini-app
	// ({{APP_DIR}} = AppsDir/<id>), normally the NAS "docker" shared folder.
	// Empty when it cannot be derived; {{APP_DIR}} deploys are then refused.
	AppsDir string
	// LanIP overrides the NAS LAN address reported to clients (the agent runs
	// in a bridge network and cannot see the host interfaces itself).
	LanIP string
}

func loadConfig() Config {
	c := Config{
		AutoProxy:     envOr("AUTO_PROXY", "true") == "true",
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
	c.AppsDir = deriveAppsDir(getenv("APPS_DIR"), c.HostDataDir)
	c.LanIP = getenv("LAN_IP")
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

var (
	appsDirPattern      = regexp.MustCompile(`^/volume[1-9][0-9]*/docker$`)
	agentDataDirPattern = regexp.MustCompile(`^(/volume[1-9][0-9]*/docker)/nashubs-agent/data$`)
)

// deriveAppsDir returns the per-app root. The DSM installer keeps the agent's
// own files in /volumeN/docker/nashubs-agent/data, so apps live next to it in
// /volumeN/docker/<id>. Legacy installers used /volumeN/docker itself as the
// data directory; apps then share that root. Anything else needs an explicit
// NASHUBS_APPS_DIR of the form /volumeN/docker.
func deriveAppsDir(explicit, hostDataDir string) string {
	if explicit != "" {
		if appsDirPattern.MatchString(explicit) {
			return explicit
		}
		return ""
	}
	clean := strings.TrimRight(hostDataDir, "/")
	if m := agentDataDirPattern.FindStringSubmatch(clean); m != nil {
		return m[1]
	}
	if appsDirPattern.MatchString(clean) {
		return clean
	}
	return ""
}
