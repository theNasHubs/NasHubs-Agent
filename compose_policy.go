package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// composePolicy restricts what a compose file deployed by a non-owner device
// may ask of the host. Everything the agent runs goes through the host Docker
// daemon as root, so without it any admin device is effectively root on the
// NAS. The owner role is not restricted.
//
// The check is an allowlist over the parsed YAML: unknown top-level keys and
// host-reaching service options are rejected, and bind mounts may only point
// at the app's own data under the project directory or at user shares
// (/volumeN/<share>/...), never at the agent's own state.
type composePolicy struct {
	appID       string
	dataDir     string // DataDir as the agent sees it
	projectDir  string // this deploy's version directory as the agent sees it
	hostDataDir string // the same directory as the Docker daemon sees it
}

var (
	allowedTopLevel = map[string]bool{"version": true, "name": true, "services": true, "networks": true, "volumes": true}
	// Service options a non-owner may use. Anything else (privileged, pid, ipc,
	// cap_add, security_opt, volumes_from, extends, build, env_file, secrets,
	// use_api_socket, ... and options added by future compose versions) is
	// rejected. network_mode, devices and volumes are checked further below.
	allowedServiceKeys = map[string]bool{
		"image": true, "command": true, "entrypoint": true, "environment": true,
		"ports": true, "expose": true, "volumes": true, "restart": true,
		"depends_on": true, "networks": true, "network_mode": true, "labels": true,
		"healthcheck": true, "user": true, "working_dir": true, "hostname": true,
		"domainname": true, "dns": true, "dns_search": true, "extra_hosts": true,
		"devices": true, "logging": true, "ulimits": true, "mem_limit": true,
		"memswap_limit": true, "mem_reservation": true, "cpus": true,
		"cpu_shares": true, "cpuset": true, "shm_size": true, "stop_signal": true,
		"stop_grace_period": true, "tty": true, "stdin_open": true, "init": true,
		"tmpfs": true, "deploy": true, "platform": true, "pull_policy": true,
		"read_only": true, "group_add": true, "container_name": true, "gpus": true,
		"cap_drop": true, "pids_limit": true, "links": true, "profiles": true,
		"mac_address": true, "oom_score_adj": true, "annotations": true,
	}
	versionDirName = regexp.MustCompile(`^v[0-9a-f]{12}$`)
)

func (p composePolicy) check(compose []byte) error {
	var doc map[string]any
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return fmt.Errorf("compose is not valid YAML: %v", err)
	}
	for k, v := range doc {
		if strings.HasPrefix(k, "x-") {
			continue
		}
		if !allowedTopLevel[k] {
			return fmt.Errorf("top-level %q is not allowed", k)
		}
		if k == "volumes" || k == "networks" {
			if err := checkTopLevelResources(k, v); err != nil {
				return err
			}
		}
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return fmt.Errorf("compose must define services")
	}
	for name, raw := range services {
		svc, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("service %q: invalid definition", name)
		}
		if err := p.checkService(svc); err != nil {
			return fmt.Errorf("service %q: %v", name, err)
		}
	}
	return nil
}

func (p composePolicy) checkService(svc map[string]any) error {
	for k := range svc {
		if !allowedServiceKeys[k] && !strings.HasPrefix(k, "x-") {
			return fmt.Errorf("%s is not allowed", k)
		}
	}
	if v, ok := svc["network_mode"]; ok {
		s, isString := v.(string)
		if !isString || strings.Contains(s, "$") || strings.HasPrefix(s, "host") || strings.HasPrefix(s, "container:") {
			return fmt.Errorf("network_mode %v is not allowed", v)
		}
	}
	if v, ok := svc["devices"]; ok {
		for _, d := range asList(v) {
			src := ""
			switch d := d.(type) {
			case string:
				src, _, _ = strings.Cut(d, ":")
			case map[string]any:
				src, _ = d["source"].(string)
			}
			if !allowedDevice(src) {
				return fmt.Errorf("device %v is not allowed", d)
			}
		}
	}
	if v, ok := svc["volumes"]; ok {
		for _, vol := range asList(v) {
			if err := p.checkVolume(vol); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkVolume accepts named volumes, tmpfs and bind mounts that pass checkBindSource.
func (p composePolicy) checkVolume(vol any) error {
	switch v := vol.(type) {
	case string:
		if strings.Contains(v, "$") {
			return fmt.Errorf("volume %q: variable interpolation is not allowed", v)
		}
		src, _, found := strings.Cut(v, ":")
		if !found {
			return nil // anonymous volume
		}
		if !strings.HasPrefix(src, "/") && !strings.HasPrefix(src, ".") && !strings.HasPrefix(src, "~") {
			return nil // named volume
		}
		return p.checkBindSource(src)
	case map[string]any:
		typ, _ := v["type"].(string)
		src, _ := v["source"].(string)
		switch typ {
		case "volume", "tmpfs":
			if strings.Contains(src, "$") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") {
				return fmt.Errorf("volume source %q is not allowed", src)
			}
			return nil
		case "bind":
			if strings.Contains(src, "$") {
				return fmt.Errorf("volume %q: variable interpolation is not allowed", src)
			}
			return p.checkBindSource(src)
		}
	}
	return fmt.Errorf("volume %v is not allowed", vol)
}

// checkBindSource allows:
//   - a relative path inside the project directory (not the directory itself,
//     which holds the compose file), and
//   - an absolute path on a user share (/volumeN/<share>/...). Inside DataDir
//     only <id>/<sub>/... where <sub> is not a deploy version or state file,
//     so a container can never rewrite compose files the agent will run.
//
// Symlinks along a path the agent can see are rejected, because the daemon
// resolves them on the host when it creates the mount.
func (p composePolicy) checkBindSource(src string) error {
	bad := func(why string) error { return fmt.Errorf("bind mount %q: %s", src, why) }
	if strings.HasPrefix(src, "~") {
		return bad("home directory paths are not allowed")
	}
	if !strings.HasPrefix(src, "/") {
		rel := filepath.Clean(src)
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || rel == "docker-compose.yml" {
			return bad("must stay inside the project directory")
		}
		return p.checkNoSymlinks(p.projectDir, rel)
	}

	clean := filepath.Clean(src)
	if !isSafeMountPath(clean) || !strings.HasPrefix(clean, "/volume") {
		return bad("only /volumeN/<share>/... paths are allowed")
	}
	for _, part := range strings.Split(clean, "/") {
		if strings.HasPrefix(part, "@") || strings.HasPrefix(part, "#") {
			return bad("system directories are not allowed")
		}
	}
	for _, root := range []string{p.hostDataDir, p.dataDir} {
		if root == "" {
			continue
		}
		root = filepath.Clean(root)
		if clean == root || strings.HasPrefix(root, clean+"/") {
			return bad("must not contain the agent data directory")
		}
		if strings.HasPrefix(clean, root+"/") {
			parts := strings.Split(strings.TrimPrefix(clean, root+"/"), "/")
			if len(parts) < 2 || versionDirName.MatchString(parts[1]) || parts[1] == "state.json" {
				return bad("must not expose agent-managed files")
			}
			return p.checkNoSymlinks(p.dataDir, strings.Join(parts, "/"))
		}
	}
	return p.checkNoSymlinks("/", strings.TrimPrefix(clean, "/"))
}

// checkNoSymlinks walks base/rel component by component and rejects a symlink.
// Components that do not exist (yet) end the walk.
func (p composePolicy) checkNoSymlinks(base, rel string) error {
	cur := base
	for _, part := range strings.Split(rel, "/") {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			return nil
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("bind mount path contains a symlink: %s", cur)
		}
	}
	return nil
}

// checkTopLevelResources rejects top-level volumes/networks that could reach
// the host or other projects: driver options can bind an arbitrary host path
// (driver_opts: {type: none, o: bind, device: /}), and external/name can attach
// to existing resources such as the "host" network.
func checkTopLevelResources(kind string, v any) error {
	items, ok := v.(map[string]any)
	if !ok && v != nil {
		return fmt.Errorf("top-level %s: invalid definition", kind)
	}
	for name, raw := range items {
		cfg, ok := raw.(map[string]any)
		if !ok && raw != nil {
			return fmt.Errorf("%s %q: invalid definition", kind, name)
		}
		for k, val := range cfg {
			switch k {
			case "labels", "attachable", "internal", "enable_ipv6", "ipam":
				continue
			case "driver":
				if val == "local" || val == "bridge" {
					continue
				}
			}
			if !strings.HasPrefix(k, "x-") {
				return fmt.Errorf("%s %q: %s is not allowed", kind, name, k)
			}
		}
	}
	return nil
}

func allowedDevice(src string) bool {
	if strings.Contains(src, "..") {
		return false
	}
	return src == "/dev/dri" || strings.HasPrefix(src, "/dev/dri/") || src == "/dev/net/tun"
}

func asList(v any) []any {
	l, _ := v.([]any)
	if l == nil && v != nil {
		return []any{v} // a scalar or map where a list was expected is checked as one entry
	}
	return l
}
