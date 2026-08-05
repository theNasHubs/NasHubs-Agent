package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// idSafe enforces a strict id charset to prevent path traversal / injection.
var idSafe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type deployRequest struct {
	ID           string `json:"id"`
	Compose      string `json:"compose"`      // rendered docker-compose.yml
	Version      string `json:"version"`      // optional label; actual artifact = sha256(compose)[:12]
	InternalPort int    `json:"internalPort"` // if > 0, auto-create reverse proxy after deploy
	PathPrefix   string `json:"pathPrefix"`   // URL prefix for reverse proxy (default: /{id})
}

type deployResponse struct {
	OK       bool   `json:"ok"`
	Version  string `json:"version"`
	HostPath string `json:"hostPath"`
	Output   string `json:"output"`
	WebPath  string `json:"webPath,omitempty"` // path for remote web access via reverse proxy
}

// handleDeploy writes an immutable versioned compose artifact and runs
// `docker compose up -d` against it via the host Docker daemon.
func (s *server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	var req deployRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("bad request", err))
		return
	}
	if !idSafe.MatchString(req.ID) || req.Compose == "" {
		writeJSON(w, http.StatusBadRequest, errMap("invalid id or empty compose", nil))
		return
	}

	sum := sha256.Sum256([]byte(req.Compose))
	version := fmt.Sprintf("v%s", hex.EncodeToString(sum[:6])) // v + 12 hex chars

	// Container path (writable mount) and the matching host path the daemon sees.
	dir := filepath.Join(s.cfg.DataDir, req.ID, version)
	hostDir := filepath.Join(s.cfg.HostDataDir, req.ID, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("mkdir", err))
		return
	}
	composeFile := filepath.Join(dir, "docker-compose.yml")
	if err := os.WriteFile(composeFile, []byte(req.Compose), 0o644); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("write compose", err))
		return
	}
	hostCompose := filepath.Join(hostDir, "docker-compose.yml")

	// docker-compose v1 (DSM 7.0) does NOT auto-create bind-mount host dirs,
	// unlike compose v2 — a deploy would fail "Bind mount failed: ... does not
	// exist". Pre-create them (agent runs as root; harmless if already present).
	ensureBindMountDirs([]byte(req.Compose))

	// Forcefully remove any existing container with the exact target name.
	// This prevents "Conflict" errors when migrating from the old agent (which
	// used random project names) to the new agent (which uses explicit `-p req.ID`).
	_ = exec.Command("docker", "rm", "-f", "nashubs-"+req.ID).Run()

	out, runErr := s.runCompose(hostCompose, req.ID, "up", "-d")

	// Record current version so /logs /health /rollback can resolve it.
	st := deployState{
		Current:      version,
		HostPath:     hostCompose,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
		InternalPort: req.InternalPort,
	}
	if req.PathPrefix != "" {
		st.PathPrefix = req.PathPrefix
	} else if req.InternalPort > 0 {
		st.PathPrefix = "/" + req.ID
	}
	if err := saveState(s.cfg.DataDir, req.ID, st); err != nil {
		// Non-fatal: deploy may have succeeded; surface in output.
		out += fmt.Sprintf("\n[warn] state save: %v", err)
	}

	resp := deployResponse{
		OK:       runErr == nil,
		Version:  version,
		HostPath: hostCompose,
		Output:   out,
	}

	// Auto-create reverse proxy if deploy succeeded and port is specified
	if runErr == nil && req.InternalPort > 0 {
		prefix := req.PathPrefix
		if prefix == "" {
			prefix = "/" + req.ID
		}
		confFile := filepath.Join(s.cfg.NginxConfDir, fmt.Sprintf("dsm.nashubs-%s.conf", req.ID))
		conf := generateNginxConf(prefix, req.InternalPort)
		if err := os.WriteFile(confFile, []byte(conf), 0o644); err == nil {
			if err := s.testNginx(); err != nil {
				_ = os.Remove(confFile)
				out += fmt.Sprintf("\n[warn] proxy config test failed, rolled back: %v", err)
			} else if err := s.reloadNginx(); err != nil {
				out += fmt.Sprintf("\n[warn] nginx reload failed: %v", err)
			} else {
				resp.WebPath = prefix + "/"
				out += fmt.Sprintf("\n[proxy] created %s → :%d", prefix, req.InternalPort)
			}
		}
		resp.Output = out
	}

	code := http.StatusOK
	if runErr != nil {
		code = http.StatusUnprocessableEntity
	}
	writeJSON(w, code, resp)
}

// runCompose invokes the compose CLI (v2 plugin or v1 binary) with a compose
// file resolved on the HOST filesystem.
func (s *server) runCompose(hostCompose string, projectName string, args ...string) (string, error) {
	argv := append([]string{}, s.composeArgs...)
	argv = append(argv, "-p", "nashubs-"+projectName)
	argv = append(argv, "-f", hostCompose, "--project-directory", filepath.Dir(hostCompose))
	argv = append(argv, args...)
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(),
		"COMPOSE_COMPATIBILITY=true",
		// Synology keeps docker/compose under these paths; harmless elsewhere.
		"PATH="+os.Getenv("PATH")+":/var/packages/ContainerManager/target/usr/bin:/var/packages/Docker/target/usr/bin:/usr/local/bin",
	)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	err := cmd.Run()
	return combined.String(), err
}

// ensureBindMountDirs parses the compose for service volume bind mounts and
// creates the host-side directories. docker-compose v1 (DSM 7.0) does NOT
// auto-create bind-mount host dirs (compose v2 / recent docker do), so without
// this a deploy fails "Bind mount failed: ... does not exist". Best-effort.
//
// Safety: only creates dirs under /volume1/ (Synology data partition) to prevent
// path-traversal via crafted compose volumes even if a signing key is compromised.
func ensureBindMountDirs(compose []byte) {
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return
	}
	for _, svc := range doc.Services {
		for _, v := range svc.Volumes {
			if host := bindHostPath(v); host != "" && isSafeMountPath(host) {
				_ = os.MkdirAll(host, 0o755)
			}
		}
	}
}

// isSafeMountPath returns true if the resolved path is under /volume1/ (or
// /data/ inside the container). This prevents a compromised key from creating
// arbitrary directories on the NAS host filesystem.
func isSafeMountPath(p string) bool {
	cleaned := filepath.Clean(p)
	return strings.HasPrefix(cleaned, "/volume1/") || strings.HasPrefix(cleaned, "/data/")
}

// bindHostPath returns the host side of a bind volume entry like "/host:/cont"
// or "./rel:/cont" (optionally ":ro"), or "" for named/anonymous volumes.
func bindHostPath(v string) string {
	v = strings.TrimSpace(v)
	i := strings.IndexByte(v, ':')
	if i <= 0 {
		return "" // anonymous volume (e.g. "/cont") or malformed
	}
	host := v[:i]
	if strings.HasPrefix(host, "/") || strings.HasPrefix(host, ".") || strings.HasPrefix(host, "~") {
		return host
	}
	return "" // named volume (e.g. "myvol:/data")
}

// --- deploy state persistence ---

type deployState struct {
	Current      string `json:"current"`
	HostPath     string `json:"hostPath"`
	UpdatedAt    string `json:"updatedAt"`
	InternalPort int    `json:"internalPort,omitempty"`
	PathPrefix   string `json:"pathPrefix,omitempty"`
}

func statePath(dataDir, id string) string { return filepath.Join(dataDir, id, "state.json") }

func saveState(dataDir, id string, st deployState) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(dataDir, id), b, 0o644)
}

func loadState(dataDir, id string) (deployState, error) {
	var st deployState
	b, err := os.ReadFile(statePath(dataDir, id))
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(b, &st)
	return st, err
}
