package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// idSafe enforces a strict id charset to prevent path traversal / injection.
var idSafe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// reservedAppIDs are ids whose "nashubs-<id>" container name belongs to the agent itself.
// Deploying or removing them would `docker rm -f nashubs-agent` mid-request, and since the
// container is removed (not stopped) its restart policy never brings it back.
var reservedAppIDs = map[string]bool{"agent": true}

// agentContainerName is the agent's own container. No deploy may ever name a
// service this, nor rm it, or the deploy would kill the control plane.
const agentContainerName = "nashubs-agent"

// validAppID reports whether id may be deployed, removed or rolled back.
func validAppID(id string) bool {
	return idSafe.MatchString(id) && !reservedAppIDs[id]
}

type deployRequest struct {
	ID           string `json:"id"`
	Compose      string `json:"compose"`      // rendered docker-compose.yml
	Version      string `json:"version"`      // optional label; actual artifact = sha256(compose)[:12]
	InternalPort int    `json:"internalPort"` // if > 0, auto-create reverse proxy after deploy
	PathPrefix   string `json:"pathPrefix"`   // URL prefix for reverse proxy (default: /{id})
	Pull         bool   `json:"pull"`         // if true, `compose pull` before `up` to fetch newer images
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
	if !validAppID(req.ID) || req.Compose == "" {
		writeJSON(w, http.StatusBadRequest, errMap("invalid id or empty compose", nil))
		return
	}
	// No service may claim the agent's own container name (any role): a later
	// rm of it would remove the control plane mid-request.
	for _, name := range composeContainerNames([]byte(req.Compose)) {
		if name == agentContainerName {
			writeJSON(w, http.StatusBadRequest, errMap("container_name "+agentContainerName+" is reserved", nil))
			return
		}
	}
	if req.InternalPort != 0 {
		prefix := req.PathPrefix
		if prefix == "" {
			prefix = "/" + req.ID
		}
		if !validAppProxy(prefix, req.InternalPort) {
			writeJSON(w, http.StatusBadRequest, errMap("invalid internalPort or pathPrefix", nil))
			return
		}
	}

	sum := sha256.Sum256([]byte(req.Compose))
	version := fmt.Sprintf("v%s", hex.EncodeToString(sum[:6])) // v + 12 hex chars

	// Container path (writable mount) and the matching host path the daemon sees.
	dir := filepath.Join(s.cfg.DataDir, req.ID, version)
	hostDir := filepath.Join(s.cfg.HostDataDir, req.ID, version)
	if authFrom(r).role != RoleOwner {
		pol := composePolicy{appID: req.ID, dataDir: s.cfg.DataDir, hostDataDir: s.cfg.HostDataDir, projectDir: dir}
		if err := pol.check([]byte(req.Compose)); err != nil {
			writeJSON(w, http.StatusForbidden, errMap("compose option requires the owner role", err))
			return
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("mkdir", err))
		return
	}
	composeFile := filepath.Join(dir, "docker-compose.yml")
	if err := writePrivateFile(composeFile, []byte(req.Compose)); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("write compose", err))
		return
	}
	hostCompose := filepath.Join(hostDir, "docker-compose.yml")

	// docker-compose v1 (DSM 7.0) does NOT auto-create bind-mount host dirs,
	// unlike compose v2 — a deploy would fail "Bind mount failed: ... does not
	// exist". Pre-create them (agent runs as root; harmless if already present).
	ensureBindMountDirs([]byte(req.Compose))

	// Forcefully remove any existing container that would collide with this
	// deploy: the project's own name, plus every container_name declared in the
	// compose. An app installed by the old agent keeps the same container_name
	// (templates are shared), so this clears the "Conflict" (422) on redeploy
	// without scanning for or touching any other container or volume.
	_ = exec.Command("docker", "rm", "-f", "nashubs-"+req.ID).Run()
	for _, name := range composeContainerNames([]byte(req.Compose)) {
		if name != "nashubs-"+req.ID && name != agentContainerName {
			_ = exec.Command("docker", "rm", "-f", name).Run()
		}
	}

	out := ""
	if req.Pull {
		// Typed image refresh (replaces the removed generic /exec): pull newer
		// images for this project before recreating. A pull failure is not fatal.
		pullOut, pullErr := s.runCompose(hostCompose, req.ID, "pull")
		out += pullOut
		if pullErr != nil {
			out += fmt.Sprintf("\n[warn] compose pull: %v", pullErr)
		}
	}
	upOut, runErr := s.runCompose(hostCompose, req.ID, "up", "-d")
	out += upOut

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

	// Bound disk usage: every deploy writes a new immutable version dir and
	// nothing would ever reclaim them. Keep the newest few for rollback.
	pruneVersions(filepath.Dir(dir), 5)

	resp := deployResponse{
		OK:       runErr == nil,
		Version:  version,
		HostPath: hostCompose,
		Output:   out,
	}

	// Auto-create reverse proxy if deploy succeeded and port is specified
	if runErr == nil && req.InternalPort > 0 && s.nginxEnabled() {
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
	// Bound every compose invocation so a hung daemon / stuck pull can't leave an
	// orphaned process forever. Generous enough for image pulls on slow links.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(composeEnv(os.Environ()),
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

// composeEnvAllowed lists the only variables of the agent's environment that
// the compose CLI receives. Compose interpolates ${VAR} from its environment,
// so anything else (pairing secret, trusted keys, tokens, future settings)
// could be copied into a deployed container. Templates are filled in by the
// app before deploy and the agent writes no .env file, so nothing needs more.
var composeEnvAllowed = map[string]bool{
	"PATH": true, "HOME": true, "TMPDIR": true, "TZ": true, "LANG": true, "LC_ALL": true,
	"DOCKER_HOST": true, "DOCKER_CONFIG": true, "DOCKER_CONTEXT": true,
	"DOCKER_CERT_PATH": true, "DOCKER_TLS_VERIFY": true, "DOCKER_API_VERSION": true,
}

// composeEnv returns the allowlisted subset of environ.
func composeEnv(environ []string) []string {
	out := make([]string, 0, len(composeEnvAllowed))
	for _, kv := range environ {
		if k, _, _ := strings.Cut(kv, "="); composeEnvAllowed[k] {
			out = append(out, kv)
		}
	}
	return out
}

// dockerNameRe is Docker's own container-name grammar. A name that does not
// match (e.g. one starting with "-") is skipped rather than passed to rm.
var dockerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

// composeContainerNames returns the explicit container_name of each service.
// Used to clear name conflicts on redeploy (incl. apps from the old agent).
func composeContainerNames(compose []byte) []string {
	var doc struct {
		Services map[string]struct {
			ContainerName string `yaml:"container_name"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil
	}
	var names []string
	for _, svc := range doc.Services {
		if n := svc.ContainerName; n != "" && dockerNameRe.MatchString(n) {
			names = append(names, n)
		}
	}
	return names
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
	if strings.HasPrefix(cleaned, "/data/") {
		return true
	}
	// Bất kỳ volume nào: /volume<digits>/...  (Synology có thể là volume1..N).
	// filepath.Clean đã loại ".." nên không lo path traversal ra ngoài volume.
	if strings.HasPrefix(cleaned, "/volume") {
		rest := cleaned[len("/volume"):]
		i := 0
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		return i > 0 && i < len(rest) && rest[i] == '/'
	}
	return false
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

// pruneVersions removes the oldest v<sha12> directories under projectDir,
// keeping the newest `keep`. Deploy artifacts are immutable and accumulate
// forever otherwise — each deploy is a new directory of YAML on the NAS disk.
// Best-effort: removal failures are ignored.
func pruneVersions(projectDir string, keep int) {
	entries, err := os.ReadDir(projectDir)
	if err != nil {
		return
	}
	type ver struct {
		name string
		mod  time.Time
	}
	var vers []ver
	for _, e := range entries {
		if !e.IsDir() || !versionDirName.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		vers = append(vers, ver{e.Name(), info.ModTime()})
	}
	if len(vers) <= keep {
		return
	}
	sort.Slice(vers, func(i, j int) bool { return vers[i].mod.After(vers[j].mod) })
	for _, v := range vers[keep:] {
		_ = os.RemoveAll(filepath.Join(projectDir, v.name))
	}
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
	return writePrivateFile(statePath(dataDir, id), b)
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
