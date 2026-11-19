package main

// The DSM installer runs this short-lived command with only the Docker socket
// mounted. DSM's container UI cannot reliably represent whole-volume mounts;
// the typed installer asks the host daemon to create the real Agent instead.
import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type bootstrapRequest struct {
	KeyID   string   `json:"keyId"`
	Secret  string   `json:"secret"`
	Image   string   `json:"image"`
	DataDir string   `json:"dataDir"`
	Volumes []string `json:"volumes"`
	// Upgrade (explicit user consent) recreates an existing nashubs-agent that
	// runs a different image, keeping its env, mounts and ports so devices,
	// TLS identity and deployments survive. Without it an existing agent is
	// never touched.
	Upgrade bool `json:"upgrade,omitempty"`
	// LanIP is the NAS LAN address the app used for DSM (reported to clients).
	LanIP string `json:"lanIP,omitempty"`
}
type bootstrapResult struct {
	OK          bool   `json:"ok"`
	Created     bool   `json:"created"`
	Upgraded    bool   `json:"upgraded,omitempty"`
	Certificate string `json:"certFingerprint,omitempty"`
	Invitation  string `json:"invitationCode,omitempty"`
	Error       string `json:"error,omitempty"`
}
type bootstrapIdentity struct {
	Certificate string `json:"certFingerprint"`
	Enrolled    bool   `json:"enrolled"`
	Revoked     bool   `json:"revoked"`
	HasOwner    bool   `json:"hasOwner"`
}

var previewImagePattern = regexp.MustCompile(`^ghcr\.io/thenashubs/nashubs-agent:sha-[0-9a-f]{40}$`)
var bootstrapVolumePattern = regexp.MustCompile(`^/volume[1-9][0-9]*$`)

func (r bootstrapRequest) validate() error {
	k, err := base64.StdEncoding.DecodeString(r.KeyID)
	if err != nil || len(k) != 32 || !previewImagePattern.MatchString(r.Image) {
		return fmt.Errorf("INVALID_BOOTSTRAP")
	}
	if len(r.Secret) < 24 || len(r.Secret) > 128 || strings.Trim(r.Secret, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
		return fmt.Errorf("INVALID_BOOTSTRAP")
	}
	if len(r.Volumes) == 0 || len(r.Volumes) > 64 {
		return fmt.Errorf("INVALID_VOLUMES")
	}
	seen := map[string]bool{}
	dataOK := false
	for _, v := range r.Volumes {
		if !bootstrapVolumePattern.MatchString(v) || seen[v] {
			return fmt.Errorf("INVALID_VOLUMES")
		}
		seen[v] = true
		if r.DataDir == v+"/docker/nashubs-agent/data" {
			dataOK = true
		}
	}
	if !dataOK {
		return fmt.Errorf("INVALID_DATA_DIR")
	}
	if r.LanIP != "" && !lanIPPattern.MatchString(r.LanIP) {
		return fmt.Errorf("INVALID_BOOTSTRAP")
	}
	return nil
}

var lanIPPattern = regexp.MustCompile(`^(10|172|192)\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

// inspectedAgent is the subset of `docker inspect nashubs-agent` the upgrade keeps.
type inspectedAgent struct {
	Config struct {
		Image string   `json:"Image"`
		Env   []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		Binds        []string `json:"Binds"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
}

// upgradeArgs builds the `docker run` argv for the upgraded agent from the
// existing container's own configuration (env, binds, published ports).
func upgradeArgs(old inspectedAgent, image, lanIP string) ([]string, error) {
	args := []string{"run", "-d", "--name", "nashubs-agent", "--restart", "unless-stopped"}
	sawSock := false
	for _, b := range old.HostConfig.Binds {
		if strings.ContainsAny(b, "\n\r") {
			return nil, fmt.Errorf("UPGRADE_UNSUPPORTED")
		}
		if strings.HasPrefix(b, "/var/run/docker.sock:") {
			sawSock = true
		}
		args = append(args, "-v", b)
	}
	if !sawSock {
		return nil, fmt.Errorf("UPGRADE_UNSUPPORTED")
	}
	ports := make([]string, 0, len(old.HostConfig.PortBindings))
	for cport, binds := range old.HostConfig.PortBindings {
		for _, b := range binds {
			p := b.HostPort + ":" + strings.TrimSuffix(cport, "/tcp")
			if b.HostIP != "" {
				p = b.HostIP + ":" + p
			}
			ports = append(ports, p)
		}
	}
	sort.Strings(ports)
	for _, p := range ports {
		args = append(args, "-p", p)
	}
	for _, e := range old.Config.Env {
		k, _, _ := strings.Cut(e, "=")
		// Image-provided variables come from the new image; the agent image ref
		// is replaced so self-update follows the upgraded line.
		if k == "PATH" || k == "HOME" || k == "NASHUBS_AGENT_IMAGE" || k == "NASDECK_AGENT_IMAGE" || strings.ContainsAny(e, "\n\r") {
			continue
		}
		args = append(args, "-e", e)
	}
	if lanIP != "" {
		hasLan := false
		for _, e := range old.Config.Env {
			if strings.HasPrefix(e, "NASHUBS_LAN_IP=") {
				hasLan = true
			}
		}
		if !hasLan {
			args = append(args, "-e", "NASHUBS_LAN_IP="+lanIP)
		}
	}
	args = append(args, "-e", "NASHUBS_AGENT_IMAGE="+image, image)
	return args, nil
}

// upgradeAgent swaps the running agent for one on the new image. The old
// container is renamed and kept until the new one proves its identity, then
// removed; on failure it is restored and started again.
func upgradeAgent(r bootstrapRequest, docker bootstrapDocker, pause func()) error {
	raw, err := docker("inspect", "nashubs-agent")
	if err != nil {
		return fmt.Errorf("DOCKER_UNAVAILABLE")
	}
	var list []inspectedAgent
	if json.Unmarshal(raw, &list) != nil || len(list) != 1 {
		return fmt.Errorf("UPGRADE_UNSUPPORTED")
	}
	if list[0].Config.Image == r.Image {
		return nil
	}
	args, err := upgradeArgs(list[0], r.Image, r.LanIP)
	if err != nil {
		return err
	}
	_, _ = docker("rm", "-f", "nashubs-agent-previous")
	if _, err := docker("rename", "nashubs-agent", "nashubs-agent-previous"); err != nil {
		return fmt.Errorf("UPGRADE_FAILED")
	}
	_, _ = docker("stop", "-t", "20", "nashubs-agent-previous")
	restore := func() {
		_, _ = docker("rm", "-f", "nashubs-agent")
		_, _ = docker("rename", "nashubs-agent-previous", "nashubs-agent")
		_, _ = docker("start", "nashubs-agent")
	}
	if _, err := docker(args...); err != nil {
		restore()
		return fmt.Errorf("UPGRADE_FAILED")
	}
	for i := 0; i < 40; i++ {
		out, err := docker("exec", "nashubs-agent", "nashubs-agent", "bootstrap-identity", r.KeyID)
		var id bootstrapIdentity
		if err == nil && json.Unmarshal(out, &id) == nil && id.Certificate != "" {
			_, _ = docker("rm", "-f", "nashubs-agent-previous")
			return nil
		}
		pause()
	}
	restore()
	return fmt.Errorf("UPGRADE_FAILED")
}

type bootstrapDocker func(...string) ([]byte, error)

func bootstrapAgent(r bootstrapRequest, docker bootstrapDocker, pause func()) (bootstrapResult, error) {
	if err := r.validate(); err != nil {
		return bootstrapResult{}, err
	}
	// Enumerate the daemon directly: DSM may not know containers created by CLI.
	list, err := docker("ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		return bootstrapResult{}, fmt.Errorf("DOCKER_UNAVAILABLE")
	}
	exists := false
	for _, name := range strings.Fields(string(list)) {
		if name == "nasdeck-agent" {
			return bootstrapResult{}, fmt.Errorf("LEGACY_AGENT_FOUND")
		}
		if name == "nashubs-agent" {
			exists = true
		}
	}
	if r.LanIP == "" && (!exists || r.Upgrade) {
		// The app may reach DSM by domain; ask the host network for the LAN IPv4.
		if out, err := docker("run", "--rm", "--network", "host", r.Image, "lan-ip"); err == nil {
			if ip := strings.TrimSpace(string(out)); lanIPPattern.MatchString(ip) {
				r.LanIP = ip
			}
		}
	}
	result := bootstrapResult{OK: true, Created: !exists}
	if exists && r.Upgrade {
		if err := upgradeAgent(r, docker, pause); err != nil {
			return bootstrapResult{}, err
		}
		result.Upgraded = true
	}
	if !exists {
		args := []string{"run", "-d", "--name", "nashubs-agent", "--restart", "unless-stopped", "-p", "8443:8443", "-v", "/var/run/docker.sock:/var/run/docker.sock"}
		for _, v := range r.Volumes {
			args = append(args, "-v", v+":"+v)
		}
		for _, env := range []string{"NASHUBS_NGINX_CONF_DIR=none", "NASHUBS_DATA_DIR=" + r.DataDir, "NASHUBS_HOST_DATA_DIR=" + r.DataDir,
			"NASHUBS_AGENT_IMAGE=" + r.Image, "NASHUBS_TRUSTED_PUBKEY=" + r.KeyID, "NASHUBS_PAIRING_SECRET=" + r.Secret} {
			args = append(args, "-e", env)
		}
		if r.LanIP != "" {
			args = append(args, "-e", "NASHUBS_LAN_IP="+r.LanIP)
		}
		args = append(args, r.Image)
		if _, err := docker(args...); err != nil {
			return bootstrapResult{}, fmt.Errorf("CREATE_FAILED")
		}
	}
	var id bootstrapIdentity
	ready := false
	for i := 0; i < 40; i++ {
		// This CLI validates the persisted store and returns only public identity.
		out, err := docker("exec", "nashubs-agent", "nashubs-agent", "bootstrap-identity", r.KeyID)
		if err == nil && json.Unmarshal(out, &id) == nil && id.Certificate != "" {
			ready = true
			break
		}
		pause()
	}
	if !ready {
		return bootstrapResult{}, fmt.Errorf("AGENT_IDENTITY_UNAVAILABLE")
	}
	if id.Revoked {
		return bootstrapResult{}, fmt.Errorf("DEVICE_REVOKED")
	}
	result.Certificate = id.Certificate
	if !id.Enrolled {
		// Also covers restored data directories and device #10, without restarting.
		role := "owner"
		if id.HasOwner {
			role = "admin"
		}
		out, err := docker("exec", "nashubs-agent", "nashubs-agent", "invite", "--role", role)
		var invitation struct {
			OK   bool   `json:"ok"`
			Code string `json:"code"`
		}
		if err != nil || json.Unmarshal(out, &invitation) != nil || !invitation.OK || invitation.Code == "" {
			return bootstrapResult{}, fmt.Errorf("INVITATION_FAILED")
		}
		result.Invitation = invitation.Code
	}
	return result, nil
}

func runBootstrapIdentity(key string) error {
	cfg := loadConfig()
	fp, err := fingerprintOfFile(filepath.Join(cfg.DataDir, "agent.crt"))
	if err != nil {
		return err
	}
	ds := newDeviceStore(cfg.DataDir)
	if ds.loadErr != nil {
		return fmt.Errorf("INVALID_DEVICE_STORE")
	}
	id := bootstrapIdentity{Certificate: fp}
	for _, d := range ds.devices {
		if d.Role == RoleOwner && !d.revoked() {
			id.HasOwner = true
		}
		if d.KeyID == key {
			id.Enrolled = true
			id.Revoked = d.revoked()
		}
	}
	return json.NewEncoder(os.Stdout).Encode(id)
}

func runDsmBootstrap() int {
	var request bootstrapRequest
	result := bootstrapResult{}
	var err error
	if os.Geteuid() != 0 {
		err = fmt.Errorf("ROOT_REQUIRED")
	} else if len(os.Getenv("NASHUBS_BOOTSTRAP_PAYLOAD")) > 16384 {
		err = fmt.Errorf("INVALID_BOOTSTRAP")
	} else {
		err = json.Unmarshal([]byte(os.Getenv("NASHUBS_BOOTSTRAP_PAYLOAD")), &request)
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			// Only fixed argument arrays; daemon errors/payload are never logged.
			result, err = bootstrapAgent(request, func(args ...string) ([]byte, error) { return exec.CommandContext(ctx, "docker", args...).Output() }, func() { time.Sleep(time.Second) })
		}
	}
	if err != nil {
		result = bootstrapResult{Error: "BOOTSTRAP_FAILED"}
		if regexp.MustCompile(`^[A-Z_]+$`).MatchString(err.Error()) {
			result.Error = err.Error()
		}
	}
	b, _ := json.Marshal(result)
	// The short-lived invitation is visible only to DSM administrators. Android
	// consumes it immediately, then removes this installer container and its logs.
	fmt.Printf("NASHUBS_BOOTSTRAP_RESULT %s\n", b)
	if err != nil {
		return 1
	}
	return 0
}
