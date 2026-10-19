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
	"strings"
	"time"
)

type bootstrapRequest struct {
	KeyID   string   `json:"keyId"`
	Secret  string   `json:"secret"`
	Image   string   `json:"image"`
	DataDir string   `json:"dataDir"`
	Volumes []string `json:"volumes"`
}
type bootstrapResult struct {
	OK          bool   `json:"ok"`
	Created     bool   `json:"created"`
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
	return nil
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
	result := bootstrapResult{OK: true, Created: !exists}
	if !exists {
		args := []string{"run", "-d", "--name", "nashubs-agent", "--restart", "unless-stopped", "-p", "8443:8443", "-v", "/var/run/docker.sock:/var/run/docker.sock"}
		for _, v := range r.Volumes {
			args = append(args, "-v", v+":"+v)
		}
		for _, env := range []string{"NASHUBS_NGINX_CONF_DIR=none", "NASHUBS_DATA_DIR=" + r.DataDir, "NASHUBS_HOST_DATA_DIR=" + r.DataDir,
			"NASHUBS_AGENT_IMAGE=" + r.Image, "NASHUBS_TRUSTED_PUBKEY=" + r.KeyID, "NASHUBS_PAIRING_SECRET=" + r.Secret} {
			args = append(args, "-e", env)
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
