package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// hostnameRe matches a DNS hostname (labels of letters/digits/hyphen, dots).
var hostnameRe = regexp.MustCompile(`^(?i)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validIngressService allows only the cloudflared service forms the app uses.
func validIngressService(s string) bool {
	switch {
	case s == "http_status:404":
		return true
	case strings.HasPrefix(s, "http://"), strings.HasPrefix(s, "https://"),
		strings.HasPrefix(s, "tcp://"), strings.HasPrefix(s, "ssh://"),
		strings.HasPrefix(s, "rdp://"), strings.HasPrefix(s, "unix:/"):
	case strings.HasPrefix(s, "http_status:"):
	default:
		return false
	}
	// No control chars / newlines / spaces that could break the config.
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

type ingressRule struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
}

type configureCloudflareReq struct {
	TunnelName string        `json:"tunnelName"`
	Ingress    []ingressRule `json:"ingress"`
}

func (s *server) handleConfigureCloudflare(w http.ResponseWriter, r *http.Request) {
	var req configureCloudflareReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("invalid json", err))
		return
	}

	if req.TunnelName == "" {
		writeJSON(w, http.StatusBadRequest, errMap("validation", fmt.Errorf("tunnelName is required")))
		return
	}

	out, err := exec.Command("docker", "run", "--rm", "-v", "nashubs-cf-creds:/root/.cloudflared", helperImage, "sh", "-c", "ls /root/.cloudflared/*.json").CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("failed to read cf-creds volume", fmt.Errorf("%s: %s", err, string(out))))
		return
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var uuidFile string
	for _, l := range lines {
		if strings.HasSuffix(l, ".json") && !strings.Contains(l, "*") {
			uuidFile = l
			break
		}
	}

	if uuidFile == "" {
		writeJSON(w, http.StatusNotFound, errMap("credentials", fmt.Errorf("no cloudflared credentials found in volume")))
		return
	}

	parts := strings.Split(uuidFile, "/")
	filename := parts[len(parts)-1]
	uuid := strings.TrimSuffix(filename, ".json")

	// Validate every ingress field before it reaches the config, and build the
	// YAML with a marshaller (never string interpolation), so a hostname/service
	// cannot inject extra cloudflared directives.
	type cfIngress struct {
		Hostname string `yaml:"hostname,omitempty"`
		Service  string `yaml:"service"`
	}
	cfg := struct {
		Tunnel          string      `yaml:"tunnel"`
		CredentialsFile string      `yaml:"credentials-file"`
		Ingress         []cfIngress `yaml:"ingress"`
	}{
		Tunnel:          uuid,
		CredentialsFile: fmt.Sprintf("/root/.cloudflared/%s.json", uuid),
	}
	for _, rule := range req.Ingress {
		if rule.Hostname != "" && !hostnameRe.MatchString(rule.Hostname) {
			writeJSON(w, http.StatusBadRequest, errMap("validation", fmt.Errorf("invalid ingress hostname %q", rule.Hostname)))
			return
		}
		if !validIngressService(rule.Service) {
			writeJSON(w, http.StatusBadRequest, errMap("validation", fmt.Errorf("invalid ingress service %q", rule.Service)))
			return
		}
		cfg.Ingress = append(cfg.Ingress, cfIngress{Hostname: rule.Hostname, Service: rule.Service})
	}
	// cloudflared requires a catch-all rule last.
	cfg.Ingress = append(cfg.Ingress, cfIngress{Service: "http_status:404"})

	yamlBytes, err := yaml.Marshal(cfg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("marshal config", err))
		return
	}
	configYAML := string(yamlBytes)

	writeCmd := exec.Command("docker", "run", "--rm", "-i", "-v", "nashubs-cf-creds:/root/.cloudflared", helperImage, "sh", "-c", "cat > /root/.cloudflared/config.yml")
	writeCmd.Stdin = strings.NewReader(configYAML)
	if out, err := writeCmd.CombinedOutput(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("failed to write config.yml", fmt.Errorf("%s: %s", err, string(out))))
		return
	}

	for _, rule := range req.Ingress {
		routeCmd := exec.Command("docker", "run", "--rm", "--user", "root", "-v", "nashubs-cf-creds:/root/.cloudflared", cloudflaredImage, "tunnel", "route", "dns", "-f", uuid, rule.Hostname)
		outRoute, errRoute := routeCmd.CombinedOutput()
		if errRoute != nil {
			// If it's just "already exists", we can ignore it.
			outStr := string(outRoute)
			if !strings.Contains(outStr, "already exists") {
				writeJSON(w, http.StatusInternalServerError, errMap("failed to route dns", fmt.Errorf("domain %s: %s - %s", rule.Hostname, errRoute, outStr)))
				return
			}
		}
	}

	_ = exec.Command("docker", "restart", "nashubs-cloudflared").Run()

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"uuid":   uuid,
		"config": configYAML,
	})
}

func (s *server) handleGetCloudflare(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("docker", "run", "--rm", "-v", "nashubs-cf-creds:/root/.cloudflared", helperImage, "cat", "/root/.cloudflared/config.yml").CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"ingress": []ingressRule{},
		})
		return
	}

	lines := strings.Split(string(out), "\n")
	var rules []ingressRule
	var currentRule *ingressRule

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- hostname:") {
			if currentRule != nil && currentRule.Hostname != "" {
				rules = append(rules, *currentRule)
			}
			currentRule = &ingressRule{Hostname: strings.TrimSpace(strings.TrimPrefix(line, "- hostname:"))}
		} else if strings.HasPrefix(line, "service:") && currentRule != nil {
			currentRule.Service = strings.TrimSpace(strings.TrimPrefix(line, "service:"))
			if currentRule.Service != "http_status:404" {
				rules = append(rules, *currentRule)
			}
			currentRule = nil
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"ingress": rules,
	})
}
