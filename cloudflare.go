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
	// Mode "merge" adds/updates the given rules (by hostname) and drops the
	// hostnames in Remove, keeping every other existing rule. The default
	// ("replace", for older apps) writes exactly the given rules.
	Mode   string   `json:"mode,omitempty"`
	Remove []string `json:"remove,omitempty"`
}

// mergeIngress applies upserts and removals to the existing rules, keyed by
// hostname, preserving order (catch-all rules without hostname are dropped;
// the writer re-adds the single http_status:404 catch-all).
func mergeIngress(existing, upserts []ingressRule, remove []string) []ingressRule {
	drop := map[string]bool{}
	for _, h := range remove {
		drop[strings.ToLower(h)] = true
	}
	idx := map[string]int{}
	var out []ingressRule
	for _, r := range existing {
		k := strings.ToLower(r.Hostname)
		if r.Hostname == "" || drop[k] {
			continue
		}
		if i, ok := idx[k]; ok {
			out[i] = r
			continue
		}
		idx[k] = len(out)
		out = append(out, r)
	}
	for _, r := range upserts {
		k := strings.ToLower(r.Hostname)
		if drop[k] {
			continue
		}
		if i, ok := idx[k]; ok {
			out[i] = r
			continue
		}
		idx[k] = len(out)
		out = append(out, r)
	}
	return out
}

// readCloudflareIngress parses the tunnel's config.yml (hostname rules only).
func (s *server) readCloudflareIngress() ([]ingressRule, error) {
	out, err := s.docker("run", "--rm", "-v", "nashubs-cf-creds:/root/.cloudflared", helperImage, "cat", "/root/.cloudflared/config.yml")
	if err != nil {
		return nil, err
	}
	return parseCloudflareConfig(out)
}

func parseCloudflareConfig(data []byte) ([]ingressRule, error) {
	var cfg struct {
		Ingress []struct {
			Hostname string `yaml:"hostname"`
			Service  string `yaml:"service"`
		} `yaml:"ingress"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	var rules []ingressRule
	for _, r := range cfg.Ingress {
		if r.Hostname != "" {
			rules = append(rules, ingressRule{Hostname: r.Hostname, Service: r.Service})
		}
	}
	return rules, nil
}

func (s *server) handleConfigureCloudflare(w http.ResponseWriter, r *http.Request) {
	var req configureCloudflareReq
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errMap("invalid json", err))
		return
	}

	if req.Mode != "" && req.Mode != "replace" && req.Mode != "merge" {
		writeJSON(w, http.StatusBadRequest, errMap("validation", fmt.Errorf("mode must be replace or merge")))
		return
	}
	for _, h := range req.Remove {
		if !hostnameRe.MatchString(h) {
			writeJSON(w, http.StatusBadRequest, errMap("validation", fmt.Errorf("invalid hostname %q", h)))
			return
		}
	}
	newRules := req.Ingress
	if req.Mode == "merge" {
		existing, _ := s.readCloudflareIngress() // no config yet = no rules
		req.Ingress = mergeIngress(existing, req.Ingress, req.Remove)
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

	for _, rule := range newRules {
		if rule.Hostname == "" {
			continue
		}
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
	rules, err := s.readCloudflareIngress()
	if err != nil || rules == nil {
		rules = []ingressRule{}
	}
	var out []ingressRule
	for _, r := range rules {
		if r.Service != "http_status:404" {
			out = append(out, r)
		}
	}
	if out == nil {
		out = []ingressRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ingress": out})
}
