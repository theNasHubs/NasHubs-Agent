package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

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

	out, err := exec.Command("docker", "run", "--rm", "-v", "nashubs-cf-creds:/root/.cloudflared", "alpine", "sh", "-c", "ls /root/.cloudflared/*.json").CombinedOutput()
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

	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("tunnel: %s\n", uuid))
	buf.WriteString(fmt.Sprintf("credentials-file: /root/.cloudflared/%s.json\n", uuid))
	buf.WriteString("ingress:\n")
	for _, rule := range req.Ingress {
		buf.WriteString(fmt.Sprintf("  - hostname: %s\n", rule.Hostname))
		buf.WriteString(fmt.Sprintf("    service: %s\n", rule.Service))
	}
	buf.WriteString("  - service: http_status:404\n")

	configYAML := buf.String()

	writeCmd := exec.Command("docker", "run", "--rm", "-i", "-v", "nashubs-cf-creds:/root/.cloudflared", "alpine", "sh", "-c", "cat > /root/.cloudflared/config.yml")
	writeCmd.Stdin = strings.NewReader(configYAML)
	if out, err := writeCmd.CombinedOutput(); err != nil {
		writeJSON(w, http.StatusInternalServerError, errMap("failed to write config.yml", fmt.Errorf("%s: %s", err, string(out))))
		return
	}

	for _, rule := range req.Ingress {
		routeCmd := exec.Command("docker", "run", "--rm", "--user", "root", "-v", "nashubs-cf-creds:/root/.cloudflared", "cloudflare/cloudflared:latest", "tunnel", "route", "dns", "-f", uuid, rule.Hostname)
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
		"ok": true,
		"uuid": uuid,
		"config": configYAML,
	})
}

func (s *server) handleGetCloudflare(w http.ResponseWriter, r *http.Request) {
	out, err := exec.Command("docker", "run", "--rm", "-v", "nashubs-cf-creds:/root/.cloudflared", "alpine", "cat", "/root/.cloudflared/config.yml").CombinedOutput()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
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
		"ok": true,
		"ingress": rules,
	})
}
