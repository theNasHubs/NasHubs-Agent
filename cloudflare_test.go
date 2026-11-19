package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidIngressService(t *testing.T) {
	// Loopback services are the only targets a non-owner may use (#32).
	okAdmin := []string{"http://localhost:8096", "https://127.0.0.1:8443", "http://localhost", "http://[::1]:9", "http://localhost:5000/path", "http_status:404", "http_status:503"}
	for _, s := range okAdmin {
		if !validIngressService(s, false) {
			t.Errorf("admin want valid: %q", s)
		}
	}
	// Non-loopback and non-http targets are owner-only.
	ownerOnly := []string{"https://10.0.0.2:443", "tcp://10.0.0.2:22", "ssh://h:22", "rdp://h:3389", "unix:/run/x.sock", "http://nas.lan:5000"}
	for _, s := range ownerOnly {
		if validIngressService(s, false) {
			t.Errorf("admin must not use: %q", s)
		}
		if !validIngressService(s, true) {
			t.Errorf("owner want valid: %q", s)
		}
	}
	bad := []string{"", "javascript:1", "file:///etc", "http://x\nwarp-routing: {enabled: true}", "http://x yes", "http://x\t",
		"http://localhost.evil.com", "http://localhost:0", "http://localhost:99999", "http_status:x", "http_status:99",
		"http://localhost@evil.com", "tcp://localhost:22"}
	for _, s := range bad {
		if validIngressService(s, false) {
			t.Errorf("admin want invalid: %q", s)
		}
	}
}

func TestHostnameRejectsInjection(t *testing.T) {
	bad := []string{"a.b\n  - service: ssh://evil", "x y.com", "has space", "a..b", "-bad.com", "a.com\twarp"}
	for _, h := range bad {
		if hostnameRe.MatchString(h) {
			t.Errorf("hostname should be rejected: %q", h)
		}
	}
	for _, h := range []string{"app.example.com", "a.co", "xn--abc.example.com", "EXAMPLE.com"} {
		if !hostnameRe.MatchString(h) {
			t.Errorf("hostname should be accepted: %q", h)
		}
	}
}

// The marshalled config.yml must contain only the expected directives even if
// an ingress field tries to smuggle YAML. (Mirrors what the handler builds.)
func TestCloudflareConfigMarshalNoInjection(t *testing.T) {
	type cfIngress struct {
		Hostname string `yaml:"hostname,omitempty"`
		Service  string `yaml:"service"`
	}
	cfg := struct {
		Tunnel          string      `yaml:"tunnel"`
		CredentialsFile string      `yaml:"credentials-file"`
		Ingress         []cfIngress `yaml:"ingress"`
	}{Tunnel: "uuid", CredentialsFile: "/root/.cloudflared/uuid.json"}
	// A malicious value that passed NO validation would still be quoted by the
	// marshaller rather than breaking out into a new directive.
	cfg.Ingress = append(cfg.Ingress, cfIngress{Hostname: "evil\nwarp-routing:\n  enabled: true", Service: "http://x"})
	cfg.Ingress = append(cfg.Ingress, cfIngress{Service: "http_status:404"})
	out, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Re-parse: the smuggled key must NOT appear as a top-level directive.
	var parsed map[string]any
	if err := yaml.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed["warp-routing"]; ok {
		t.Fatalf("injection succeeded, config:\n%s", out)
	}
	if !strings.Contains(string(out), "warp-routing") {
		t.Fatal("test precondition: expected the smuggled text to be present (as quoted data)")
	}
}
