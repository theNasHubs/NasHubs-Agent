package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// ensureDockerOnPATH appends the locations Synology keeps docker/compose under,
// so exec.LookPath finds them regardless of the (often restricted) inherited PATH.
func ensureDockerOnPATH() {
	extra := []string{
		"/usr/local/bin",
		"/var/packages/Docker/target/usr/bin",
		"/var/packages/ContainerManager/target/usr/bin",
	}
	cur := os.Getenv("PATH")
	parts := strings.Split(cur, ":")
	for _, e := range extra {
		if !strings.Contains(cur, e) {
			parts = append(parts, e)
		}
	}
	os.Setenv("PATH", strings.Join(parts, ":"))
}

func main() {
	ensureDockerOnPATH()
	cfg := loadConfig()

	if len(cfg.TrustedPublicKeys) == 0 {
		log.Println("[warn] NASHUBS_TRUSTED_PUBKEY not set — no client can authenticate")
	}
	if cfg.PairingSecret == "" {
		log.Println("[warn] NASHUBS_PAIRING_SECRET not set — /pair will be rejected")
	}

	cert, fp, err := ensureCert(cfg.DataDir)
	if err != nil {
		log.Fatalf("ensure cert: %v", err)
	}

	s := &server{
		cfg:             cfg,
		nonces:          newNonceCache(),
		certFingerprint: fp,
		composeArgs:     detectCompose(),
		devices:         newDeviceStore(cfg.DataDir),
		startedAt:       time.Now(),
		// Allow a handful of pairing attempts per client IP within the window
		// (the app retries while the container boots).
		pairLimiter: newRateLimiter(10, 5*time.Minute),
	}
	log.Printf("using compose: %v", s.composeArgs)

	// Parsed by the app from the Task Scheduler output after bootstrap.
	fmt.Printf("NASHUBS_CERT_FINGERPRINT=%s\n", fp)
	fmt.Printf("NASHUBS_VERSION=%s\n", cfg.Version)

	// Ensure the agent is accessible via Synology Reverse Proxy / Cloudflare Tunnel
	s.ensureSelfProxy()
	// Restore reverse proxy configs for all deployed mini-apps
	s.ensureAllProxies()

	addr := ":" + cfg.Port
	log.Printf("nashubs-agent listening on https://0.0.0.0%s (TLS pinned by fingerprint)", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: s.routes(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
	}
	// Empty cert/key paths → use TLSConfig.Certificates.
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("server: %v", err)
	}
}
