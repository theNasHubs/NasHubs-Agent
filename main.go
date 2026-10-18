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
	if len(os.Args) > 1 && os.Args[1] == "invite" {
		if err := runInvitationCLI(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	ensureDockerOnPATH()
	cfg := loadConfig()

	if len(cfg.TrustedPublicKeys) == 0 {
		log.Println("[warn] No bootstrap key — enrolled devices may reconnect; root can issue an invitation")
	}
	if cfg.PairingSecret == "" {
		log.Println("[warn] No legacy bootstrap secret — use invitations for new devices")
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
	s.invitations = newInvitationStore(cfg.DataDir)
	closeControl, err := s.startControl()
	if err != nil {
		log.Fatalf("local control: %v", err)
	}
	defer closeControl()

	// Parsed by the app from the Task Scheduler output after bootstrap.
	fmt.Printf("NASHUBS_CERT_FINGERPRINT=%s\n", fp)
	fmt.Printf("NASHUBS_VERSION=%s\n", cfg.Version)

	// Ensure the agent is accessible via Synology Reverse Proxy / Cloudflare Tunnel
	if cfg.AutoProxy {
		s.ensureSelfProxy()
	}
	// Restore reverse proxy configs for all deployed mini-apps
	if cfg.AutoProxy {
		s.ensureAllProxies()
	}

	addr := ":" + cfg.Port
	log.Printf("nashubs-agent listening on https://0.0.0.0%s (TLS pinned by fingerprint)", addr)

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
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
