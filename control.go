package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The local control socket is root-only (0600), deliberately outside the public
// TLS API. SSH/sudo administrators can invite a device without rewriting JSON,
// exposing a permanent token, or restarting the Agent.
func (s *server) startControl() (func(), error) {
	path := filepath.Join(s.cfg.DataDir, "control.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("control path is not a socket")
		}
		c, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			c.Close()
			return nil, fmt.Errorf("another agent is using the data directory")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	// Unix sockets are created with restrictive permissions from the outset.
	old := setControlUmask()
	defer restoreControlUmask(old)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /invitation", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		s.createInvitation(w, r, true)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second}
	go srv.Serve(l)
	return func() { srv.Close(); os.Remove(path) }, nil
}

func runInvitationCLI(args []string) error {
	flags := flag.NewFlagSet("invite", flag.ContinueOnError)
	role := flags.String("role", "admin", "admin, viewer, or owner (root recovery only)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	c := loadConfig()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(c.DataDir, "control.sock"))
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	b, _ := json.Marshal(map[string]string{"role": *role})
	resp, err := client.Post("http://local/invitation", "application/json", strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("invitation failed: HTTP %d", resp.StatusCode)
	}
	_, err = io.Copy(os.Stdout, io.LimitReader(resp.Body, 4096))
	return err
}
