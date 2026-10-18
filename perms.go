package main

import (
	"log"
	"os"
	"path/filepath"
)

// Files the agent keeps in DataDir can hold secrets (compose files with app
// tokens, enrolled device keys). DataDir is usually a shared folder, so they
// are written owner-only.
const privateFileMode os.FileMode = 0o600

// writePrivateFile writes data with mode 0600, also tightening a file that
// already existed with a looser mode (os.WriteFile only applies perm on create).
func writePrivateFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, privateFileMode); err != nil {
		return err
	}
	return os.Chmod(path, privateFileMode)
}

// tightenDataFilePerms chmods agent-owned files left by older versions with
// 0644 to 0600. It only touches the exact files the agent writes, never app
// data that may live under DataDir.
func tightenDataFilePerms(dataDir string) {
	paths := []string{
		filepath.Join(dataDir, "devices.json"),
		filepath.Join(dataDir, "agent.key"),
	}
	for _, pattern := range []string{
		filepath.Join(dataDir, "*", "state.json"),
		filepath.Join(dataDir, "*", "*", "docker-compose.yml"),
	} {
		m, _ := filepath.Glob(pattern)
		paths = append(paths, m...)
	}
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 == 0 {
			continue
		}
		if err := os.Chmod(p, privateFileMode); err != nil {
			log.Printf("[warn] chmod %s: %v", p, err)
		}
	}
}
