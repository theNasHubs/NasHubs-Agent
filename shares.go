package main

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// shareInfo is one top-level folder of a mounted /volumeN (a DSM shared folder).
type shareInfo struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Volume string `json:"volume"`
}

// listShares returns the user-visible top-level folders of every mounted
// /volumeN under root ("/" in production). System folders (@…, #…, lost+found,
// homes-style dot folders) are skipped. Symlinks are never followed.
func listShares(root string) []shareInfo {
	vols, _ := filepath.Glob(filepath.Join(root, "volume[0-9]*"))
	sort.Strings(vols)
	var out []shareInfo
	for _, v := range vols {
		vname := filepath.Base(v)
		if !bootstrapVolumePattern.MatchString("/" + vname) {
			continue
		}
		entries, err := os.ReadDir(v)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
				continue
			}
			if strings.HasPrefix(n, "@") || strings.HasPrefix(n, "#") || strings.HasPrefix(n, ".") || n == "lost+found" {
				continue
			}
			out = append(out, shareInfo{Name: n, Path: "/" + vname + "/" + n, Volume: "/" + vname})
		}
	}
	return out
}

// handleListShares lets the app offer real shared folders (video, music,
// photo, …) for media mounts instead of guessing paths.
func (s *server) handleListShares(w http.ResponseWriter, _ *http.Request) {
	shares := listShares(s.sharesRoot())
	if shares == nil {
		shares = []shareInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "appsDir": s.cfg.AppsDir, "shares": shares})
}

func (s *server) sharesRoot() string {
	if s.fsRoot != "" {
		return s.fsRoot
	}
	return "/"
}
