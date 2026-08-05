package main

import (
	"net/http"
	"os"
	"sort"
	"strings"
	"syscall"
)

// volumeInfo mô tả một volume dữ liệu của NAS mà agent nhìn thấy.
type volumeInfo struct {
	Path       string `json:"path"`       // ví dụ "/volume1"
	TotalBytes uint64 `json:"totalBytes"` // dung lượng tổng
	FreeBytes  uint64 `json:"freeBytes"`  // còn trống
}

// handleListVolumes liệt kê các volume Synology (/volume1, /volume2, …) mà
// container agent thấy được (nhờ bootstrap mount từng volume vào đúng path).
// App dùng danh sách này để người dùng chọn nơi cài mini-app.
func (s *server) handleListVolumes(w http.ResponseWriter, _ *http.Request) {
	out := []volumeInfo{}
	entries, err := os.ReadDir("/")
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if !e.IsDir() || !isVolumeDirName(name) {
				continue
			}
			path := "/" + name
			vi := volumeInfo{Path: path}
			var st syscall.Statfs_t
			if syscall.Statfs(path, &st) == nil {
				bs := uint64(st.Bsize)
				vi.TotalBytes = st.Blocks * bs
				vi.FreeBytes = st.Bavail * bs
			}
			out = append(out, vi)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "volumes": out})
}

// isVolumeDirName khớp "volume" + ít nhất một chữ số (volume1, volume2, …).
func isVolumeDirName(name string) bool {
	if !strings.HasPrefix(name, "volume") {
		return false
	}
	rest := name[len("volume"):]
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
