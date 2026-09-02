package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// mediaStatus is the stable, read-only contract consumed by NasHubs clients.
// Jellyfin remains an implementation detail of the Media Engine: clients do
// not need to inspect Docker or guess whether the setup wizard is complete.
type mediaStatus struct {
	Installed    bool   `json:"installed"`
	Running      bool   `json:"running"`
	Ready        bool   `json:"ready"`
	Configured   bool   `json:"configured"`
	State        string `json:"state"`
	InternalPort int   `json:"internalPort,omitempty"`
	PathPrefix  string `json:"pathPrefix,omitempty"`
	ServerName  string `json:"serverName,omitempty"`
	Version     string `json:"version,omitempty"`
}

type jellyfinPublicInfo struct {
	ServerName             string `json:"ServerName"`
	Version                string `json:"Version"`
	StartupWizardCompleted bool   `json:"StartupWizardCompleted"`
}

func mediaStatusFrom(state string, st deployState, info *jellyfinPublicInfo) mediaStatus {
	status := mediaStatus{
		Installed:    state != stMissing,
		Running:      state == stUp,
		State:        state,
		InternalPort: st.InternalPort,
		PathPrefix:   st.PathPrefix,
	}
	if info != nil {
		status.Ready = true
		status.Configured = info.StartupWizardCompleted
		status.ServerName = info.ServerName
		status.Version = info.Version
	}
	return status
}

func probeJellyfinPublicInfo(port int) (*jellyfinPublicInfo, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid internal port")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/System/Info/Public", port)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var info jellyfinPublicInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

func (s *server) handleMediaStatus(w http.ResponseWriter, _ *http.Request) {
	const id = "jellyfin"
	st, err := loadState(s.cfg.DataDir, id)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"media": mediaStatus{State: stMissing},
		})
		return
	}

	state := s.probeState(id, st.HostPath)
	var info *jellyfinPublicInfo
	if state == stUp {
		info, _ = probeJellyfinPublicInfo(st.InternalPort)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"media": mediaStatusFrom(state, st, info),
	})
}
