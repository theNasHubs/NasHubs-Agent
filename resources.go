package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func readCPU() (total, idle uint64, err error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	fields := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, fmt.Errorf("cpu unavailable")
	}
	// guest/guest_nice (columns 9+) are already included in user/nice.
	for i, v := range fields[1:] {
		if i >= 8 {
			break
		}
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil {
			return 0, 0, e
		}
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return total, idle, nil
}

func readMemory() (total, available uint64, err error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, err
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			n, e := strconv.ParseUint(f[1], 10, 64)
			if e == nil {
				values[strings.TrimSuffix(f[0], ":")] = n * 1024
			}
		}
	}
	total = values["MemTotal"]
	available = values["MemAvailable"]
	if _, ok := values["MemAvailable"]; !ok {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	if total == 0 {
		return 0, 0, fmt.Errorf("memory unavailable")
	}
	if available > total {
		available = total
	}
	return total, available, nil
}

// Host kernel procfs + mounted volume stats; no DSM session or SYNO API.
func (s *server) handleResources(w http.ResponseWriter, r *http.Request) {
	total, idle, err := readCPU()
	if err != nil {
		writeJSON(w, 503, errMap("resources unavailable", nil))
		return
	}
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return
	case <-timer.C:
	}
	next, nextIdle, err := readCPU()
	if err != nil || next <= total || nextIdle < idle {
		writeJSON(w, 503, errMap("resources unavailable", nil))
		return
	}
	cpu := 100 * (1 - float64(nextIdle-idle)/float64(next-total))
	if cpu < 0 {
		cpu = 0
	}
	if cpu > 100 {
		cpu = 100
	}
	mem, available, err := readMemory()
	if err != nil {
		writeJSON(w, 503, errMap("resources unavailable", nil))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "sampledAt": time.Now().UTC().Format(time.RFC3339),
		"cpu": map[string]any{"usagePercent": cpu}, "memory": map[string]any{"totalBytes": mem, "availableBytes": available, "usagePercent": 100 * float64(mem-available) / float64(mem)}})
}
