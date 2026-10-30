// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
)

// Container mode (v2.5.0, GP-03). Inside Docker the binary lives in a read-only image layer:
// swapping it in place would be lost on the next container re-create, could corrupt the
// layer, and a handover child would die with PID 1 (restart loop). So the self-updater,
// rollback and in-app restart are disabled; updates are done by pulling/building a new image.
//
// Detected by GOPROXY_CONTAINER=true|1|yes (set in docker-compose.yml) or by the files
// Docker (/.dockerenv) and Podman (/run/.containerenv) create. GOPROXY_CONTAINER=false
// forces it off.

var (
	containerOnce sync.Once
	containerVal  bool
	// containerHook overrides detection (tests only).
	containerHook    func() bool
	containerMarkers = []string{"/.dockerenv", "/run/.containerenv"}
)

func detectContainer(env string, exists func(string) bool) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	for _, p := range containerMarkers {
		if exists(p) {
			return true
		}
	}
	return false
}

func inContainer() bool {
	if containerHook != nil {
		return containerHook()
	}
	containerOnce.Do(func() {
		containerVal = detectContainer(os.Getenv("GOPROXY_CONTAINER"), func(p string) bool { _, err := os.Stat(p); return err == nil })
	})
	return containerVal
}

const containerUpdateMsg = "GoProxy is running in a container, so in-app updates, rollback and restart are disabled. " +
	"To update: build or pull the new image (docker build -f docker/Dockerfile -t goproxy:<version> .), change the image tag in docker-compose.yml, " +
	"then in Container Manager > Project > goproxy choose Build (or run: docker compose up -d). Your settings, cache and login in /data are kept. " +
	"To restart: Container Manager > Container > goproxy > Restart (or: docker restart goproxy)."

// containerRefuse answers 409 with guidance when running in a container.
func containerRefuse(w http.ResponseWriter) bool {
	if !inContainer() {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "container": true, "error": containerUpdateMsg})
	return true
}
