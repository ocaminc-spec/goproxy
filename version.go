// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"runtime"
)

// Version is set at build time: -ldflags "-X main.Version=2.1.0".
var Version = "2.8.2"

//go:embed CHANGELOG.md
var changelog string

// versionMarkers is set by V28 (v2.8.1).
var versionMarkers func() []VersionMarker

func serveVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // v2.8.1: other home dashboards (dnsspeed) draw version markers
	out := map[string]any{"version": Version, "go": runtime.Version(), "os": runtime.GOOS + "/" + runtime.GOARCH}
	if r.URL.Query().Get("brief") == "" {
		out["changelog"] = changelog
	}
	if versionMarkers != nil {
		out["markers"] = versionMarkers() // [{version, t}] install times, no other data
	}
	_ = json.NewEncoder(w).Encode(out)
}

// Vendor is shown in -version, the dashboard footer and the Version tab.
var Vendor = "Ocam"

// VersionString is the full version line embedded in the binary.
func VersionString() string { return "GoProxy DNS " + Version + " by " + Vendor }
