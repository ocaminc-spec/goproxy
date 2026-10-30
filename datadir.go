// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// dataDir holds everything GoProxy writes (cache snapshot, history, settings, health, auth,
// update record, log), kept apart from the program so an install under Program Files
// (read-only for services/users) works and the updater can swap the exe freely.
var dataDir = "."

// resolveDataDir picks the data folder:
//  1. -data-dir if given;
//  2. %ProgramData%\GoProxyDNS on Windows if it already exists (installer, v2.4) or the exe
//     lives under Program Files;
//  3. otherwise the exe's folder: the existing portable install (e.g. C:\GoProxyDNS) keeps
//     its cache, settings and login exactly where they are today.
func resolveDataDir(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	exe := exeDir()
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			d := filepath.Join(pd, "GoProxyDNS")
			if st, err := os.Stat(d); err == nil && st.IsDir() {
				return d
			}
			for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
				if pf := os.Getenv(env); pf != "" && strings.HasPrefix(strings.ToLower(exe), strings.ToLower(pf)+`\`) {
					return d
				}
			}
		}
	}
	return exe
}

func initDataDir(flagVal string) {
	dataDir = resolveDataDir(flagVal)
	_ = os.MkdirAll(dataDir, 0o755)
}
