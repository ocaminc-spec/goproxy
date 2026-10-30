// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The v2.4.1 -> v2.4.2 failure, reproduced: the running exe is moved aside fine, but the
// freshly written + probed goproxy.new.exe is still held by the antivirus, so a single
// rename fails with exactly the message from the dashboard log.
func TestV241SwapFailsWhileAVHoldsNewExe(t *testing.T) {
	_, cur, _, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	fs.setScan(next, -1)
	if err := fs.Rename(cur, oldPath(cur)); err != nil {
		t.Fatal(err)
	}
	err := fs.Rename(next, cur)
	if err == nil || !strings.Contains(err.Error(), "rename "+next+" "+cur+": The process cannot access the file because it is being used by another process") {
		t.Fatalf("got %v", err)
	}
}

func TestInstallWaitsForScanner(t *testing.T) {
	fastSwap(t)
	_, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	fs.setScan(next, 20) // released after ~20 attempts
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	if content(t, cur) != "v2" || content(t, prev) != "v1" || !fs.locked[oldPath(cur)] {
		t.Fatalf("cur=%q prev=%q", content(t, cur), content(t, prev))
	}
	// the running exe must not have been touched until the new file could be renamed
	if fs.renames[0] != "goproxy.new.exe>goproxy.ready.exe" {
		t.Fatalf("order: %v", fs.renames)
	}
}

func TestInstallCopiesWhenStillLocked(t *testing.T) {
	fastSwap(t)
	_, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	fs.afterRename = func(from, to string) {
		if to == readyPath(cur) {
			fs.setScan(to, -1) // the scanner opens it again under its new name
		}
	}
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	if content(t, cur) != "v2" || content(t, prev) != "v1" || content(t, oldPath(cur)) != "v1" {
		t.Fatalf("cur=%q prev=%q old=%q", content(t, cur), content(t, prev), content(t, oldPath(cur)))
	}
}

func TestInstallGivesUpWithoutTouchingRunningExe(t *testing.T) {
	fastSwap(t)
	_, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	fs.setScan(next, -1)
	_, err := installExe(fs, cur, prev, next, true)
	if err == nil || !strings.Contains(err.Error(), "still in use") {
		t.Fatalf("err=%v", err)
	}
	if content(t, cur) != "v1" || !fs.locked[cur] || len(fs.renames) != 0 {
		t.Fatalf("running exe touched: %v", fs.renames)
	}
	if _, err := os.Stat(prev); err == nil {
		t.Fatal("prev should not be written before the new file is ready")
	}
}

// End to end through the dashboard's "Update from file" handler: POST /api/update/upload ->
// prepareSigned -> start -> apply (write goproxy.new.exe, probe it, save, installExe) with
// Windows semantics: the running exe is locked, and running the probe makes the
// "antivirus" hold goproxy.new.exe for a while (as on the owner's PC).
func TestDashboardUploadInstallsDespiteAVLock(t *testing.T) {
	fastSwap(t)
	dir := t.TempDir()
	cur, prev, next := filepath.Join(dir, "goproxy.exe"), filepath.Join(dir, "goproxy.prev.exe"), filepath.Join(dir, "goproxy.new.exe")
	os.WriteFile(cur, []byte("old exe"), 0o755)
	fs := &winFS{locked: map[string]bool{cur: true}}
	oldFS := exeFS
	exeFS = fs
	exePathsHook = func() (string, string, string) { return cur, prev, next }
	probed := 0
	probeHook = func(p string) (string, error) {
		if p != next {
			return "2.4.2", nil // the dashboard status probes goproxy.prev.exe
		}
		probed++
		fs.setScan(p, 40) // Defender scans the new .exe on first run
		return "2.4.3", nil
	}
	t.Cleanup(func() { exeFS, exePathsHook, probeHook = oldFS, nil, nil })

	s := zoneServer(t, nil)
	a := &App{s: s, cache: s.cache, stop: make(chan struct{})}
	u := NewUpdater(a, "", "", "")
	done := make(chan string, 1)
	u.afterInstall = func(c, ver, kind string, restore func()) error {
		done <- ver + " " + kind
		return nil
	}
	bin := append([]byte("MZ"), bytes.Repeat([]byte{7}, 2<<20)...)
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("file", "goproxy.exe")
	fw.Write(bin)
	mw.Close()
	r := httptest.NewRequest("POST", "/api/update/upload", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.RemoteAddr = "192.168.1.50:5000"
	w := httptest.NewRecorder()
	u.serveUpload(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("upload: %d %s", w.Code, w.Body.String())
	}
	select {
	case got := <-done:
		if got != "2.4.3 upload" {
			t.Fatal(got)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("not installed: %v", u.Status().Log)
	}
	if b, _ := os.ReadFile(cur); !bytes.Equal(b, bin) {
		t.Fatal("new exe not in place")
	}
	if content(t, prev) != "old exe" || content(t, oldPath(cur)) != "old exe" || !fs.locked[oldPath(cur)] {
		t.Fatal("prev/old wrong")
	}
	if probed != 1 {
		t.Fatalf("probed %d times", probed)
	}
	logs := strings.Join(u.Status().Log, "\n")
	if !strings.Contains(logs, "in use by another program") || strings.Contains(logs, "FAILED") {
		t.Fatalf("log:\n%s", logs)
	}
}
