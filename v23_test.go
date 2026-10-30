// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeBin() []byte { return append([]byte("MZ"), bytes.Repeat([]byte{1}, 2<<20)...) }

func TestPrepareSHAAndZip(t *testing.T) {
	b := fakeBin()
	sum := sha256.Sum256(b)
	if _, err := prepare(b, "goproxy.exe", hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if _, err := prepare(b, "goproxy.exe", strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("want mismatch, got %v", err)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("README-WINDOWS.txt")
	w.Write([]byte("hi"))
	w, _ = zw.Create("goproxy.exe")
	w.Write(b)
	zw.Close()
	zsum := sha256.Sum256(zb.Bytes())
	got, err := prepare(zb.Bytes(), "x.zip", hex.EncodeToString(zsum[:])+"  x.zip")
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("zip extract: %v", err)
	}
	if _, err := prepare([]byte("MZtiny"), "a.exe", ""); err == nil {
		t.Fatal("tiny file accepted")
	}
}

func TestNewerVersion(t *testing.T) {
	for _, c := range []struct {
		a, b string
		w    bool
	}{{"2.3.1", "2.3.0", true}, {"v2.10.0", "2.9.9", true}, {"2.3.0", "2.3.0", false}, {"2.2.0", "2.3.0-dev", false}} {
		if newerVersion(c.a, c.b) != c.w {
			t.Errorf("%s > %s should be %v", c.a, c.b, c.w)
		}
	}
}

func TestShutdownLocalOnly(t *testing.T) {
	a := &App{stop: make(chan struct{})}
	r := httptest.NewRequest("POST", "/api/shutdown", nil)
	r.RemoteAddr = "192.168.1.50:1234"
	w := httptest.NewRecorder()
	a.serveShutdown(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("LAN shutdown allowed: %d", w.Code)
	}
	r.RemoteAddr = "8.8.8.8:1"
	if trustedClient(r) {
		t.Fatal("public IP trusted for updates")
	}
	r.RemoteAddr = "192.168.1.50:1"
	if !trustedClient(r) {
		t.Fatal("LAN not trusted")
	}
}
