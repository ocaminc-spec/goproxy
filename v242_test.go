// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---------- signed releases ----------

func TestReleaseSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := append([]byte("MZ"), bytes.Repeat([]byte{7}, 2<<20)...)
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, bin))
	if st, err := verifyRelease(bin, sig, true, pub); err != nil || st != "signed" {
		t.Fatalf("good signature: %v %s", err, st)
	}
	bad := append([]byte{}, bin...)
	bad[100] ^= 1
	if _, err := verifyRelease(bad, sig, false, pub); err == nil || !strings.Contains(err.Error(), "does NOT match") {
		t.Fatalf("tampered file accepted even with require off: %v", err)
	}
	if st, err := verifyRelease(bin, "", false, pub); err != nil || st != "unsigned" {
		t.Fatal("unsigned must be accepted when not required (default)")
	}
	if _, err := verifyRelease(bin, "", true, pub); !errors.Is(err, errUnsigned) || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned must be refused with a clear error when required: %v", err)
	}
	if _, err := verifyRelease(bin, "!!", false, pub); err == nil {
		t.Fatal("damaged signature accepted")
	}
	// the signature travels inside the release zip
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("goproxy.exe")
	w.Write(bin)
	w, _ = zw.Create("goproxy.exe.sig")
	w.Write([]byte(sig + "\n"))
	zw.Close()
	if got := zipSignature(zb.Bytes()); got != sig {
		t.Fatal("signature not read from zip")
	}
	if len(releaseKey()) != ed25519.PublicKeySize {
		t.Fatal("embedded release key")
	}
}

// ---------- auto-rollback ----------

func TestAutoRollbackWatchable(t *testing.T) {
	now := time.Now()
	rec := lastUpdate{From: "2.4.1", To: "2.4.2", At: now.Add(-time.Minute).Format(time.RFC3339), Kind: "upload"}
	if _, ok := watchable(rec, "2.4.2", now); !ok {
		t.Fatal("fresh upload must be watched")
	}
	for _, k := range []string{"rollback", "auto-rollback", "restart"} {
		r := rec
		r.Kind = k
		if _, ok := watchable(r, "2.4.2", now); ok {
			t.Fatalf("%s must not be watched (no loops)", k)
		}
	}
	if _, ok := watchable(rec, "2.4.2", now.Add(5*time.Minute)); ok {
		t.Fatal("window is 5 minutes")
	}
	if _, ok := watchable(rec, "2.4.3", now); ok {
		t.Fatal("record for another version")
	}
}

func TestAutoRollbackDecision(t *testing.T) {
	base := time.Now()
	clockT := base
	mk := func(check func() error, selfTest func() bool, offline bool, enabled bool) rollbackProbe {
		return rollbackProbe{enabled: func() bool { return enabled }, check: check, selfTest: selfTest,
			offline: func() bool { return offline }, every: time.Millisecond,
			now: func() time.Time { clockT = clockT.Add(20 * time.Second); return clockT }}
	}
	end := base.Add(autoRollbackWindow)
	ok := func() error { return nil }
	fail := func() error { return errors.New("no answer") }
	good := func() bool { return true }
	bad := func() bool { return false }
	ctx := context.Background()
	if r := rollbackDecision(ctx, end, mk(ok, good, false, true)); r != "" {
		t.Fatalf("healthy version rolled back: %s", r)
	}
	clockT = base
	if r := rollbackDecision(ctx, end, mk(fail, good, false, true)); !strings.Contains(r, "3 times") {
		t.Fatalf("dead DNS not rolled back: %q", r)
	}
	clockT = base
	n := 0
	flaky := func() error {
		n++
		if n%3 == 0 {
			return nil
		}
		return errors.New("x")
	}
	if r := rollbackDecision(ctx, end, mk(flaky, good, false, true)); r != "" {
		t.Fatalf("2 failures then OK must not roll back: %s", r)
	}
	clockT = base
	if r := rollbackDecision(ctx, end, mk(ok, bad, false, true)); !strings.Contains(r, "self-test") {
		t.Fatalf("failing self-test not rolled back: %q", r)
	}
	clockT = base
	if r := rollbackDecision(ctx, end, mk(ok, bad, true, true)); r != "" {
		t.Fatal("internet outage must not cause a rollback")
	}
	clockT = base
	if r := rollbackDecision(ctx, end, mk(fail, bad, false, false)); r != "" {
		t.Fatal("feature off (default) must never roll back")
	}
	if (Settings{}).AutoRollback || (Settings{}).RequireSigned {
		t.Fatal("defaults must be off")
	}
}

// ---------- why lookup ----------

func TestWhyLookup(t *testing.T) {
	s, _, _ := adsServer(t)
	s.ads.Apply(Settings{AdsClients: map[string]string{"192.168.1.50": "on"}})
	s.Handle(q("example.org."))
	v := s.Why("googleads.g.doubleclick.net", "192.168.1.50")
	if !v.AdsListed || !v.AdsOn || !strings.Contains(v.Verdict, "Ads & Tracking") {
		t.Fatalf("%+v", v)
	}
	v = s.Why("googleads.g.doubleclick.net", "192.168.1.51")
	if v.AdsOn || !strings.Contains(v.Verdict, "answered normally") {
		t.Fatalf("other device: %+v", v)
	}
	v = s.Why("www.youtube.com", "192.168.1.50")
	if !v.Pinned || !v.Protected || v.Service != "YouTube" {
		t.Fatalf("pinned: %+v", v)
	}
	v = s.Why("example.org", "")
	if v.Cache[0].State != "fresh" || v.Cache[0].Answer != "7.7.7.7" {
		t.Fatalf("cache: %+v", v.Cache)
	}
	if v = s.Why("x.ads.example", ""); !v.Blocklist {
		t.Fatal("blocklist")
	}
	w := httptest.NewRecorder()
	s.serveWhy(w, httptest.NewRequest("GET", "/api/why?name=not%20a%20domain", nil))
	if w.Code != 400 {
		t.Fatal("bad name accepted")
	}
}

// ---------- weekly summary ----------

func TestWeeklySummary(t *testing.T) {
	s, st, _ := adsServer(t)
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.Local)
	s.ads.now = func() time.Time { return now }
	out := NewOutages(filepath.Join(t.TempDir(), "o.json"), st, nil)
	w := NewWeekly(filepath.Join(t.TempDir(), "w.json"), s, out)
	w.now = func() time.Time { return now }
	w.Sample()
	for i := 0; i < 5; i++ {
		s.ServeDNS(&fakeWriter{}, q("weekly.example."))
	}
	s.ads.Apply(Settings{AdsFilter: true})
	s.ServeDNS(&fakeWriter{}, q("doubleclick.net."))
	w.Sample()
	v := w.View()
	if len(v.Days) != 7 || v.Queries != 6 || v.Blocked != 1 || v.AdsBlocked != 1 {
		t.Fatalf("%+v", v)
	}
	if len(v.TopDomains) == 0 || v.TopDomains[0].Host != "weekly.example" || v.TopDomains[0].Requests != 5 {
		t.Fatalf("top: %+v", v.TopDomains)
	}
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	w2 := NewWeekly(w.path, s, out)
	w2.now = w.now
	if w2.View().Queries != 6 {
		t.Fatal("not persisted")
	}
}

// ---------- backup / restore ----------

func TestSettingsExportImport(t *testing.T) {
	s, st, au := adsServer(t)
	s.flight = NewFlight(16, time.Minute, t.TempDir())
	s.alerts = NewAlerts(st, nil)
	s.alerts.toast = nil
	v := &V24{s: s, audit: au}
	if _, _, err := st.Update("t", "setup", func(x *Settings) error {
		x.NtfyToken, x.NtfyTopic, x.AdsFilter = "tk_secret", "topic1", true
		x.LocalNames = map[string]string{"nas.home": "192.168.1.123"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	grp := "Kids"
	_ = s.devices.Edit(deviceEdit{IP: "192.168.1.60", Group: &grp})
	w := httptest.NewRecorder()
	v.serveExport(w, httptest.NewRequest("GET", "/api/settings/export", nil))
	body := w.Body.String()
	if strings.Contains(body, "tk_secret") || strings.Contains(body, "hash") {
		t.Fatal("secret in export")
	}
	var b settingsBackup
	if err := json.Unmarshal([]byte(body), &b); err != nil || !b.Settings.AdsFilter || b.Devices == nil {
		t.Fatalf("%v %+v", err, b)
	}
	// change things, then import the backup
	_, _, _ = st.Update("t", "change", func(x *Settings) error { x.AdsFilter = false; x.LocalNames = nil; return nil })
	post := func(remote string, body any) *httptest.ResponseRecorder {
		bb, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/settings/import", bytes.NewReader(bb))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		v.serveImport(w, r)
		return w
	}
	if w := post("66.229.219.10:5000", map[string]any{"backup": b}); w.Code != http.StatusForbidden {
		t.Fatal("import from a public address must be refused")
	}
	if w := post("192.168.1.5:5000", map[string]any{"backup": map[string]any{"app": "x"}}); w.Code != 400 {
		t.Fatal("non-backup accepted")
	}
	if w := post("192.168.1.5:5000", map[string]any{"backup": b, "with_devices": true}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cur := st.Get()
	if !cur.AdsFilter || cur.LocalNames["nas.home"] != "192.168.1.123" || cur.NtfyToken != "tk_secret" {
		t.Fatalf("import result %+v", cur)
	}
	if s.devices.groupOf("192.168.1.60") != "Kids" {
		t.Fatal("devices not imported")
	}
	h := st.History()
	if !strings.Contains(h[len(h)-1].What, "imported") {
		t.Fatal("import not in config history")
	}
	// a backup with a pinned name in the extra list is refused
	b.Settings.AdsExtra = "youtube.com"
	if w := post("192.168.1.5:5000", map[string]any{"backup": b}); w.Code != 400 {
		t.Fatal("invalid backup accepted")
	}
}

type fakeWriter struct{ out *dns.Msg }

func (f *fakeWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (f *fakeWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 168, 0, 70), Port: 5353}
}
func (f *fakeWriter) WriteMsg(m *dns.Msg) error   { f.out = m; return nil }
func (f *fakeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeWriter) Close() error                { return nil }
func (f *fakeWriter) TsigStatus() error           { return nil }
func (f *fakeWriter) TsigTimersOnly(bool)         {}
func (f *fakeWriter) Hijack()                     {}
