// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func adsServer(t *testing.T) (*DNSServer, *settingsStore, *Audit) {
	var calls atomic.Int64
	s := newTestServer(t, "7.7.7.7", &calls, nil)
	s.pinned = NewPinned(splitList(defaultPinned), []string{"googlevideo.com"})
	s.neverBlock = append([]string{"googlevideo.com", "nflxvideo.net"}, connectivityNames...)
	st := newStore(t)
	au := NewAudit(filepath.Join(filepath.Dir(st.path), "goproxy-audit.jsonl"), func() int { return 90 })
	st.audit = au.Add
	s.settings = st
	al := NewAlerts(st, nil)
	al.toast = nil
	s.devices = NewDevices(filepath.Join(t.TempDir(), "g.json"), st, al)
	return s, st, au
}

func adsBlocked(s *DNSServer, name, ip string) bool {
	_, res, _ := s.HandleFrom(q(name), ip)
	return res == "blocked"
}

func TestAdsFilterOffByDefault(t *testing.T) {
	s, st, _ := adsServer(t)
	s.ads.Apply(st.Get())
	for _, n := range []string{"doubleclick.net.", "googleads.g.doubleclick.net.", "app-measurement.com."} {
		if adsBlocked(s, n, "192.168.1.10") {
			t.Fatalf("%s blocked while the filter is off (default)", n)
		}
	}
	if (Settings{}).AdsFilter {
		t.Fatal("default must be off")
	}
}

func TestAdsFilterGlobalListAndAnalyticsSubToggle(t *testing.T) {
	s, _, _ := adsServer(t)
	s.ads.Apply(Settings{AdsFilter: true})
	for _, n := range []string{"doubleclick.net.", "googleads.g.doubleclick.net.", "pagead2.googlesyndication.com.", "googleadservices.com.",
		"adservice.google.com.", "ad.doubleclick.net.", "static.doubleclick.net.", "stats.g.doubleclick.net.", "x.googlesyndication.com.", "app-measurement.com."} {
		if !adsBlocked(s, n, "192.168.1.10") {
			t.Fatalf("%s not blocked", n)
		}
	}
	if adsBlocked(s, "imasdk.googleapis.com.", "192.168.1.10") {
		t.Fatal("imasdk.googleapis.com must never be blocked (breaks video players)")
	}
	if adsBlocked(s, "www.google-analytics.com.", "192.168.1.10") {
		t.Fatal("analytics blocked without the sub-switch")
	}
	s.ads.Apply(Settings{AdsFilter: true, AdsAnalytics: true, AdsExtra: "tracker.example"})
	if !adsBlocked(s, "www.google-analytics.com.", "192.168.1.10") || !adsBlocked(s, "a.tracker.example.", "1.2.3.4") {
		t.Fatal("analytics / extra not blocked")
	}
	if got := s.ads.Days(1)[0].Count; got < 12 {
		t.Fatalf("daily count %d", got)
	}
}

// Pinned YouTube / Netflix / googlevideo / connectivity names always win over the filter.
func TestAdsFilterPinnedAlwaysWins(t *testing.T) {
	s, _, _ := adsServer(t)
	// even if a user (or a bad list) adds them to the extra list
	cfg := Settings{AdsFilter: true, AdsAnalytics: true, AdsExtra: "youtube.com,googlevideo.com,netflix.com,gstatic.com,apple.com,google.com,googleapis.com,msftconnecttest.com"}
	s.ads.Apply(cfg)
	for _, n := range []string{"youtube.com.", "www.youtube.com.", "m.youtube.com.", "i.ytimg.com.", "youtubei.googleapis.com.",
		"rr3---sn-abc.googlevideo.com.", "netflix.com.", "www.netflix.com.", "api-global.netflix.com.", "ipv4-c001.nflxvideo.net.",
		"connectivitycheck.gstatic.com.", "clients3.google.com.", "captive.apple.com.", "www.msftconnecttest.com.", "detectportal.firefox.com.",
		"imasdk.googleapis.com."} {
		if adsBlocked(s, n, "192.168.1.10") {
			t.Fatalf("pinned/protected %s was blocked", n)
		}
	}
	if !adsBlocked(s, "adservice.google.com.", "192.168.1.10") {
		t.Fatal("adservice.google.com must still be blocked (protection must not cover parents)")
	}
	if err := validateAds(&Settings{AdsExtra: "youtube.com"}, s.protectedName); err == nil {
		t.Fatal("validation must reject a pinned name in the extra list")
	}
	if err := validateAds(&Settings{AdsExtra: "rr1.googlevideo.com"}, s.protectedName); err == nil {
		t.Fatal("validation must reject googlevideo")
	}
}

func TestAdsFilterPerClientAndGroup(t *testing.T) {
	s, _, _ := adsServer(t)
	grp := "Kids"
	if err := s.devices.Edit(deviceEdit{IP: "192.168.1.60", Group: &grp}); err != nil {
		t.Fatal(err)
	}
	// global OFF, one device ON
	s.ads.Apply(Settings{AdsClients: map[string]string{"192.168.1.50": "on"}})
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.50") || adsBlocked(s, "doubleclick.net.", "192.168.1.51") {
		t.Fatal("per-client on")
	}
	// IPv4-mapped IPv6 address of the same device
	if !adsBlocked(s, "doubleclick.net.", "::ffff:192.168.1.50") {
		t.Fatal("mapped address")
	}
	// global ON, one device OFF
	s.ads.Apply(Settings{AdsFilter: true, AdsClients: map[string]string{"192.168.1.50": "off"}})
	if adsBlocked(s, "doubleclick.net.", "192.168.1.50") || !adsBlocked(s, "doubleclick.net.", "192.168.1.51") {
		t.Fatal("per-client off")
	}
	// group ON, device in it follows; device override beats group
	s.ads.Apply(Settings{AdsGroups: map[string]string{"Kids": "on"}})
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.60") || adsBlocked(s, "doubleclick.net.", "192.168.1.61") {
		t.Fatal("group on")
	}
	s.ads.Apply(Settings{AdsGroups: map[string]string{"Kids": "on"}, AdsClients: map[string]string{"192.168.1.60": "off"}})
	if adsBlocked(s, "doubleclick.net.", "192.168.1.60") {
		t.Fatal("device override must beat group")
	}
	// pinned still wins for a device that is ON
	s.ads.Apply(Settings{AdsClients: map[string]string{"192.168.1.50": "on"}, AdsExtra: "ytimg.com"})
	if adsBlocked(s, "i.ytimg.com.", "192.168.1.50") {
		t.Fatal("pinned lost for a per-client ON device")
	}
}

func TestAdsFilterSchedule(t *testing.T) {
	s, _, _ := adsServer(t)
	now := time.Date(2026, 10, 17, 22, 0, 0, 0, time.Local) // Saturday 22:00
	s.ads.now = func() time.Time { return now }
	grp := "Kids"
	_ = s.devices.Edit(deviceEdit{IP: "192.168.1.60", Group: &grp})
	s.ads.Apply(Settings{AdsSchedules: []adsSchedule{{Target: "group:Kids", Mode: "on", From: "21:00", To: "07:00"}}})
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.60") {
		t.Fatal("night schedule should be on at 22:00")
	}
	now = time.Date(2026, 10, 18, 6, 59, 0, 0, time.Local)
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.60") {
		t.Fatal("still on at 06:59 (wraps midnight)")
	}
	now = time.Date(2026, 10, 18, 12, 0, 0, 0, time.Local)
	if adsBlocked(s, "doubleclick.net.", "192.168.1.60") {
		t.Fatal("off at noon")
	}
	// days: Saturday-night window only
	s.ads.Apply(Settings{AdsSchedules: []adsSchedule{{Target: "192.168.1.60", Mode: "on", From: "21:00", To: "07:00", Days: "sat"}}})
	now = time.Date(2026, 10, 18, 2, 0, 0, 0, time.Local) // Sunday 02:00, window began Saturday
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.60") {
		t.Fatal("window that started Saturday must count")
	}
	now = time.Date(2026, 10, 18, 22, 0, 0, 0, time.Local) // Sunday 22:00
	if adsBlocked(s, "doubleclick.net.", "192.168.1.60") {
		t.Fatal("Sunday not in days")
	}
	if validateAds(&Settings{AdsSchedules: []adsSchedule{{Target: "x", Mode: "on", From: "21:00", To: "07:00"}}}, nil) == nil {
		t.Fatal("bad target accepted")
	}
	if validateAds(&Settings{AdsSchedules: []adsSchedule{{Target: "192.168.1.1", Mode: "on", From: "25:00", To: "07:00"}}}, nil) == nil {
		t.Fatal("bad time accepted")
	}
}

// Toggles go through the settings store: config history (revertable) + audit log.
func TestAdsTogglesRecordedInHistoryAndAudit(t *testing.T) {
	s, st, au := adsServer(t)
	v := &V24{s: s, audit: au, started: Settings{}}
	s.flight = NewFlight(16, time.Minute, t.TempDir())
	s.alerts = NewAlerts(st, nil)
	s.alerts.toast = nil
	post := func(h http.HandlerFunc, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/", bytes.NewReader(b))
		r.RemoteAddr = "192.168.1.5:1234"
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	if w := post(v.serveSettings, map[string]any{"ads_filter": true}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.9") {
		t.Fatal("global toggle not applied live")
	}
	if w := post(v.serveAdsClient, adsEdit{IP: "192.168.1.9", Mode: "off"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if adsBlocked(s, "doubleclick.net.", "192.168.1.9") {
		t.Fatal("per-client off not applied live")
	}
	if w := post(v.serveAdsClient, adsEdit{Group: "Kids", Mode: "on"}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if w := post(v.serveAdsClient, adsEdit{IP: "192.168.1.9", Mode: "maybe"}); w.Code != 400 {
		t.Fatal("bad mode accepted")
	}
	if w := post(v.serveSettings, map[string]any{"ads_extra": "youtube.com"}); w.Code != 400 {
		t.Fatal("pinned name accepted in extra list")
	}
	h := st.History()
	if len(h) != 3 {
		t.Fatalf("history %d", len(h))
	}
	all := ""
	for _, c := range h {
		all += strings.Join(c.Diff, ";") + "|"
	}
	for _, want := range []string{"ads_filter", "ads_clients.192.168.1.9", "ads_groups.Kids"} {
		if !strings.Contains(all, want) {
			t.Fatalf("%s missing from history: %s", want, all)
		}
	}
	aud := au.Last(10)
	if len(aud) < 3 || !strings.Contains(aud[1].Action+aud[0].Action, "Ads & Tracking") {
		t.Fatalf("audit: %+v", aud)
	}
	// revert the per-client change -> device follows global (on) again
	if _, err := st.Revert(h[1].ID, "test"); err != nil {
		t.Fatal(err)
	}
	s.ads.Apply(st.Get())
	if !adsBlocked(s, "doubleclick.net.", "192.168.1.9") {
		t.Fatal("revert")
	}
}
