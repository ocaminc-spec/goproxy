// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func v27Env(t *testing.T) (*DNSServer, *V24, *V27) {
	s, st, au := adsServer(t)
	s.alerts = NewAlerts(st, nil)
	s.alerts.toast = nil
	s.flight = NewFlight(16, time.Minute, t.TempDir())
	v := &V24{s: s, audit: au, started: Settings{}}
	x := NewV27(v)
	return s, v, x
}

func TestV27DefaultsAllOff(t *testing.T) {
	var c V27Config
	if c.BlockOn || webhookReady(c) || c.slowMs() != 300 || c.failPct() != 20 {
		t.Fatal("bad defaults")
	}
	if (Settings{}).Feature("device_volume") {
		t.Fatal("device_volume must default off")
	}
	if len(c.lists()) != 2 || !strings.Contains(c.lists()[0], "StevenBlack") || !strings.Contains(c.lists()[1], "oisd") {
		t.Fatal(c.lists())
	}
}

func TestV27BlockingSubscriptionsOnOff(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "0.0.0.0 ads.one\n0.0.0.0 track.two\n")
	}))
	defer srv.Close()
	bl := NewBlocklist(nil, nil, nil)
	bl.Enabled = false
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go bl.Run(ctx, time.Hour)
	if bl.SetSources(false, []string{srv.URL}, nil, nil) || hits.Load() != 0 {
		t.Fatal("downloaded while off")
	}
	if !bl.SetSources(true, []string{srv.URL}, []string{"track.two"}, []string{"extra.bad"}) {
		t.Fatal("switching on must refresh")
	}
	deadline := time.Now().Add(3 * time.Second)
	for !bl.Blocked("ads.one") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !bl.Blocked("ads.one") || bl.Blocked("track.two") || !bl.Blocked("extra.bad") {
		t.Fatal("lists not applied")
	}
	bl.SetSources(false, []string{srv.URL}, nil, nil)
	if bl.Blocked("ads.one") {
		t.Fatal("blocking after off")
	}
}

func TestV27DeviceRulesGatedAndBedtime(t *testing.T) {
	s, _, _ := v27Env(t)
	st := Settings{V27: V27Config{DeviceRules: []DeviceRule{{IP: "192.168.1.50", Block: true},
		{IP: "192.168.1.51", Bedtime: []adsSchedule{{Target: "192.168.1.51", Mode: "on", From: "22:00", To: "07:00"}}}}}}
	s.applyV27(st)
	if s.deviceBlocked("192.168.1.50", time.Now()) {
		t.Fatal("rules enforced with the approval flag off")
	}
	st.Features = map[string]bool{"device_volume": true}
	s.applyV27(st)
	night := time.Date(2026, 10, 29, 23, 0, 0, 0, time.Local)
	day := time.Date(2026, 10, 29, 12, 0, 0, 0, time.Local)
	if !s.deviceBlocked("192.168.1.50", day) || !s.deviceBlocked("192.168.1.51", night) || s.deviceBlocked("192.168.1.51", day) || s.deviceBlocked("192.168.1.9", night) {
		t.Fatal("rule logic")
	}
	if validateV27(&V27Config{DeviceRules: []DeviceRule{{IP: "nope"}}}) == nil || validateV27(&V27Config{WebhookKind: "smtp"}) == nil {
		t.Fatal("bad config accepted")
	}
}

func TestV27WebhookKindsAndRateLimit(t *testing.T) {
	var got []*http.Request
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got, bodies = append(got, r), append(bodies, string(b))
	}))
	defer srv.Close()
	h := NewWebhook()
	if h.Send(V27Config{WebhookURL: srv.URL}, "k", "T", "M", false) == nil {
		t.Fatal("sent while off")
	}
	c := V27Config{WebhookOn: true, WebhookURL: srv.URL, WebhookToken: "tok123"}
	_ = h.Send(c, "a", "Title", "msg", false)
	_ = h.Send(c, "a", "Title", "msg", false) // rate limited
	c.WebhookKind, c.WebhookUser = "pushover", "user1"
	_ = h.Send(c, "b", "T2", "m2", false)
	c.WebhookKind = "json"
	_ = h.Send(c, "c", "T3", "m3", false)
	if len(got) != 3 {
		t.Fatalf("sends: %d", len(got))
	}
	if got[0].Header.Get("Title") != "Title" || got[0].Header.Get("Authorization") != "Bearer tok123" || bodies[0] != "msg" {
		t.Fatal("ntfy format")
	}
	if !strings.Contains(bodies[1], "user=user1") || !strings.Contains(bodies[1], "token=tok123") {
		t.Fatal("pushover format")
	}
	if !strings.Contains(bodies[2], `"title":"T3"`) {
		t.Fatal("json format")
	}
}

func TestV27SecretsSealedAndMasked(t *testing.T) {
	s, _, _ := v27Env(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	_, _, err := s.settings.Update("t", "t", func(st *Settings) error {
		st.V27.WebhookURL, st.V27.WebhookToken = "https://ntfy.example/secret-topic-xyz", "tok-secret-abc"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(s.settings.path)
	if bytes.Contains(raw, []byte("secret-topic-xyz")) || bytes.Contains(raw, []byte("tok-secret-abc")) {
		t.Fatal("webhook secrets stored in clear")
	}
	st2 := &settingsStore{path: s.settings.path}
	got, _ := st2.Load()
	if got.V27.WebhookURL != "https://ntfy.example/secret-topic-xyz" {
		t.Fatal("not reopened")
	}
	m := maskV27(got.V27)
	if strings.Contains(m.WebhookURL+m.WebhookToken, "secret") {
		t.Fatal("not masked")
	}
	if strings.Contains(buf.String(), "secret-topic") || strings.Contains(buf.String(), "tok-secret") {
		t.Fatal("secret logged")
	}
}

func TestV27SyncNewestWins(t *testing.T) {
	_, _, x := v27Env(t)
	x.v.s.settings.Update("t", "t", func(st *Settings) error {
		st.PeerToken, st.Peers = strings.Repeat("p", 20), []PeerEntry{{Name: "syn", URL: "http://192.168.1.75:8080"}}
		return nil
	})
	now := time.UnixMilli(1_800_000_000_000)
	x.now = func() time.Time { return now }
	remote := syncState{Stamp: 0, Data: syncOf(x.v.s.settings.Get())}
	remote.Data.BlockDeny = []string{"remote.bad"}
	x.call = func(ctx context.Context, p PeerEntry, tok, m, path string, out any) error {
		*(out.(*syncState)) = remote
		return nil
	}
	x.RunOnce(context.Background(), false) // first run: both stamps 0, nothing adopted
	if len(x.v.s.settings.Get().V27.BlockDeny) != 0 || x.v.s.settings.Get().V27.SyncStamp != 0 {
		t.Fatal("first run must not override")
	}
	remote.Stamp = now.UnixMilli() + 5
	x.RunOnce(context.Background(), false)
	if g := x.v.s.settings.Get().V27; len(g.BlockDeny) != 1 || g.SyncFrom != "syn" {
		t.Fatal("newer remote not adopted")
	}
	// local change later -> ours is newer; an older remote is ignored
	now = now.Add(time.Minute)
	x.v.s.settings.Update("t", "t", func(st *Settings) error { st.V27.BlockDeny = []string{"local.bad"}; return nil })
	x.RunOnce(context.Background(), false)
	if g := x.v.s.settings.Get().V27; g.BlockDeny[0] != "local.bad" || g.SyncStamp != now.UnixMilli() {
		t.Fatal("older remote overrode a newer local change")
	}
	// secrets never travel
	if strings.Contains(string(mustJSON(syncOf(x.v.s.settings.Get()))), strings.Repeat("p", 20)) {
		t.Fatal("peer token in sync data")
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestV27PeerWatchAlert(t *testing.T) {
	_, _, x := v27Env(t)
	p := PeerEntry{Name: "syn"}
	for i := 0; i < 2; i++ {
		x.watch(p, errors.New("down"))
	}
	if len(x.v.s.alerts.Active()) != 0 {
		t.Fatal("alert too early")
	}
	x.watch(p, errors.New("down"))
	if a := x.v.s.alerts.Active(); len(a) != 1 || a[0].Key != "v27:peer:syn" {
		t.Fatal("no peer alert", a)
	}
	x.watch(p, nil)
	if len(x.v.s.alerts.Active()) != 0 {
		t.Fatal("not cleared")
	}
}

func TestV27BackupRotatesSeven(t *testing.T) {
	_, _, x := v27Env(t)
	x.v.s.settings.Update("t", "t", func(st *Settings) error { st.V27.WebhookToken = "tok-secret-abc"; return nil })
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	base := time.Date(2026, 10, 1, 3, 30, 0, 0, time.Local)
	for i := 0; i < 9; i++ {
		d := base.AddDate(0, 0, i)
		x.now = func() time.Time { return d }
		if !x.backupDue() {
			t.Fatal("backup should be due")
		}
		if _, n, err := x.BackupNow(); err != nil || n < 1 {
			t.Fatal(err, n)
		}
		if x.backupDue() {
			t.Fatal("second backup same day")
		}
	}
	b := x.Backups()
	if len(b) != 7 || !strings.HasPrefix(b[0].Name, "2026-10-09") {
		t.Fatal(len(b), b[0].Name)
	}
	fi, _ := os.Stat(filepath.Join(x.backups, b[0].Name, "goproxy-settings.json"))
	if fi == nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("backup file perms")
	}
	if strings.Contains(buf.String(), "tok-secret") {
		t.Fatal("secret logged")
	}
}

func TestV27InsightsTopFeedRace(t *testing.T) {
	in := NewInsights()
	now := time.Unix(1_800_000_000, 0)
	in.now = func() time.Time { return now }
	in.RecordName("a.com") // not watched: ignored
	if _, n := in.Top(1, 5); n != 0 {
		t.Fatal("recorded while not watched")
	}
	in.Touch()
	for i := 0; i < 3; i++ {
		in.RecordName("a.com")
	}
	in.RecordName("b.com")
	now = now.Add(2 * time.Minute)
	in.Touch()
	in.RecordName("b.com")
	r1, _ := in.Top(1, 5)
	r5, n5 := in.Top(5, 5)
	if len(r1) != 1 || r1[0].Name != "b.com" || r5[0].Name != "a.com" || n5 != 5 {
		t.Fatal(r1, r5, n5)
	}
	for i := 0; i < 250; i++ {
		in.RecordFeed(feedItem{T: int64(i + 1), Name: "x", Result: "blocked"})
	}
	if f := in.Feed(0, 500); len(f) != 200 {
		t.Fatal(len(f))
	}
	if f := in.Feed(245, 50); len(f) != 5 {
		t.Fatal(len(f))
	}
	in.SampleRace(map[string]raceSnap{"google": {}, "cloudflare": {}})
	now = now.Add(time.Second)
	in.SampleRace(map[string]raceSnap{"google": {wins: 3, latSum: 30e6, latN: 3}, "cloudflare": {wins: 1, latSum: 20e6, latN: 1}})
	r := in.Race()
	if len(r) != 1 || r[0].Ups["google"].Share != 0.75 || r[0].Ups["cloudflare"].AvgMS != 20 {
		t.Fatal(r)
	}
}

func TestV27SlowAlertFromHist(t *testing.T) {
	s, _, _ := v27Env(t)
	var h [11]int64
	h[9] = 100 // all answers 250..1000 ms
	if p := histP95(h); p <= 300 {
		t.Fatal(p)
	}
	h = [11]int64{}
	h[3] = 100
	if p := histP95(h); p > 10 {
		t.Fatal(p)
	}
	s.checkServer() // no traffic: no alert
	if len(s.alerts.Active()) != 0 {
		t.Fatal("alert without data")
	}
}

func TestV27LiveClientsCountOnly(t *testing.T) {
	s, _, _ := v27Env(t)
	s.live = NewLive()
	s.live.SeeClient("192.168.1.9") // not watched: ignored
	rec := httptest.NewRecorder()
	s.serveHealthLive(rec, httptest.NewRequest("GET", "/api/health/live", nil))
	for _, ip := range []string{"192.168.1.2", "192.168.1.3", "192.168.1.2"} {
		s.live.SeeClient(ip)
	}
	if n := s.live.act.Count(time.Now()); n != 2 {
		t.Fatal(n)
	}
	if n := s.live.act.Count(time.Now().Add(61 * time.Second)); n != 0 {
		t.Fatal("not pruned", n)
	}
	s.live.SeeClient("192.168.1.2")
	rec = httptest.NewRecorder()
	s.serveHealthLive(rec, httptest.NewRequest("GET", "/api/health/live", nil))
	if strings.Contains(rec.Body.String(), "192.168.1.2") {
		t.Fatal("client IP shown without the approval flag")
	}
	s.settings.Update("t", "t", func(st *Settings) error { st.Features = map[string]bool{"device_volume": true}; return nil })
	rec = httptest.NewRecorder()
	s.serveHealthLive(rec, httptest.NewRequest("GET", "/api/health/live", nil))
	if !strings.Contains(rec.Body.String(), "192.168.1.2") {
		t.Fatal("client list missing with flag on")
	}
}

func TestV27ResourceSampler(t *testing.T) {
	r := newResSampler()
	t0 := time.Now()
	r.sample(t0)
	x := 0
	for i := 0; i < 3_000_000; i++ {
		x += i % 7
	}
	_ = x
	p, h, m, hm := r.sample(t0.Add(500 * time.Millisecond))
	if m <= 0 || p < 0 || p > 100 || h > 100 || hm > 100 {
		t.Fatal(p, h, m, hm)
	}
}

func TestV27EndpointsNeedLogin(t *testing.T) {
	for _, p := range []string{"/api/v27/config", "/api/v27/sync", "/api/v27/backup", "/api/v27/webhook/test", "/api/v27/devices/live", "/api/v27/insights", "/v27.js"} {
		if strings.HasPrefix(p, "/api") && publicPath(httptest.NewRequest("GET", p, nil)) {
			t.Fatal("public:", p)
		}
	}
}
