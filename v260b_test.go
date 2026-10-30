// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestV260SecretsEncryptedAtRest(t *testing.T) {
	_, st, _ := adsServer(t)
	if _, _, err := st.Update("t", "tok", func(s *Settings) error {
		s.PeerToken, s.NtfyToken = "peer-secret-0123456789", "tk_ntfysecret"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(st.path)
	if strings.Contains(string(raw), "peer-secret") || strings.Contains(string(raw), "ntfysecret") || !strings.Contains(string(raw), secretPrefix) {
		t.Fatalf("secret on disk: %s", raw)
	}
	fi, err := os.Stat(secretKeyPath(st.path))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	s2, _ := (&settingsStore{path: st.path}).Load()
	if s2.PeerToken != "peer-secret-0123456789" || s2.NtfyToken != "tk_ntfysecret" {
		t.Fatalf("round trip: %+v", s2)
	}
	for _, h := range st.History() {
		if strings.Contains(strings.Join(h.Diff, ";"), "peer-secret") {
			t.Fatal("secret in history diff")
		}
	}
}

func TestV260BlockingToggleKeepsSettings(t *testing.T) {
	s, st, _ := adsServer(t)
	_, _, _ = st.Update("t", "x", func(x *Settings) error { x.NtfyTopic = "keep_me"; return nil })
	s.setBlockingPaused(true, "t")
	if g := st.Get(); !g.BlockingPaused || g.NtfyTopic != "keep_me" {
		t.Fatalf("toggle wiped settings: %+v", g)
	}
}

func TestV260PeerAuth(t *testing.T) {
	s, st, _ := adsServer(t)
	_, _, _ = st.Update("t", "p", func(x *Settings) error { x.PeerToken = "0123456789abcdef-tok"; return nil })
	call := func(ip, tok string) int {
		r := httptest.NewRequest("GET", "/api/peer/status", nil)
		r.RemoteAddr = ip + ":5000"
		if tok != "" {
			r.Header.Set(peerHeader, tok)
		}
		w := httptest.NewRecorder()
		s.servePeerAPI(w, r)
		return w.Code
	}
	if c := call("192.168.1.108", "0123456789abcdef-tok"); c != 200 {
		t.Fatalf("good peer: %d", c)
	}
	for _, c := range [][2]string{{"192.168.1.108", "wrong-token-xxxxxxxx"}, {"192.168.1.108", ""}, {"8.8.8.8", "0123456789abcdef-tok"}} {
		if code := call(c[0], c[1]); code != 403 {
			t.Fatalf("%v allowed: %d", c, code)
		}
	}
	if validatePeers([]PeerEntry{{Name: "x", URL: "http://8.8.8.8:8053"}}) == nil {
		t.Fatal("public peer accepted")
	}
}

func TestV260PeerDownIsGraceful(t *testing.T) {
	s, st, _ := adsServer(t)
	_, _, _ = st.Update("t", "p", func(x *Settings) error {
		x.PeerToken = "0123456789abcdef-tok"
		x.Peers = []PeerEntry{{Name: "down", URL: "http://127.0.0.1:1"}}
		return nil
	})
	w := httptest.NewRecorder()
	t0 := time.Now()
	s.servePeers(w, httptest.NewRequest("GET", "/api/peers", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":false`) || time.Since(t0) > 4*time.Second {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}

func TestV260HealthLeaksNothing(t *testing.T) {
	s, _, _ := adsServer(t)
	w := httptest.NewRecorder()
	s.serveHealthz(w, httptest.NewRequest("GET", "/health", nil))
	if b := w.Body.String(); (b != "ok\n" && b != "degraded\n") || !publicPath(httptest.NewRequest("GET", "/health", nil)) {
		t.Fatalf("%q", b)
	}
}

func TestV260PlainFallbackOff(t *testing.T) {
	var c1, c2 atomic.Int64
	var bad atomic.Bool
	bad.Store(true)
	enc := NewUpstream(fakeUp(t, 0, "1.1.1.1", &c1, &bad), nil)
	plain := NewUpstream(fakeUp(t, 0, "8.8.8.8", &c2, nil), nil)
	rs := &Resolver{DoH: []*Upstream{enc}, Fallback: []*Upstream{plain}}
	if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("f.example."))); err != nil || u != plain {
		t.Fatalf("fallback on: %v %v", u, err)
	}
	rs.NoPlainFallback.Store(true)
	if _, u, _ := rs.Resolve(context.Background(), upstreamQuery(q("f2.example."))); u == plain {
		t.Fatal("plain used while fallback is off")
	}
}

func TestV260PreloadOrderAndProfile(t *testing.T) {
	got := preloadNames([]string{"A.com", "b.com"}, []string{"b.com", "c.com", "a.com."})
	if strings.Join(got, ",") != "a.com,b.com,c.com" {
		t.Fatalf("%v", got)
	}
	if p, err := profileFor("max"); err != nil || p.UDPListeners < 1 || p.WarmupRate <= 0 {
		t.Fatal(p, err)
	}
	if _, err := profileFor("bogus"); err == nil {
		t.Fatal("bad profile accepted")
	}
}

func TestV260DeviceVolume(t *testing.T) {
	d := NewDeviceVolume()
	now := time.Unix(1_800_000_000, 0)
	d.now = func() time.Time { return now }
	d.Record("192.168.1.9", false)
	if len(d.Snapshot(nil, 0)) != 0 {
		t.Fatal("off must record nothing")
	}
	d.On.Store(true)
	for i := 0; i < 10; i++ {
		d.Record("192.168.1.9", i%2 == 0)
	}
	now = now.Add(time.Minute)
	for i := 0; i < 300; i++ {
		d.Record("192.168.1.50", false)
	}
	now = now.Add(time.Minute)
	rows := d.Snapshot(func(ip string) string { return "n-" + ip }, 0)
	if len(rows) != 2 || rows[0].IP != "192.168.1.50" || !rows[0].Spike || rows[0].PerMin != 300 || rows[0].Name != "n-192.168.1.50" {
		t.Fatalf("%+v", rows)
	}
	if r := rows[1]; r.Hour != 10 || r.HourBlock != 5 || r.Day != 10 || r.Spike {
		t.Fatalf("%+v", r)
	}
	now = now.Add(25 * time.Hour)
	if len(d.Snapshot(nil, 0)) != 0 {
		t.Fatal("old buckets must expire")
	}
}

func TestV260Kuma(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/status-page/dns":
			_, _ = w.Write([]byte(`{"publicGroupList":[{"monitorList":[{"id":1,"name":"DNS primary server"},{"id":2,"name":"DNS NAS"}]}]}`))
		case "/api/status-page/heartbeat/dns":
			_, _ = w.Write([]byte(`{"heartbeatList":{"1":[{"status":1,"ping":4}],"2":[{"status":0,"ping":null,"msg":"timeout"}]},"uptimeList":{"1_24":0.999,"2_24":0.5}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()
	m, err := fetchKuma(context.Background(), ts.URL, "dns")
	if err != nil || len(m) != 2 || !*m[0].Up || m[0].PingMs != 4 || m[0].Uptime24h != 0.999 || *m[1].Up || m[1].Msg != "timeout" {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := fetchKuma(context.Background(), ts.URL, "nope"); err == nil {
		t.Fatal("missing page must error")
	}
	if validateKuma("http://8.8.8.8:3001", "dns") == nil || validateKuma("http://192.168.1.123:3001", "DNS!") == nil || validateKuma("http://192.168.1.123:3001", "dns") != nil {
		t.Fatal("validateKuma")
	}
}
