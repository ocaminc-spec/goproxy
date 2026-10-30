// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLiveRingAndStats(t *testing.T) {
	ck := &clock{time.Date(2026, 10, 29, 16, 0, 0, 0, time.Local)}
	l := NewLive()
	l.now = ck.now
	var c liveSnap
	l.Sample(c) // prime
	for i := 0; i < 150; i++ {
		ck.t = ck.t.Add(time.Second)
		c.q += 100
		c.hits += 80
		c.misses += 20
		c.fail += 2
		c.hist[1] += 90 // 0.1-0.5 ms
		c.hist[8] += 10 // 100-250 ms
		l.Sample(c)
	}
	p := l.Points()
	if len(p) != liveKeep {
		t.Fatal("ring size", len(p))
	}
	x := p[len(p)-1]
	if x.QPS != 100 || x.HitPct != 80 || x.FailPS != 2 || x.Answers != 100 || x.T != ck.t.Unix() {
		t.Fatalf("%+v", x)
	}
	if want := (90*0.3 + 10*175.0) / 100; x.AvgMS < want-1e-9 || x.AvgMS > want+1e-9 {
		t.Fatal("avg", x.AvgMS, want)
	}
	if x.P95MS != 250 {
		t.Fatal("p95", x.P95MS)
	}
	if p[0].T != ck.t.Unix()-liveKeep+1 {
		t.Fatal("oldest point")
	}
	// a gap (nobody watching) drops old points instead of drawing a fake line
	ck.t = ck.t.Add(time.Minute)
	l.Sample(c)
	if len(l.Points()) != 0 {
		t.Fatal("stale points kept after gap")
	}
	ck.t = ck.t.Add(time.Second)
	c.q += 5
	l.Sample(c)
	if pts := l.Points(); len(pts) != 1 || pts[0].QPS != 5 || pts[0].AvgMS != 0 || pts[0].HitPct != 0 {
		t.Fatalf("after resume %+v", pts)
	}
}

func TestLiveIdleWhenUnwatched(t *testing.T) {
	ck := &clock{time.Date(2026, 10, 29, 16, 0, 0, 0, time.Local)}
	l := NewLive()
	l.now = ck.now
	if l.Active() {
		t.Fatal("active before any viewer")
	}
	l.Touch()
	ck.t = ck.t.Add(29 * time.Second)
	if !l.Active() {
		t.Fatal("should be active while watched")
	}
	ck.t = ck.t.Add(2 * time.Second)
	if l.Active() {
		t.Fatal("should go idle 30 s after the last poll")
	}
}

func TestLiveEndpointJSONAndAuth(t *testing.T) {
	s := &DNSServer{}
	rec := httptest.NewRecorder()
	s.serveHealthLive(rec, httptest.NewRequest("GET", "/api/health/live", nil))
	if rec.Code != 503 {
		t.Fatal("nil live should 503", rec.Code)
	}
	l := NewLive()
	rec = httptest.NewRecorder()
	serveLiveJSON(l, rec)
	var j struct {
		Step   int         `json:"step_sec"`
		Keep   int         `json:"keep"`
		Points []LivePoint `json:"points"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil || j.Step != 1 || j.Keep != liveKeep || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("json", err, j)
	}
	if publicPath(httptest.NewRequest("GET", "/api/health/live", nil)) {
		t.Fatal("/api/health/live must require login")
	}
}
