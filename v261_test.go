// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthShortWindows(t *testing.T) {
	ck := &clock{time.Date(2026, 10, 29, 16, 0, 0, 0, time.Local)}
	h := NewHealth("")
	h.now = ck.now
	h.Sample(healthSnap{})
	var q int64
	for i := 0; i < 60; i++ { // 5 minutes of 5 s samples, 10 queries each, all fast hits
		ck.t = ck.t.Add(5 * time.Second)
		q += 10
		h.Sample(healthSnap{q: q, hits: q, timed: q, fast: q})
	}
	one := h.WindowView(5*time.Second, 12)
	if len(one) != 12 {
		t.Fatal(len(one))
	}
	for i, b := range one {
		if b.End-b.Start != 5 || b.Queries != 10 || b.Scores.Overall != 100 {
			t.Fatalf("1m bucket %d %+v", i, b)
		}
		if i > 0 && b.Start != one[i-1].End {
			t.Fatal("not contiguous")
		}
	}
	if one[11].Start != ck.t.Truncate(5*time.Second).Unix() {
		t.Fatal("last 1m bucket not current")
	}
	five := h.WindowView(15*time.Second, 20)
	var tot int64
	for _, b := range five {
		if b.End-b.Start != 15 {
			t.Fatal("5m step")
		}
		tot += b.Queries
	}
	if len(five) != 20 || tot != 580 { // window starts at 16:00:15; the 16:00:05 and :10 buckets fall before it
		t.Fatalf("5m %d %d", len(five), tot)
	}
	if five[10].Queries != 30 {
		t.Fatalf("15s bucket %+v", five[10])
	}
	if len(h.fine) != fineKeep {
		t.Fatal("ring not bounded", len(h.fine))
	}
	// old fine data drops out of the windows; 24 h view unaffected
	ck.t = ck.t.Add(2 * time.Minute)
	for _, b := range h.WindowView(5*time.Second, 12) {
		if b.Queries != 0 || b.Scores.Overall != -1 {
			t.Fatal("stale data in 1m view")
		}
	}
	var day int64
	for _, b := range h.View() {
		day += b.Queries
	}
	if day != 600 {
		t.Fatal("24h total", day)
	}
	h.AddCanary(1, 1)
	if v := h.WindowView(5*time.Second, 12); v[11].Scores.Canary != 50 {
		t.Fatal("canary in fine ring", v[11].Scores)
	}
}

func TestServeHealthWindowParam(t *testing.T) {
	h := NewHealth("")
	for _, c := range []struct {
		q   string
		w   string
		sec int
		n   int
	}{{"", "24h", 600, healthKeep}, {"?window=1m", "1m", 5, 12}, {"?window=5m", "5m", 15, 20}, {"?window=bogus", "24h", 600, healthKeep}} {
		rec := httptest.NewRecorder()
		serveHealthJSON(h, rec, httptest.NewRequest("GET", "/api/health"+c.q, nil))
		var j struct {
			Window    string            `json:"window"`
			BucketSec int               `json:"bucket_sec"`
			Buckets   []json.RawMessage `json:"buckets"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &j); err != nil {
			t.Fatal(err)
		}
		if j.Window != c.w || j.BucketSec != c.sec || len(j.Buckets) != c.n {
			t.Fatalf("%s: %+v n=%d", c.q, j.Window, len(j.Buckets))
		}
	}
}
