// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestHealthBucketsScoresAndPersist(t *testing.T) {
	ck := &clock{time.Date(2026, 10, 15, 17, 51, 0, 0, time.Local)}
	h := NewHealth(filepath.Join(t.TempDir(), "h.json"))
	h.now = ck.now
	h.Sample(healthSnap{})
	h.Sample(healthSnap{q: 1000, hits: 900, misses: 100, upq: 100, timed: 1000, fast: 1000})
	ck.t = ck.t.Add(10 * time.Minute)
	h.Sample(healthSnap{q: 2000, hits: 1000, misses: 1000, fail: 50, upq: 1000, uperr: 300, timed: 2000, fast: 1500, slow: 100})
	v := h.View()
	if len(v) != healthKeep {
		t.Fatal(len(v))
	}
	good, bad := v[len(v)-2].Scores, v[len(v)-1].Scores
	if good.Overall != 100 || good.Cache != 100 {
		t.Fatalf("good %+v", good)
	}
	if bad.Upstream != 33 || bad.Errors != 50 || bad.Overall > min(bad.Upstream, bad.Cache, bad.Latency, bad.Errors)+15 {
		t.Fatalf("bad %+v", bad)
	}
	if v[0].Scores.Overall != -1 || v[len(v)-2].Start != time.Date(2026, 10, 15, 17, 50, 0, 0, time.Local).Unix() {
		t.Fatal("alignment / empty buckets")
	}
	if err := h.Save(); err != nil {
		t.Fatal(err)
	}
	h2 := NewHealth(h.path)
	h2.now = ck.now
	if err := h2.Load(); err != nil || len(h2.View()) != healthKeep || h2.View()[healthKeep-1].Queries != 1000 {
		t.Fatal("not restored")
	}
	ck.t = ck.t.Add(25 * time.Hour)
	h3 := NewHealth(h.path)
	h3.now = ck.now
	h3.Load()
	if len(h3.buckets) != 0 {
		t.Fatal("old buckets kept")
	}
}
