// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestStaleTimeoutPrefersFresh(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "1.2.3.4", &calls, nil)
	ck := &clock{time.Now()}
	s.cache.now = ck.now
	s.Handle(q("f.example."))
	ck.t = ck.t.Add(10 * time.Minute) // expired, upstream healthy -> fresh answer, not stale
	if _, res, _ := s.Handle(q("f.example.")); res != "refreshed" {
		t.Fatalf("want refreshed, got %s", res)
	}
}

func TestStaleTimeoutServesStaleWhenSlow(t *testing.T) {
	var calls atomic.Int64
	up := NewUpstream(fakeUp(t, 400*time.Millisecond, "9.9.9.9", &calls, nil), nil)
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 1000, 4), &Resolver{DoH: []*Upstream{up}}, NewBlocklist(nil, nil, nil))
	s.tune.StaleTimeout = 100 * time.Millisecond
	ck := newAclock(time.Now()) // race-safe: the background refresh reads the clock too
	s.cache.now = ck.now
	s.Handle(q("slow.example."))
	ck.add(10 * time.Minute)
	t0 := time.Now()
	r, res, _ := s.Handle(q("slow.example."))
	if res != "stale" || r.Answer[0].Header().Ttl != 30 {
		t.Fatalf("want stale, got %s", res)
	}
	if d := time.Since(t0); d < 90*time.Millisecond || d > 300*time.Millisecond {
		t.Fatalf("stale served after %v, want ~100ms", d)
	}
	// beyond the 1h max stale age the entry is gone
	ck.add(2 * time.Hour)
	if e, _ := s.cache.Get(cacheKey("slow.example.", dns.TypeA, dns.ClassINET)); e != nil {
		t.Fatal("entry older than max stale age still served")
	}
}

func TestPersistRoundTripAndFlush(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "4.4.4.4", &calls, nil)
	for _, n := range []string{"a.example.", "b.example.", "c.example."} {
		s.Handle(q(n))
		s.domains.Record(n[:len(n)-1], 1, 0)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "c.bin")
	if n, err := s.cache.Save(path); err != nil || n != 3 {
		t.Fatalf("save %d %v", n, err)
	}
	if err := s.SaveState(path + ".h"); err != nil {
		t.Fatal(err)
	}
	s2 := newTestServer(t, "4.4.4.4", &calls, nil)
	if n, err := s2.cache.LoadFile(path); err != nil || n != 3 {
		t.Fatalf("load %d %v", n, err)
	}
	names, err := s2.LoadState(path + ".h")
	if err != nil || len(names) != 3 || s2.stats.Queries.Load() != 3 {
		t.Fatalf("state %v %v q=%d", names, err, s2.stats.Queries.Load())
	}
	before := calls.Load()
	if _, res, _ := s2.Handle(q("b.example.")); res != "cached" || calls.Load() != before {
		t.Fatal("restored entry not served from cache")
	}
	if n := s2.cache.Flush(); n != 3 || s2.cache.entries.Load() != 0 || s2.cache.Bytes() != 0 {
		t.Fatal("flush")
	}
}

func TestSiblingPrefetchAndWarmup(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "5.6.7.8", &calls, nil)
	s.tune.Siblings = true
	s.Handle(q("sib.example."))
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.cache.entries.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.cache.entries.Load() != 3 || s.stats.Siblings.Load() != 2 {
		t.Fatalf("entries=%d siblings=%d", s.cache.entries.Load(), s.stats.Siblings.Load())
	}
	s.tune.Siblings = false
	s.Warmup(context.Background(), []string{"w1.example", "w2.example", "sib.example", "x.ads.example"})
	if s.stats.Warmed.Load() != 2 {
		t.Fatalf("warmed=%d", s.stats.Warmed.Load())
	}
}

func TestPinnedAutoPinAndSweep(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "8.8.4.4", &calls, nil)
	s.pinned = NewPinned([]string{"youtube.com"}, []string{"googlevideo.com"})
	s.pinned.Observe("rr3---sn-abc.googlevideo.com")
	s.pinned.Observe("example.com")
	if l := s.pinned.List(); len(l) != 2 || l[0].Name != "youtube.com" || l[0].Service != "YouTube" || serviceOf("occ-0-1.nflxso.net") != "Netflix" || !l[1].Auto {
		t.Fatalf("%v", l)
	}
	s.sweep()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.cache.entries.Load() < 6 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.cache.entries.Load() != 6 {
		t.Fatalf("pinned names not cached: %d", s.cache.entries.Load())
	}
	bl := NewBlocklist(nil, []string{"googlevideo.com"}, []string{"googlevideo.com", "ads.example"})
	if bl.Blocked("rr1.googlevideo.com") || !bl.Blocked("ads.example") {
		t.Fatal("googlevideo.com must never be blocked")
	}
}
