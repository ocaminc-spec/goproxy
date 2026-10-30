// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshotKeepsRemainingTTLAcrossRestart(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "4.4.4.4", &calls, nil)
	ck := &clock{time.Now()}
	s.cache.now = ck.now
	s.Handle(q("ttl.example.")) // TTL 300
	s.Handle(q("old.example."))
	path := filepath.Join(t.TempDir(), "goproxy-cache.bin")
	if _, err := s.cache.Save(path); err != nil {
		t.Fatal(err)
	}
	// "restart" 100 s later
	s2 := newTestServer(t, "4.4.4.4", &calls, nil)
	ck2 := &clock{ck.t.Add(100 * time.Second)}
	s2.cache.now = ck2.now
	if n, err := s2.cache.LoadFile(path); err != nil || n != 2 {
		t.Fatalf("load %d %v", n, err)
	}
	before := calls.Load()
	r, res, _ := s2.Handle(q("ttl.example."))
	if res != "cached" || calls.Load() != before {
		t.Fatalf("want cache hit after restore, got %s", res)
	}
	if ttl := r.Answer[0].Header().Ttl; ttl < 195 || ttl > 201 {
		t.Fatalf("remaining TTL %d, want ~200 (300 - 100 s downtime)", ttl)
	}
}

func TestSnapshotDropsEntriesPastStaleWindow(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "4.4.4.4", &calls, nil)
	ck := &clock{time.Now()}
	s.cache.now = ck.now
	s.Handle(q("x.example."))
	path := filepath.Join(t.TempDir(), "c.bin")
	_, _ = s.cache.Save(path)
	// expired but within the 1 h serve-stale window: kept (servable as stale)
	s2 := newTestServer(t, "4.4.4.4", &calls, nil)
	s2.cache.now = (&clock{ck.t.Add(30 * time.Minute)}).now
	if n, _ := s2.cache.LoadFile(path); n != 1 {
		t.Fatalf("stale-servable entry dropped: %d", n)
	}
	// past TTL + 1 h: dropped
	s3 := newTestServer(t, "4.4.4.4", &calls, nil)
	s3.cache.now = (&clock{ck.t.Add(2 * time.Hour)}).now
	if n, _ := s3.cache.LoadFile(path); n != 0 {
		t.Fatalf("expired entry restored: %d", n)
	}
}

func TestCorruptSnapshotIsSkippedSafely(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "4.4.4.4", &calls, nil)
	dir := t.TempDir()
	junk := filepath.Join(dir, "junk.bin")
	_ = os.WriteFile(junk, []byte("this is not a snapshot \x00\x01\x02"), 0o644)
	if n, err := s.cache.LoadFile(junk); n != 0 || err == nil {
		t.Fatalf("corrupt file: n=%d err=%v", n, err)
	}
	// truncated mid-way: the good part is restored, the rest skipped with an error
	for _, n := range []string{"a.example.", "b.example.", "c.example.", "d.example."} {
		s.Handle(q(n))
	}
	good := filepath.Join(dir, "good.bin")
	if _, err := s.cache.Save(good); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(good)
	trunc := filepath.Join(dir, "trunc.bin")
	_ = os.WriteFile(trunc, b[:len(b)-20], 0o644)
	s2 := newTestServer(t, "4.4.4.4", &calls, nil)
	n, err := s2.cache.LoadFile(trunc)
	if n < 1 || n > 3 || err == nil {
		t.Fatalf("truncated: n=%d err=%v", n, err)
	}
	if _, err := os.Stat(good + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
	if n, err := s2.cache.LoadFile(filepath.Join(dir, "missing.bin")); n != 0 || !os.IsNotExist(err) {
		t.Fatalf("missing: %d %v", n, err)
	}
}

func TestStateKeepsPrefetchAndKeepHotCounters(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "4.4.4.4", &calls, nil)
	s.stats.Prefetches.Add(7)
	s.stats.KeepHot.Add(5)
	s.stats.Warmed.Add(3)
	s.stats.Coalesced.Add(2)
	s.domains.Record("top.example", 9, 0)
	p := filepath.Join(t.TempDir(), "h.json")
	if err := s.SaveState(p); err != nil {
		t.Fatal(err)
	}
	s2 := newTestServer(t, "4.4.4.4", &calls, nil)
	names, err := s2.LoadState(p)
	if err != nil || len(names) != 1 || names[0] != "top.example" {
		t.Fatalf("%v %v", names, err)
	}
	if s2.stats.Prefetches.Load() != 7 || s2.stats.KeepHot.Load() != 5 || s2.stats.Warmed.Load() != 3 || s2.stats.Coalesced.Load() != 2 {
		t.Fatal("counters not restored")
	}
}

func TestAutosaveWritesSnapshot(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "4.4.4.4", &calls, nil)
	dir := t.TempDir()
	s.cacheFile = filepath.Join(dir, "goproxy-cache.bin")
	s.health = NewHealth(filepath.Join(dir, "h.json"))
	s.Handle(q("auto.example."))
	a := &App{s: s, cache: s.cache, stateFile: s.cacheFile + ".history.json", stop: make(chan struct{})}
	ctx, cancel := contextWithCancel()
	defer cancel()
	go a.autosave(ctx, 30*time.Millisecond)
	waitFor(t, func() bool { _, err := os.Stat(s.cacheFile); return err == nil })
	s2 := newTestServer(t, "4.4.4.4", &calls, nil)
	if n, err := s2.cache.LoadFile(s.cacheFile); n != 1 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
}

func contextWithCancel() (context.Context, context.CancelFunc) {
	return context.WithCancel(context.Background())
}
