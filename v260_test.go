// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Parallel upstream: every upstream (even a UDP one below the top) is asked at once, fastest wins.
func TestV260ParallelFastWins(t *testing.T) {
	var c1, c2, c3 atomic.Int64
	slow := NewUpstream(fakeUp(t, 300*time.Millisecond, "1.1.1.1", &c1, nil), nil)
	mid := NewUpstream(fakeUp(t, 150*time.Millisecond, "8.8.4.4", &c2, nil), nil)
	fast := NewUpstream(fakeUp(t, 0, "8.8.8.8", &c3, nil), nil)
	rs := &Resolver{DoH: []*Upstream{slow, mid, fast}, First: 1, Hedge: 2 * time.Second}
	rs.ParallelAll.Store(true)
	t0 := time.Now()
	r, u, err := rs.Resolve(context.Background(), upstreamQuery(q("p.example.")))
	if err != nil || u != fast || r.Answer[0].String() == "" {
		t.Fatalf("u=%v err=%v", u, err)
	}
	if time.Since(t0) > 120*time.Millisecond {
		t.Fatal("did not take the fastest answer")
	}
	if c3.Load() != 1 || fast.Wins.Load() != 1 || slow.Wins.Load() != 0 {
		t.Fatal("fast must win")
	}
	time.Sleep(350 * time.Millisecond)
	if c1.Load() != 1 || c2.Load() != 1 {
		t.Fatalf("all upstreams must be queried at once: %d %d", c1.Load(), c2.Load())
	}
	if !strings.HasPrefix(rs.LastWinner(), fast.Label()) {
		t.Fatalf("last winner %q", rs.LastWinner())
	}
}

// A fast SERVFAIL must not win; the slower good answer does.
func TestV260ParallelErrorFallsThrough(t *testing.T) {
	var c1, c2 atomic.Int64
	var bad atomic.Bool
	bad.Store(true)
	failing := NewUpstream(fakeUp(t, 0, "9.9.9.9", &c1, &bad), nil)
	good := NewUpstream(fakeUp(t, 60*time.Millisecond, "1.1.1.1", &c2, nil), nil)
	rs := &Resolver{DoH: []*Upstream{failing, good}}
	rs.ParallelAll.Store(true)
	r, u, err := rs.Resolve(context.Background(), upstreamQuery(q("e.example.")))
	if err != nil || u != good || !validAnswer(r) {
		t.Fatalf("u=%v err=%v", u, err)
	}
	if failing.Wins.Load() != 0 || good.Wins.Load() != 1 {
		t.Fatal("SERVFAIL must not win")
	}
	// a dead upstream (nothing listening) also falls through
	dead := NewUpstream("127.0.0.1:1", nil)
	rs.SetUpstreams([]*Upstream{dead, good})
	if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("e2.example."))); err != nil || u != good {
		t.Fatalf("dead: u=%v err=%v", u, err)
	}
}

func TestV260DefaultsGoogleCloudflare(t *testing.T) {
	l := defaultDNSServers(defaultDoH, Settings{})
	want := []string{"https://1.1.1.1/dns-query", "https://dns.google/dns-query", "tls://1.1.1.1:853", "tls://8.8.8.8:853"}
	if len(l) != len(want) {
		t.Fatalf("%+v", l)
	}
	for i, w := range want {
		if l[i].Addr != w || !l[i].Enabled {
			t.Fatalf("%d: %+v", i, l[i])
		}
	}
	if providerOf(l[0].Addr) == providerOf(l[1].Addr) {
		t.Fatal("first two must be different providers")
	}
}
