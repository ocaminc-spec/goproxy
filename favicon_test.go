// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	good := map[string]string{"Example.COM": "example.com", "www.apple.com:443": "www.apple.com", "a-b.co.uk.": "a-b.co.uk"}
	for in, want := range good {
		if got, err := normalizeHost(in); err != nil || got != want {
			t.Errorf("%q -> %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "localhost", "127.0.0.1", "10.0.0.1", "[::1]", "::1", "192.168.1.123:80", "a..b", "-a.com",
		"evil.com/x", "evil.com?x", "user@evil.com", "printer.local", "nas.lan", "1.0.0.127.in-addr.arpa", "a b.com", strings.Repeat("a", 64) + ".com"} {
		if _, err := normalizeHost(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestBlockedIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.123", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:10.0.0.1"} {
		if !blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s not blocked", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "17.253.144.10", "2606:4700::1111"} {
		if blockedIP(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
	if err := safeDialControl("tcp", "127.0.0.1:443", nil); err == nil {
		t.Error("dial control allowed loopback")
	}
}

func TestRootDomain(t *testing.T) {
	for in, want := range map[string]string{"swcdn.apple.com": "apple.com", "apple.com": "apple.com", "a.b.bbc.co.uk": "bbc.co.uk", "x.y.z.google.com": "google.com"} {
		if got := rootDomain(in); got != want {
			t.Errorf("%s -> %s want %s", in, got, want)
		}
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{"http://Example.com:8080/a?b": "example.com", "swcdn.apple.com:443": "swcdn.apple.com", "http://u:p@x.org/": "x.org"} {
		if got := hostOf(in); got != want {
			t.Errorf("%s -> %s", in, got)
		}
	}
}

func TestIconFallbackChain(t *testing.T) {
	ic := NewIconCache(10, time.Hour, time.Second)
	var tried []string
	var mu sync.Mutex
	ic.fetch = func(_ context.Context, h string) ([]byte, string, error) {
		mu.Lock()
		tried = append(tried, h)
		mu.Unlock()
		if h == "apple.com" {
			return []byte("ICO"), "image/x-icon", nil
		}
		return nil, "", errors.New("404")
	}
	b, ct := ic.Get(context.Background(), "swcdn.apple.com")
	if string(b) != "ICO" || ct != "image/x-icon" || strings.Join(tried, ",") != "swcdn.apple.com,apple.com" {
		t.Fatalf("got %q %s tried %v", b, ct, tried)
	}
	ic.fetch = func(context.Context, string) ([]byte, string, error) { return nil, "", errors.New("down") }
	b, ct = ic.Get(context.Background(), "nothing.example.org")
	if ct != "image/svg+xml" || !strings.Contains(string(b), ">E</text>") {
		t.Fatalf("letter icon wrong: %s %s", ct, b)
	}
}

func TestIconCacheDedupTTLAndBound(t *testing.T) {
	ic := NewIconCache(3, 50*time.Millisecond, time.Second)
	var calls atomic.Int64
	ic.fetch = func(context.Context, string) ([]byte, string, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return []byte("x"), "image/png", nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); ic.Get(context.Background(), "a.com") }()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expected 1 fetch, got %d", calls.Load())
	}
	time.Sleep(60 * time.Millisecond)
	ic.Get(context.Background(), "a.com")
	if calls.Load() != 2 {
		t.Fatalf("TTL not honored: %d", calls.Load())
	}
	for _, h := range []string{"b.com", "c.com", "d.com", "e.com"} {
		ic.Get(context.Background(), h)
	}
	if ic.Len() > 3 {
		t.Fatalf("cache unbounded: %d", ic.Len())
	}
}

func TestFaviconEndpoint(t *testing.T) {
	ic := NewIconCache(10, time.Hour, time.Second)
	ic.fetch = func(context.Context, string) ([]byte, string, error) { return nil, "", errors.New("x") }
	for _, h := range []string{"127.0.0.1", "localhost", "192.168.1.1", "evil.com/../x"} {
		rr := httptest.NewRecorder()
		ic.ServeHTTP(rr, httptest.NewRequest("GET", "/favicon?host="+h, nil))
		if rr.Code != 400 {
			t.Errorf("%s: code %d", h, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	ic.ServeHTTP(rr, httptest.NewRequest("GET", "/favicon?host=github.com", nil))
	if rr.Code != 200 || rr.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("code %d ct %s", rr.Code, rr.Header().Get("Content-Type"))
	}
}

// Real fetch path must refuse hosts resolving to loopback (DNS-level SSRF).
func TestFetchRemoteBlocksLoopback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("\x00\x00\x01\x00")) }))
	defer srv.Close()
	ic := NewIconCache(10, time.Hour, time.Second)
	_, _, err := ic.fetchRemote(context.Background(), strings.TrimPrefix(srv.URL, "https://"))
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected blocked, got %v", err)
	}
}

func TestHostStatsTop(t *testing.T) {
	hs := NewHostStats(100)
	for i := 0; i < 15; i++ {
		for j := 0; j <= i; j++ {
			hs.Record("h"+string(rune('a'+i))+".com", 1, 0)
		}
	}
	top := hs.Top(10)
	if len(top) != 10 || top[0].Host != "ho.com" || top[0].Requests != 15 {
		t.Fatalf("bad top: %+v", top)
	}
	small := NewHostStats(2)
	small.Record("a.com", 1, 0)
	small.Record("b.com", 1, 0)
	small.Record("c.com", 1, 0)
	if len(small.Top(10)) != 2 {
		t.Fatal("host stats unbounded")
	}
}
