// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func aReply(name string, ttl uint32, ip string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m := new(dns.Msg)
	m.SetReply(q)
	rr, _ := dns.NewRR(fmt.Sprintf("%s %d IN A %s", dns.Fqdn(name), ttl, ip))
	m.Answer = []dns.RR{rr}
	return m
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestCacheTTLMinAndExpiry(t *testing.T) {
	ck := &clock{time.Unix(1e9, 0)}
	c := NewDNSCache(1<<20, 1000, 4)
	c.now, c.minTTL, c.staleFor = ck.now, 60*time.Second, time.Hour
	k := cacheKey("Example.COM", dns.TypeA, dns.ClassINET)
	if k != cacheKey("example.com.", dns.TypeA, dns.ClassINET) {
		t.Fatal("key not normalised")
	}
	c.Set(k, aReply("example.com", 5, "1.2.3.4")) // below min-ttl -> 60s
	if e, fresh := c.Get(k); e == nil || !fresh {
		t.Fatal("expected fresh")
	}
	ck.t = ck.t.Add(30 * time.Second)
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	e, _ := c.Get(k)
	if ttl := e.Reply(q, ck.t, false).Answer[0].Header().Ttl; ttl != 30 {
		t.Fatalf("decremented ttl = %d, want 30", ttl)
	}
	ck.t = ck.t.Add(31 * time.Second)
	if e, fresh := c.Get(k); e == nil || fresh {
		t.Fatal("expected stale")
	}
	ck.t = ck.t.Add(2 * time.Hour)
	if e, _ := c.Get(k); e != nil {
		t.Fatal("expected gone after stale window")
	}
}

func TestCacheNegativeAndServfail(t *testing.T) {
	c := NewDNSCache(1<<20, 1000, 4)
	c.minTTL = 0
	q := new(dns.Msg)
	q.SetQuestion("nx.example.", dns.TypeA)
	m := new(dns.Msg)
	m.SetRcode(q, dns.RcodeNameError)
	soa, _ := dns.NewRR("example. 3600 IN SOA ns. host. 1 2 3 4 120")
	m.Ns = []dns.RR{soa}
	e := c.Set("nx", m)
	if e == nil || !e.Negative || e.OrigTTL != 120 {
		t.Fatalf("negative entry wrong: %+v", e)
	}
	sf := new(dns.Msg)
	sf.SetRcode(q, dns.RcodeServerFailure)
	if c.Set("sf", sf) != nil {
		t.Fatal("SERVFAIL must not be cached")
	}
}

func TestCacheBudgetEviction(t *testing.T) {
	c := NewDNSCache(64<<10, 1<<20, 2) // 64KB
	for i := 0; i < 2000; i++ {
		c.Set(fmt.Sprint(i), aReply(fmt.Sprintf("h%d.example", i), 300, "1.1.1.1"))
	}
	if c.Bytes() > 64<<10 || c.evictions.Load() == 0 {
		t.Fatalf("bytes=%d evictions=%d", c.Bytes(), c.evictions.Load())
	}
	c2 := NewDNSCache(1<<30, 100, 4)
	for i := 0; i < 1000; i++ {
		c2.Set(fmt.Sprint(i), aReply("x.example", 300, "1.1.1.1"))
	}
	if c2.entries.Load() > 100 {
		t.Fatalf("entry budget exceeded: %d", c2.entries.Load())
	}
}

func TestBlocklist(t *testing.T) {
	b := NewBlocklist(nil, []string{"ok.ads.com"}, []string{"deny.me"})
	n := b.Load([]io.Reader{strings.NewReader("# c\n127.0.0.1 localhost\n0.0.0.0 ads.com tracker.net # x\nplain.org\n\n")})
	if n != 4 { // ads.com tracker.net plain.org deny.me
		t.Fatalf("n=%d", n)
	}
	for name, want := range map[string]bool{"ads.com.": true, "x.y.ADS.com": true, "ok.ads.com": false, "a.ok.ads.com": false,
		"notads.com": false, "plain.org": true, "deny.me": true, "localhost": false, "google.com": false} {
		if got := b.Blocked(name); got != want {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
	b.paused.Store(true)
	if b.Blocked("ads.com") {
		t.Fatal("paused must not block")
	}
	q := new(dns.Msg)
	q.SetQuestion("ads.com.", dns.TypeAAAA)
	if r := blockedReply(q); !r.Answer[0].(*dns.AAAA).AAAA.Equal(net.IPv6zero) {
		t.Fatal("want ::")
	}
}

// fakeUp is an in-process upstream used through a real UDP socket.
func fakeUp(t *testing.T, delay time.Duration, ip string, calls *atomic.Int64, fail *atomic.Bool) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		calls.Add(1)
		time.Sleep(delay)
		if fail != nil && fail.Load() {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		m := aReply(r.Question[0].Name, 300, ip)
		m.Id = r.Id
		w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestRaceFirstWins(t *testing.T) {
	var c1, c2 atomic.Int64
	slow := NewUpstream(fakeUp(t, 300*time.Millisecond, "2.2.2.2", &c1, nil), nil)
	fast := NewUpstream(fakeUp(t, 0, "1.1.1.1", &c2, nil), nil)
	rs := &Resolver{DoH: []*Upstream{slow, fast}}
	q := upstreamQuery(func() *dns.Msg { m := new(dns.Msg); m.SetQuestion("a.example.", dns.TypeA); return m }())
	t0 := time.Now()
	r, u, err := rs.Resolve(context.Background(), q)
	if err != nil || u != fast || r.Answer[0].(*dns.A).A.String() != "1.1.1.1" {
		t.Fatalf("u=%v err=%v", u, err)
	}
	if time.Since(t0) > 200*time.Millisecond {
		t.Fatal("did not return first answer")
	}
	if slow.Queries.Load() != 1 || fast.Queries.Load() != 1 || fast.Wins.Load() != 1 || slow.Wins.Load() != 0 {
		t.Fatalf("both upstreams should be queried in parallel: %d %d %d", c1.Load(), c2.Load(), fast.Wins.Load())
	}
}

func newTestServer(t *testing.T, ip string, calls *atomic.Int64, fail *atomic.Bool) *DNSServer {
	up := NewUpstream(fakeUp(t, 0, ip, calls, fail), nil)
	c := NewDNSCache(1<<20, 1000, 4)
	bl := NewBlocklist(nil, nil, []string{"ads.example"})
	return NewDNSServer(context.Background(), c, &Resolver{DoH: []*Upstream{up}}, bl)
}

func q(name string) *dns.Msg { m := new(dns.Msg); m.SetQuestion(name, dns.TypeA); return m }

func TestServeStaleAndBackgroundRefresh(t *testing.T) {
	var calls atomic.Int64
	var fail atomic.Bool
	s := newTestServer(t, "5.5.5.5", &calls, &fail)
	ck := newAclock(time.Now())
	s.cache.now = ck.now
	if _, res, _ := s.Handle(q("s.example.")); res != "forwarded" {
		t.Fatal(res)
	}
	if _, res, _ := s.Handle(q("s.example.")); res != "cached" || calls.Load() != 1 {
		t.Fatal("expected hit")
	}
	fail.Store(true) // upstream now broken; expired entry must still be served
	ck.add(10 * time.Minute)
	r, res, _ := s.Handle(q("s.example."))
	if res != "stale" || r.Answer[0].Header().Ttl != 30 || r.Answer[0].(*dns.A).A.String() != "5.5.5.5" {
		t.Fatalf("res=%s r=%v", res, r)
	}
	time.Sleep(100 * time.Millisecond)
	fail.Store(false)
	ck.set(time.Now().Add(10 * time.Minute))
	s.Handle(q("s.example.")) // triggers refresh that succeeds
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if e, fresh := s.cache.Get(cacheKey("s.example.", dns.TypeA, dns.ClassINET)); e != nil && fresh {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("background refresh did not renew the entry")
}

func TestBlockedAndPrefetch(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "6.6.6.6", &calls, nil)
	r, res, _ := s.Handle(q("x.ads.example."))
	if res != "blocked" || !r.Answer[0].(*dns.A).A.Equal(net.IPv4zero) || calls.Load() != 0 {
		t.Fatal("not blocked")
	}
	ck := &clock{time.Now()}
	s.cache.now = ck.now
	s.Handle(q("p.example."))
	s.Handle(q("p.example."))
	ck.t = ck.t.Add(295 * time.Second) // last 10% of 300s
	s.Handle(q("p.example."))
	time.Sleep(200 * time.Millisecond)
	if s.stats.Prefetches.Load() != 1 || calls.Load() != 2 {
		t.Fatalf("prefetches=%d calls=%d", s.stats.Prefetches.Load(), calls.Load())
	}
}

func TestFailureIsServfail(t *testing.T) {
	rs := &Resolver{DoH: []*Upstream{NewUpstream("127.0.0.1:1", nil)}}
	rs.DoH[0].udp.Timeout = 100 * time.Millisecond
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 100, 2), rs, NewBlocklist(nil, nil, nil))
	r, res, _ := s.Handle(q("f.example."))
	if res != "failed" || r.Rcode != dns.RcodeServerFailure {
		t.Fatal(errors.New(res))
	}
}

func TestHitLatency(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "7.7.7.7", &calls, nil)
	s.Handle(q("h.example."))
	n := 100000
	t0 := time.Now()
	for i := 0; i < n; i++ {
		s.Handle(q("h.example."))
	}
	per := time.Since(t0) / time.Duration(n)
	t.Logf("in-process cache hit: %v/op", per)
	if per > time.Millisecond {
		t.Fatalf("hit too slow: %v", per)
	}
}

func BenchmarkCacheHit(b *testing.B) {
	var calls atomic.Int64
	s := newTestServer(&testing.T{}, "7.7.7.7", &calls, nil)
	s.Handle(q("h.example."))
	req := q("h.example.")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			s.Handle(req)
		}
	})
}
