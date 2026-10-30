// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// handlerUp runs an in-process UDP+TCP upstream with a custom handler.
func handlerUp(t *testing.T, h func(r *dns.Msg) *dns.Msg) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	fn := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := h(r)
		m.Id = r.Id
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			m.Truncate(4096)
		}
		w.WriteMsg(m)
	})
	u := &dns.Server{PacketConn: pc, Handler: fn}
	tc := &dns.Server{Listener: ln, Handler: fn}
	go u.ActivateAndServe()
	go tc.ActivateAndServe()
	t.Cleanup(func() { u.Shutdown(); tc.Shutdown() })
	return pc.LocalAddr().String()
}

func rr(s string) dns.RR {
	r, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

// realistic upstream: lowercase names, HTTPS records, RRSIGs when DO=1, NODATA w/ SOA.
func zoneUp(t *testing.T, calls *atomic.Int64) string {
	return handlerUp(t, func(r *dns.Msg) *dns.Msg {
		if calls != nil {
			calls.Add(1)
		}
		q := r.Question[0]
		n := strings.ToLower(q.Name)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question[0].Name = n
		do := r.IsEdns0() != nil && r.IsEdns0().Do()
		switch {
		case n == "nx.example.":
			m.Rcode = dns.RcodeNameError
			m.Ns = []dns.RR{rr("example. 900 IN SOA ns. host. 1 2 3 4 120")}
		case n == "big.example." && q.Qtype == dns.TypeA:
			for i := 0; i < 100; i++ {
				m.Answer = append(m.Answer, rr(fmt.Sprintf("big.example. 300 IN A 10.0.%d.%d", i/250, i%250+1)))
			}
		case q.Qtype == dns.TypeHTTPS && n == "www.youtube.com.":
			m.Answer = []dns.RR{rr("www.youtube.com. 60 IN CNAME youtube-ui.l.google.com."), rr(`youtube-ui.l.google.com. 60 IN HTTPS 1 . alpn="h2,h3"`)}
		case q.Qtype == dns.TypeHTTPS:
			m.Ns = []dns.RR{rr("example. 900 IN SOA ns. host. 1 2 3 4 120")} // NODATA
		case q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{rr(n + " 20 IN A 192.0.2.1")}
			m.AuthenticatedData = true
			if do {
				m.Answer = append(m.Answer, rr(n+" 20 IN RRSIG A 13 2 20 20300101000000 20200101000000 1234 example. AAAA"))
			}
		default:
			m.Ns = []dns.RR{rr("example. 900 IN SOA ns. host. 1 2 3 4 120")}
		}
		return m
	})
}

func zoneServer(t *testing.T, calls *atomic.Int64) *DNSServer {
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 1000, 4), &Resolver{DoH: []*Upstream{NewUpstream(zoneUp(t, calls), nil)}}, NewBlocklist(nil, nil, nil))
	s.cache.minTTL = 300 * time.Second
	s.pinned = NewPinned(nil, nil)
	return s
}

func qt(name string, t uint16, edns, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, t)
	if edns {
		m.SetEdns0(1232, do)
	}
	return m
}

func TestHTTPSPassthroughAndHonouredTTL(t *testing.T) {
	s := zoneServer(t, nil)
	for i := 0; i < 2; i++ { // forwarded, then cached
		r, res, _ := s.Handle(qt("www.youtube.com.", dns.TypeHTTPS, true, false))
		if len(r.Answer) != 2 || r.Answer[1].Header().Rrtype != dns.TypeHTTPS || r.Rcode != 0 {
			t.Fatalf("%s: %v", res, r)
		}
		if ttl := r.Answer[1].Header().Ttl; ttl > 60 {
			t.Fatalf("HTTPS ttl raised to %d (min-ttl must not apply)", ttl)
		}
		if _, err := r.Pack(); err != nil {
			t.Fatal(err)
		}
	}
	// NODATA for HTTPS stays NOERROR+empty, NXDOMAIN stays NXDOMAIN
	if r, _, _ := s.Handle(qt("nohttps.example.", dns.TypeHTTPS, false, false)); r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("NODATA broken: %v", r)
	}
	for i := 0; i < 2; i++ {
		if r, _, _ := s.Handle(qt("nx.example.", dns.TypeA, false, false)); r.Rcode != dns.RcodeNameError {
			t.Fatalf("NXDOMAIN broken: %v", r)
		}
	}
	// the A sibling prefetch must never put HTTPS data under the A key or vice versa
	s.tune.Siblings = true
	s.Handle(qt("sib.example.", dns.TypeA, false, false))
	time.Sleep(200 * time.Millisecond)
	for _, ty := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
		if e, _ := s.cache.Get(cacheKey("sib.example.", ty, dns.ClassINET)); e != nil {
			for _, a := range e.Msg.Answer {
				if a.Header().Rrtype != ty && !dnssecType(a.Header().Rrtype) {
					t.Fatalf("wrong type %d under key %d", a.Header().Rrtype, ty)
				}
			}
			if e.Msg.Question[0].Qtype != ty {
				t.Fatal("question mismatch")
			}
		}
	}
}

func TestCasePreservedAndDNSSEC(t *testing.T) {
	s := zoneServer(t, nil)
	for _, name := range []string{"MiXeD.Example.", "mixed.example.", "MIXED.EXAMPLE."} {
		r, _, _ := s.Handle(qt(name, dns.TypeA, true, false))
		if r.Question[0].Name != name || r.Answer[0].Header().Name != name {
			t.Fatalf("case not preserved: %v", r)
		}
		if len(r.Answer) != 1 || r.AuthenticatedData {
			t.Fatalf("non-DO client got RRSIG/AD: %v", r)
		}
		if o := r.IsEdns0(); o == nil || o.UDPSize() != ednsUDPSize || o.Do() {
			t.Fatal("OPT not mirrored")
		}
	}
	r, _, _ := s.Handle(qt("mixed.example.", dns.TypeA, true, true))
	if len(r.Answer) != 2 || r.Answer[1].Header().Rrtype != dns.TypeRRSIG || !r.AuthenticatedData || !r.IsEdns0().Do() {
		t.Fatalf("DO client must get RRSIG+AD+DO: %v", r)
	}
	if r, _, _ := s.Handle(qt("mixed.example.", dns.TypeA, false, false)); r.IsEdns0() != nil {
		t.Fatal("OPT sent to non-EDNS client")
	}
	bv := qt("v.example.", dns.TypeA, true, false)
	bv.IsEdns0().SetVersion(1)
	if r, _, _ := s.Handle(bv); r.Rcode != dns.RcodeBadVers {
		t.Fatalf("want BADVERS got %d", r.Rcode)
	}
}

func TestUDPTruncationAndTCP(t *testing.T) {
	s := zoneServer(t, nil)
	addr := startTestDNS(t, s)
	for _, c := range []struct {
		edns  bool
		limit int
	}{{false, 512}, {true, 1232}} {
		cl := &dns.Client{Net: "udp", UDPSize: 65535}
		r, _, err := cl.Exchange(qt("big.example.", dns.TypeA, c.edns, false), addr)
		if r != nil {
			r.Compress = true
		}
		if w, _ := r.Pack(); err != nil || !r.Truncated || len(w) > c.limit {
			t.Fatalf("udp edns=%v: err=%v tc=%v len=%d", c.edns, err, r != nil && r.Truncated, r.Len())
		}
	}
	r, _, err := (&dns.Client{Net: "tcp"}).Exchange(qt("big.example.", dns.TypeA, true, false), addr)
	if err != nil || r.Truncated || len(r.Answer) != 100 {
		t.Fatalf("tcp: %v %v", err, r)
	}
}

func startTestDNS(t *testing.T, h dns.Handler) string {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	ln, _ := net.Listen("tcp", pc.LocalAddr().String())
	u := &dns.Server{PacketConn: pc, Handler: h}
	tc := &dns.Server{Listener: ln, Handler: h}
	go u.ActivateAndServe()
	go tc.ActivateAndServe()
	t.Cleanup(func() { u.Shutdown(); tc.Shutdown() })
	time.Sleep(50 * time.Millisecond)
	return pc.LocalAddr().String()
}

func TestServfailAndRefusedNeverWin(t *testing.T) {
	for _, rc := range []int{dns.RcodeServerFailure, dns.RcodeRefused} {
		bad := NewUpstream(handlerUp(t, func(r *dns.Msg) *dns.Msg { m := new(dns.Msg); m.SetRcode(r, rc); return m }), nil)
		var c atomic.Int64
		good := NewUpstream(fakeUp(t, 80*time.Millisecond, "7.7.7.7", &c, nil), nil)
		rs := &Resolver{DoH: []*Upstream{bad, good}}
		r, u, err := rs.Resolve(context.Background(), upstreamQuery(q("w.example.")))
		if err != nil || u != good || r.Rcode != 0 || bad.Wins.Load() != 0 || bad.Servfails.Load()+bad.Refused.Load() != 1 || bad.Errors.Load() != 0 {
			t.Fatalf("rcode %d won: u=%v err=%v badwins=%d errs=%d", rc, u, err, bad.Wins.Load(), bad.Errors.Load())
		}
	}
}

func TestMissesAreCoalesced(t *testing.T) {
	var calls atomic.Int64
	up := NewUpstream(fakeUp(t, 100*time.Millisecond, "8.8.4.4", &calls, nil), nil)
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 1000, 4), &Resolver{DoH: []*Upstream{up}}, NewBlocklist(nil, nil, nil))
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, _, _ := s.Handle(q("co.example.")); r.Rcode == 0 && len(r.Answer) == 1 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || ok.Load() != 50 {
		t.Fatalf("calls=%d ok=%d", calls.Load(), ok.Load())
	}
}

func TestOfflineServesStaleImmediately(t *testing.T) {
	rs := &Resolver{DoH: []*Upstream{NewUpstream("127.0.0.1:1", nil)}}
	rs.DoH[0].udp.Timeout = 50 * time.Millisecond
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 100, 2), rs, NewBlocklist(nil, nil, nil))
	s.tune.StaleTimeout = 3 * time.Second
	ck := &clock{time.Now()}
	s.cache.now = ck.now
	s.cache.Set(cacheKey("st.example.", dns.TypeA, dns.ClassINET), aReply("st.example", 60, "1.2.3.4"))
	ck.t = ck.t.Add(2 * time.Minute)
	s.Handle(q("nothere.example.")) // fails -> resolver marked offline
	if !rs.Offline() {
		t.Fatal("not offline after total failure")
	}
	t0 := time.Now()
	r, res, _ := s.Handle(q("st.example."))
	if res != "stale" || time.Since(t0) > 500*time.Millisecond || len(r.Answer) != 1 {
		t.Fatalf("res=%s took %v", res, time.Since(t0))
	}
}

func TestBlockingOffByDefaultAndPausePersists(t *testing.T) {
	bl := NewBlocklist([]string{"http://127.0.0.1:1/never"}, nil, []string{"ads.example"})
	bl.Enabled = false
	// v2.7.0: Run stays idle (it can be switched on from the dashboard) but downloads nothing.
	ctx, cancel := context.WithCancel(context.Background())
	up0 := bl.Updated.Load()
	done := make(chan struct{})
	go func() { bl.Run(ctx, time.Hour); close(done) }()
	time.Sleep(300 * time.Millisecond)
	if bl.Updating.Load() || bl.Updated.Load() != up0 || bl.Size() != 1 {
		t.Fatal("Run must not download when blocking is off")
	}
	cancel()
	<-done
	if bl.Blocked("ads.example") || bl.Updating.Load() {
		t.Fatal("blocked while off")
	}
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 100, 2), &Resolver{}, bl)
	s.settings = &settingsStore{path: filepath.Join(t.TempDir(), "goproxy-settings.json")}
	rec := httptest.NewRecorder()
	s.serveBlocking(rec, httptest.NewRequest("POST", "/api/blocking?enabled=true", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("toggle while off: %d", rec.Code)
	}
	bl.Enabled = true
	rec = httptest.NewRecorder()
	s.serveBlocking(rec, httptest.NewRequest("POST", "/api/blocking?enabled=false", nil))
	if st, err := s.settings.Load(); err != nil || !st.BlockingPaused || rec.Code != 200 {
		t.Fatalf("pause not persisted: %v %v", st, err)
	}
	s.serveBlocking(httptest.NewRecorder(), httptest.NewRequest("POST", "/api/blocking?enabled=true", nil))
	if st, _ := s.settings.Load(); st.BlockingPaused {
		t.Fatal("resume not persisted")
	}
}

func TestMinTTLExempt(t *testing.T) {
	c := NewDNSCache(1<<20, 100, 2)
	c.minTTL, c.minTTLExempt = 300*time.Second, []string{"googlevideo.com"}
	e := c.Set("k1", aReply("rr1---sn-x.googlevideo.com", 30, "1.1.1.1"))
	e2 := c.Set("k2", aReply("example.com", 30, "1.1.1.1"))
	e3 := c.Set("k3", aReply("zero.googlevideo.com", 0, "1.1.1.1"))
	if e.OrigTTL != 30 || e2.OrigTTL != 300 || e3.OrigTTL != 5 {
		t.Fatalf("%d %d %d", e.OrigTTL, e2.OrigTTL, e3.OrigTTL)
	}
}
