// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}

func udpUp(t *testing.T, delay time.Duration, ip string) (*Upstream, *atomic.Int64) {
	var c atomic.Int64
	return NewUpstream(fakeUp(t, delay, ip, &c, nil), nil), &c
}

// seed gives an upstream a latency history so it gets a score.
func seed(u *Upstream, d time.Duration, n int) {
	for i := 0; i < n; i++ {
		u.record(outOK, d)
	}
}

func TestLosersAreCancelledNotErrors(t *testing.T) {
	fast, _ := udpUp(t, 0, "1.1.1.1")
	slow, _ := dohServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond); dohAnswer(w, r) })
	rs := &Resolver{DoH: []*Upstream{slow, fast}, Hedge: time.Second}
	for i := 0; i < 5; i++ {
		if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("c.example."))); err != nil || u != fast {
			t.Fatalf("u=%v err=%v", u, err)
		}
	}
	waitFor(t, func() bool { return slow.Cancelled.Load() == 5 })
	if slow.Errors.Load() != 0 || slow.Timeouts.Load() != 0 || fast.Errors.Load() != 0 || fast.Wins.Load() != 5 {
		t.Fatalf("slow errs=%d to=%d fast errs=%d wins=%d", slow.Errors.Load(), slow.Timeouts.Load(), fast.Errors.Load(), fast.Wins.Load())
	}
}

func TestBestTwoRacedFirstOthersOnlyOnHedge(t *testing.T) {
	a, ca := udpUp(t, 0, "1.0.0.1")
	b, cb := udpUp(t, 0, "1.1.1.1")
	c, cc := udpUp(t, 0, "9.9.9.9")
	d, cd := udpUp(t, 0, "149.112.112.112")
	seed(a, 30*time.Millisecond, 20)
	seed(b, 20*time.Millisecond, 20)
	seed(c, 90*time.Millisecond, 20)
	seed(d, 80*time.Millisecond, 20)
	rs := &Resolver{DoH: []*Upstream{c, a, d, b}, Hedge: 500 * time.Millisecond}
	if o := rs.order(); o[0] != b || o[1] != a {
		t.Fatalf("order: %s %s", o[0].Name, o[1].Name)
	}
	for i := 0; i < 4; i++ {
		if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("h.example."))); err != nil || (u != a && u != b) {
			t.Fatalf("u=%v err=%v", u, err)
		}
	}
	if cc.Load() != 0 || cd.Load() != 0 || ca.Load()+cb.Load() < 7 || rs.Hedged.Load() != 0 {
		t.Fatalf("calls a=%d b=%d c=%d d=%d hedged=%d", ca.Load(), cb.Load(), cc.Load(), cd.Load(), rs.Hedged.Load())
	}
}

func TestHedgeFiresAfterDelay(t *testing.T) {
	slowH := func(w http.ResponseWriter, r *http.Request) { time.Sleep(400 * time.Millisecond); dohAnswer(w, r) }
	a, _ := dohServer(t, slowH)
	b, _ := dohServer(t, slowH)
	c, _ := udpUp(t, 0, "9.9.9.9")
	seed(a, 10*time.Millisecond, 5)
	seed(b, 10*time.Millisecond, 5)
	seed(c, 50*time.Millisecond, 5)
	rs := &Resolver{DoH: []*Upstream{a, b, c}, Hedge: 50 * time.Millisecond}
	t0 := time.Now()
	_, u, err := rs.Resolve(context.Background(), upstreamQuery(q("f.example.")))
	if err != nil || u != c || time.Since(t0) > 250*time.Millisecond || rs.Hedged.Load() != 1 {
		t.Fatalf("u=%v err=%v took=%v hedged=%d", u, err, time.Since(t0), rs.Hedged.Load())
	}
	waitFor(t, func() bool { return a.Cancelled.Load() == 1 && b.Cancelled.Load() == 1 })
}

func TestHedgeImmediateWhenPrimariesFail(t *testing.T) {
	sf := func(r *dns.Msg) *dns.Msg { m := new(dns.Msg); m.SetRcode(r, dns.RcodeServerFailure); return m }
	a := NewUpstream(handlerUp(t, sf), nil)
	b := NewUpstream(handlerUp(t, sf), nil)
	c, _ := udpUp(t, 0, "9.9.9.9")
	seed(a, 5*time.Millisecond, 5)
	seed(b, 5*time.Millisecond, 5)
	seed(c, 80*time.Millisecond, 5)
	rs := &Resolver{DoH: []*Upstream{a, b, c}, Hedge: 2 * time.Second}
	t0 := time.Now()
	r, u, err := rs.Resolve(context.Background(), upstreamQuery(q("s.example.")))
	if err != nil || u != c || r.Rcode != 0 || time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("u=%v err=%v took=%v", u, err, time.Since(t0))
	}
	if a.Servfails.Load() != 1 || a.Errors.Load() != 0 || a.Wins.Load() != 0 {
		t.Fatalf("servfail=%d errors=%d", a.Servfails.Load(), a.Errors.Load())
	}
}

func TestServfailOnlyReturnedAsLastResort(t *testing.T) {
	sf := func(r *dns.Msg) *dns.Msg { m := new(dns.Msg); m.SetRcode(r, dns.RcodeServerFailure); return m }
	a := NewUpstream(handlerUp(t, sf), nil)
	rs := &Resolver{DoH: []*Upstream{a}}
	r, _, err := rs.Resolve(context.Background(), upstreamQuery(q("x.example.")))
	if err != nil || r == nil || r.Rcode != dns.RcodeServerFailure || a.Wins.Load() != 0 {
		t.Fatalf("r=%v err=%v wins=%d", r, err, a.Wins.Load())
	}
}

func dohServer(t *testing.T, h http.HandlerFunc) (*Upstream, *httptest.Server) {
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	tr := srv.Client().Transport.(*http.Transport).Clone()
	return NewUpstream(srv.URL+"/dns-query", tr), srv
}

func dohAnswer(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	m := new(dns.Msg)
	_ = m.Unpack(b)
	a := aReply(m.Question[0].Name, 300, "4.4.4.4")
	a.Id = m.Id
	w.Header().Set("Content-Type", "application/dns-message")
	out, _ := a.Pack()
	_, _ = w.Write(out)
}

func TestErrorClassification(t *testing.T) {
	limited, _ := dohServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "slow down", 429) })
	if _, err := limited.Exchange(context.Background(), upstreamQuery(q("a.example."))); err == nil {
		t.Fatal("want error")
	}
	if limited.HTTPErrs.Load() != 1 || limited.Errors.Load() != 1 || limited.lastHTTP.Load() != 429 {
		t.Fatalf("http=%d errs=%d last=%d", limited.HTTPErrs.Load(), limited.Errors.Load(), limited.lastHTTP.Load())
	}
	slow, _ := dohServer(t, func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond); dohAnswer(w, r) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, _ = slow.Exchange(ctx, upstreamQuery(q("b.example.")))
	cancel()
	if slow.Timeouts.Load() != 1 || slow.Cancelled.Load() != 0 {
		t.Fatalf("timeouts=%d cancelled=%d", slow.Timeouts.Load(), slow.Cancelled.Load())
	}
	ctx, cancel = context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	_, _ = slow.Exchange(ctx, upstreamQuery(q("c.example.")))
	if slow.Cancelled.Load() != 1 || slow.Errors.Load() != 1 {
		t.Fatalf("cancelled=%d errors=%d", slow.Cancelled.Load(), slow.Errors.Load())
	}
	good, _ := dohServer(t, dohAnswer)
	if r, err := good.Exchange(context.Background(), upstreamQuery(q("d.example."))); err != nil || r.Rcode != 0 {
		t.Fatalf("doh: %v", err)
	}
}

func TestConnectionResetIsRetriedOnFreshConnection(t *testing.T) {
	var n atomic.Int64
	u, _ := dohServer(t, func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 { // first request: the server drops the connection (like a GOAWAY/reset)
			hj, ok := w.(http.Hijacker)
			if ok {
				c, _, _ := hj.Hijack()
				c.Close()
				return
			}
		}
		dohAnswer(w, r)
	})
	r, err := u.Exchange(context.Background(), upstreamQuery(q("r.example.")))
	if err != nil || r.Rcode != 0 {
		t.Fatalf("err=%v", err)
	}
	if u.Errors.Load() != 0 {
		t.Fatalf("errors=%d retries=%d", u.Errors.Load(), u.Retries.Load())
	}
}

func TestCircuitBreakerBacksOffAndRecovers(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	bad, _ := dohServer(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", 503) })
	good, _ := udpUp(t, 0, "1.1.1.1")
	bad.now, good.now = clock, clock
	rs := &Resolver{DoH: []*Upstream{bad, good}, Hedge: time.Second}
	for i := 0; i < breakerAfter; i++ {
		_, _ = bad.Exchange(context.Background(), upstreamQuery(q("b.example.")))
	}
	if !bad.open() || bad.health() != "down" {
		t.Fatal("breaker should be open")
	}
	if o := rs.order(); len(o) != 1 || o[0] != good {
		t.Fatalf("open upstream must be skipped: %d", len(o))
	}
	now = now.Add(breakerBase + time.Millisecond)
	if bad.open() || len(rs.order()) != 2 {
		t.Fatal("breaker should half-open after backoff")
	}
	for i := 0; i < breakerAfter; i++ { // trips again: backoff doubles
		_, _ = bad.Exchange(context.Background(), upstreamQuery(q("b.example.")))
	}
	now = now.Add(breakerBase + time.Millisecond)
	if !bad.open() {
		t.Fatal("second trip should back off longer")
	}
	// all open: still tried rather than failing outright
	good.brkUntil.Store(now.Add(time.Hour).UnixNano())
	if len(rs.order()) != 2 {
		t.Fatal("all-open must fall back to trying everyone")
	}
	bad.record(outOK, time.Millisecond)
	if bad.brkTrips.Load() != 0 {
		t.Fatal("success resets the backoff")
	}
}

func TestStatsSplitAndP95(t *testing.T) {
	u := NewUpstream("127.0.0.1:1", nil)
	for i := 1; i <= 100; i++ {
		u.record(outOK, time.Duration(i)*time.Millisecond)
	}
	u.record(outTimeout, 0)
	u.record(outHTTP, 0)
	u.record(outConn, 0)
	u.record(outServfail, 0)
	u.record(outRefused, 0)
	u.record(outCancelled, 0)
	u.record(outCancelled, 0)
	rs := &Resolver{Fallback: []*Upstream{u}}
	s := rs.Stats()[0]
	if s.Errors != 3 || s.Timeouts != 1 || s.HTTPErrs != 1 || s.ConnErrs != 1 || s.Servfails != 1 || s.Refused != 1 || s.Cancelled != 2 {
		t.Fatalf("%+v", s)
	}
	if s.P95Ms < 94 || s.P95Ms > 96 || s.ErrRate <= 0 {
		t.Fatalf("p95=%v errRate=%v", s.P95Ms, s.ErrRate)
	}
}

func TestAdaptiveHedgeDelay(t *testing.T) {
	u := NewUpstream("127.0.0.1:1", nil)
	rs := &Resolver{}
	if rs.hedgeDelay(u) != defaultHedge {
		t.Fatal("default")
	}
	seed(u, 5*time.Millisecond, 10)
	if rs.hedgeDelay(u) != minHedge {
		t.Fatal("min clamp")
	}
	seed(u, time.Second, 128)
	if rs.hedgeDelay(u) != maxHedge {
		t.Fatal("max clamp")
	}
}
