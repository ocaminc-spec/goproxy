// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func fakeUps(ms ...int) []*Upstream {
	var out []*Upstream
	for i, m := range ms {
		u := &Upstream{Name: string(rune('a' + i)), URL: "https://" + string(rune('a'+i)) + "/dns-query", doh: true}
		u.probeEWMA.Store(int64(time.Duration(m) * time.Millisecond))
		out = append(out, u)
	}
	return out
}

func TestV28SmartSplitTopN(t *testing.T) {
	rs := &Resolver{}
	rs.SetUpstreams(fakeUps(50, 10, 30, 20, 90))
	rs.Smart.Store(true)
	rs.SmartN.Store(3)
	raced, fb := rs.smartSplit()
	if len(raced) != 3 || raced[0].Name != "b" || raced[1].Name != "d" || raced[2].Name != "c" {
		t.Fatalf("raced %v", names(raced))
	}
	if len(fb) != 2 {
		t.Fatalf("fallback %v", names(fb))
	}
	explored := map[string]bool{}
	for i := 0; i < 4*exploreEvery; i++ {
		r, _ := rs.smartSplit()
		if len(r) == 4 {
			explored[r[3].Name] = true
		}
	}
	if !explored["a"] || !explored["e"] {
		t.Fatalf("exploration should rotate through the rest: %v", explored)
	}
	rs.Widen(time.Minute)
	if rs.smartOn() {
		t.Fatal("widened: smart split must be off")
	}
}

func names(u []*Upstream) (s []string) {
	for _, x := range u {
		s = append(s, x.Name)
	}
	return
}

func TestV28AutoDemote(t *testing.T) {
	rs := &Resolver{}
	ups := fakeUps(10, 12, 15, 400, 11)
	ups[1].errPPM.Store(600_000)
	rs.SetUpstreams(ups)
	rs.SmartN.Store(3)
	d := rs.autoDemote()
	if len(d) != 2 {
		t.Fatalf("demoted %v", names(d))
	}
	raced, _ := rs.smartSplit()
	for _, u := range raced[:3] {
		if u.Name == "d" || u.Name == "b" {
			t.Fatalf("demoted upstream raced: %v", names(raced))
		}
	}
	// never demotes below N healthy
	rs2 := &Resolver{}
	rs2.SetUpstreams(fakeUps(10, 400, 500))
	if d := rs2.autoDemote(); len(d) != 0 {
		t.Fatalf("must keep N: %v", names(d))
	}
}

func aMsg(name string, ttl uint32, ips ...string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	for _, ip := range ips {
		m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP(ip)})
	}
	return m
}

func TestV28AdaptiveTTL(t *testing.T) {
	c := NewDNSCache(1<<20, 1000, 4)
	c.minTTL = 60 * time.Second
	v := NewVolatility(100)
	v.On.Store(true)
	c.adapt = v.Adapt
	var d time.Duration
	for i := 0; i < 3; i++ {
		d, _ = c.ttlFor(aMsg("stable.example", 300, "1.2.3.4"))
	}
	if d != 600*time.Second {
		t.Fatalf("stable: %v", d)
	}
	for i := 0; i < 6; i++ {
		d, _ = c.ttlFor(aMsg("vol.example", 300, "1.2.3."+string(rune('0'+i))))
	}
	if d != 150*time.Second {
		t.Fatalf("volatile: %v", d)
	}
	for i := 0; i < 6; i++ {
		d, _ = c.ttlFor(aMsg("low.example", 30, "1.2.4."+string(rune('0'+i))))
	}
	if d != 60*time.Second {
		t.Fatalf("never under min-ttl floor: %v", d)
	}
	c.minTTLExempt = []string{"cdn.example"}
	for i := 0; i < 4; i++ {
		d, _ = c.ttlFor(aMsg("x.cdn.example", 20, "1.1.1.1"))
	}
	if d != 20*time.Second {
		t.Fatalf("exempt changed: %v", d)
	}
	v.On.Store(false)
	if d, _ = c.ttlFor(aMsg("stable.example", 300, "1.2.3.4")); d != 300*time.Second {
		t.Fatalf("off: %v", d)
	}
}

func TestV28TSDBRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ts.bin")
	ts := OpenTSDB(p)
	now := time.Unix(1_800_000_000, 0)
	ts.now = func() time.Time { return now }
	ts.cur.Store(&tsAcc{min: now.Unix() / 60})
	for i := 0; i < 10; i++ {
		ts.Observe("cached", dns.TypeA, 0, 200*time.Microsecond, "10.0.0.1")
	}
	ts.Observe("forwarded", dns.TypeAAAA, 3, 30*time.Millisecond, "10.0.0.2")
	ts.Observe("failed", dns.TypeHTTPS, 2, time.Second, "10.0.0.2")
	now = now.Add(time.Minute)
	ts.Tick()
	ts.Tick()
	ts2 := OpenTSDB(p)
	s := ts2.Sum(now.Unix()-120, now.Unix())
	if s.Q != 12 || s.Cached != 10 || s.Fwd != 1 || s.Failed != 1 || s.NX != 1 || s.Servfail != 1 || s.AAAA != 1 || s.HTTPS != 1 || s.Clients != 2 {
		t.Fatalf("%+v", s)
	}
	if s.FwdAvgMs < 29 || s.FwdAvgMs > 31 {
		t.Fatalf("fwd avg %v", s.FwdAvgMs)
	}
	if hr := s.HitRate(); hr < 0.9 {
		t.Fatalf("hit %v", hr)
	}
	if fi, _ := ts2.f.Stat(); fi.Size() > tsSlots*tsRecSize {
		t.Fatal("ring file must stay bounded")
	}
}

func TestV28DGA(t *testing.T) {
	for _, n := range []string{"www.google.com", "netflix.com", "rr3---sn-ab5l6nr6.googlevideo.com", "d1a2b3c4d5e6f7.cloudfront.net", "my-favourite-recipes.co.uk", "instagram.com", "microsoftonline.com", "1.0.168.192.in-addr.arpa"} {
		if s := dgaScore(n); s >= 0.75 {
			t.Errorf("%s flagged (%.2f)", n, s)
		}
	}
	for _, n := range []string{"xkqjvbzrtpwmnfgh.com", "q8w7e6r5t4y3u2i1o9p.net", "zxcvbnmlkjhgfdsqwrtp.info"} {
		if s := dgaScore(n); s < 0.75 {
			t.Errorf("%s not flagged (%.2f)", n, s)
		}
	}
}

func TestV28TunnelAndBlockMode(t *testing.T) {
	d := NewDetector()
	d.On.Store(true)
	var got []DetectEvent
	d.raise = func(e DetectEvent) { got = append(got, e) }
	for i := 0; i < 70; i++ {
		d.Observe(strings.Repeat("ab", 12)+string(rune('a'+i%26))+string(rune('a'+i/26))+".exfil.example", dns.TypeTXT)
	}
	if len(got) != 1 || got[0].Kind != "tunnel" || got[0].Domain != "exfil.example" {
		t.Fatalf("%+v", got)
	}
	if d.ShouldBlock("x.exfil.example") {
		t.Fatal("alert-only by default")
	}
	d.Block.Store(true)
	if !d.ShouldBlock("y.exfil.example") || d.ShouldBlock("www.google.com") {
		t.Fatal("block mode")
	}
}

func TestV28Habits(t *testing.T) {
	p := filepath.Join(t.TempDir(), "h.json")
	h := NewHabits(p)
	now := time.Date(2026, 10, 26, 19, 30, 0, 0, time.Local)
	h.now = func() time.Time { return now }
	h.curSlot = hourOfWeek(now)
	h.On.Store(true)
	for i := 0; i < 5; i++ {
		h.Record("youtube.com")
	}
	h.Record("netflix.com")
	now = now.Add(time.Hour)
	if !h.Roll() {
		t.Fatal("roll")
	}
	now = time.Date(2026, 11, 2, 18, 50, 0, 0, time.Local) // next Monday, 10 min before 19:00
	up := h.Upcoming(10*time.Minute, 5)
	if len(up) != 2 || up[0] != "youtube.com" {
		t.Fatalf("%v", up)
	}
	h2 := NewHabits(p)
	if len(h2.Slots[hourOfWeek(time.Date(2026, 10, 26, 19, 0, 0, 0, time.Local))]) != 2 {
		t.Fatal("not persisted")
	}
}

func TestV28PrefetchBucket(t *testing.T) {
	x := &V28{}
	x.prefetchOn.Store(true)
	x.tokens.Store(3)
	n := 0
	for i := 0; i < 10; i++ {
		if x.allowPrefetch() {
			n++
		}
	}
	if n != 3 || x.PrefSkipped.Load() != 7 {
		t.Fatalf("allowed %d", n)
	}
	x.prefetchOn.Store(false)
	x.tokens.Store(3)
	if x.allowPrefetch() {
		t.Fatal("off")
	}
	var nilx *V28
	if !nilx.allowPrefetch() || nilx.preCheck("a.com") != "" {
		t.Fatal("nil safe")
	}
}

func TestV28Validate(t *testing.T) {
	if validateV28(&V28Config{SmartN: 3, ThreatLists: []string{"ftp://x"}}) == nil {
		t.Fatal("bad url accepted")
	}
	if validateV28(&V28Config{}) != nil {
		t.Fatal("defaults rejected")
	}
	c := V28Config{}
	if c.smartN() != 3 || c.prefetchRate() != 20 || len(c.threatLists()) != 2 || c.ThreatOn || c.DetectBlock || c.DNSSECStrict {
		t.Fatal("defaults")
	}
}
