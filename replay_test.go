// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// Offline "YouTube-safe" replay suite (spec 03 part A). Hand-written scenarios in
// testdata/replay go through DNSServer.Handle with a fake clock and a scripted loopback
// upstream; no real network. Invariant 9 (answer stability) is report-only.

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type replayLine struct {
	Comment    string `json:"comment"`
	Event      string `json:"event"`
	TMs        int64  `json:"t_ms"`
	Client     string `json:"client"`
	Name       string `json:"name"`
	QType      string `json:"qtype"`
	DO         bool   `json:"do_bit"`
	EDNS       int    `json:"edns_size"`
	Concurrent bool   `json:"concurrent"`
}

// aclock is a race-safe fake clock (background refreshes read it too).
type aclock struct{ n atomic.Int64 }

func (c *aclock) now() time.Time      { return time.Unix(0, c.n.Load()) }
func (c *aclock) set(t time.Time)     { c.n.Store(t.UnixNano()) }
func (c *aclock) add(d time.Duration) { c.n.Add(int64(d)) }
func newAclock(t time.Time) *aclock   { c := &aclock{}; c.set(t); return c }
func cdnName(n string) bool {
	n = strings.ToLower(n)
	return strings.HasSuffix(n, "googlevideo.com.") || strings.HasSuffix(n, "nflxvideo.net.")
}
func replayKey(n string, t uint16) string { return strings.ToLower(n) + "/" + dns.TypeToString[t] }

type scriptedUp struct {
	fail  atomic.Bool
	delay atomic.Int64 // ns
	mu    sync.Mutex
	calls map[string]int
}

func (u *scriptedUp) answer(r *dns.Msg) *dns.Msg {
	q := r.Question[0]
	u.mu.Lock()
	u.calls[replayKey(q.Name, q.Qtype)]++
	u.mu.Unlock()
	time.Sleep(time.Duration(u.delay.Load()))
	m := new(dns.Msg)
	if u.fail.Load() {
		m.SetRcode(r, dns.RcodeServerFailure)
		return m
	}
	m.SetReply(r)
	ttl := uint32(300)
	if cdnName(q.Name) {
		ttl = 10
	}
	do := r.IsEdns0() != nil && r.IsEdns0().Do()
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60}, Ns: "ns.example.", Mbox: "h.example.", Minttl: 60}
	switch q.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		owner := q.Name
		if strings.EqualFold(q.Name, "www.youtube.com.") {
			m.Answer = append(m.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl}, Target: "youtube-ui.l.google.com."})
			owner = "youtube-ui.l.google.com."
		}
		if q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.ParseIP("142.250.1.1")})
		} else {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: net.ParseIP("2607:f8b0::1")})
		}
		if do {
			m.Answer = append(m.Answer, &dns.RRSIG{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl}, TypeCovered: q.Qtype, Algorithm: 13, SignerName: "example.", Signature: "AAAA"})
		}
	case dns.TypeHTTPS:
		if strings.Contains(strings.ToLower(q.Name), "googlevideo") || strings.Contains(strings.ToLower(q.Name), "nflx") {
			m.Ns = []dns.RR{soa} // NODATA
		} else {
			m.Answer = append(m.Answer, &dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: ttl}, Priority: 1, Target: "."}})
		}
	default:
		m.Ns = []dns.RR{soa}
	}
	if o := r.IsEdns0(); o != nil {
		m.SetEdns0(1232, o.Do())
	}
	return m
}

func (u *scriptedUp) count(name string, t uint16) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls[replayKey(name, t)]
}

type replayEnv struct {
	s     *DNSServer
	up    *scriptedUp
	ck    *aclock
	never []string
}

func newReplayEnv(t *testing.T) *replayEnv {
	up := &scriptedUp{calls: map[string]int{}}
	up.delay.Store(int64(2 * time.Millisecond))
	ck := newAclock(time.Unix(1_800_000_000, 0))
	never := append([]string{"www.youtube.com", "youtubei.googleapis.com", "googlevideo.com", "netflix.com", "nflxvideo.net"}, connectivityNames...)
	// blocking ON with a list that contains never-block names: they must still never be blocked
	bl := NewBlocklist(nil, never, []string{"www.youtube.com", "googlevideo.com", "ads.example", "nflxvideo.net"})
	s := NewDNSServer(context.Background(), NewDNSCache(1<<22, 10000, 4), &Resolver{DoH: []*Upstream{NewUpstream(handlerUp(t, up.answer), nil)}}, bl)
	s.cache.now = ck.now
	s.cache.minTTL = 300 * time.Second
	s.cache.minTTLExempt = []string{"googlevideo.com", "nflxvideo.net"}
	s.tune.StaleTimeout = 400 * time.Millisecond
	s.pinned = NewPinned([]string{"youtube.com", "www.youtube.com", "netflix.com", "www.netflix.com"}, []string{"googlevideo.com", "nflxso.net", "nflxvideo.net"})
	return &replayEnv{s: s, up: up, ck: ck, never: never}
}

func loadScenario(t *testing.T, path string) []replayLine {
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []replayLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l replayLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if l.Comment == "" {
			out = append(out, l)
		}
	}
	return out
}

func (e *replayEnv) neverBlocked(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, x := range e.never {
		if n == x || strings.HasSuffix(n, "."+x) {
			return true
		}
	}
	return false
}

func (e *replayEnv) pinnedName(name string) bool {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, p := range e.s.pinned.List() {
		if p.Name == n {
			return true
		}
	}
	return false
}

// query runs one line and checks invariants 1-5 and 7; it returns problems found.
func (e *replayEnv) query(l replayLine) []string {
	qt := dns.StringToType[l.QType]
	req := new(dns.Msg)
	req.SetQuestion(l.Name, qt)
	if l.EDNS > 0 {
		req.SetEdns0(uint16(l.EDNS), l.DO)
	}
	key := cacheKey(l.Name, qt, dns.ClassINET)
	before := rawEntry(e.s.cache, key) // stored copy, servable or not
	var beforeExp time.Time
	if before != nil {
		beforeExp = before.Expires
	}
	now := e.s.cache.now()
	// policy window: RFC 8767 serve-stale for 1 h (the shipped default), independent of
	// what the code under test is configured with
	inWindow := before != nil && now.Before(beforeExp.Add(time.Hour))
	e.s.pinned.Observe(strings.TrimSuffix(strings.ToLower(l.Name), "."))
	r, result, _ := e.s.Handle(req)
	var bad []string
	add := func(f string) { bad = append(bad, l.Name+" "+l.QType+": "+f) }
	if r == nil {
		add("no reply")
		return bad
	}
	// 1. never SERVFAIL for a pinned name while a cached copy exists
	if inWindow && e.pinnedName(l.Name) && r.Rcode == dns.RcodeServerFailure {
		add("invariant 1: SERVFAIL although a cached copy existed")
	}
	// 2. stale only within staleFor
	if result == "stale" && (before == nil || now.After(beforeExp.Add(e.s.cache.staleFor))) {
		add("invariant 2: stale answer outside staleFor")
	}
	// 3. min-TTL-exempt names keep their real TTL (10 s here), never stretched to 300
	if cdnName(l.Name) && r.Rcode == dns.RcodeSuccess && result != "stale" {
		for _, rr := range r.Answer {
			if rr.Header().Ttl > 10 {
				add("invariant 3: CDN TTL stretched to " + itoa(int(rr.Header().Ttl)))
			}
		}
	}
	// 4. HTTPS NODATA stays NOERROR + empty
	if qt == dns.TypeHTTPS && cdnName(l.Name) && r.Rcode != dns.RcodeServerFailure && (r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0) {
		add("invariant 4: HTTPS NODATA changed")
	}
	// 5. never-block names are never blocked
	if result == "blocked" && e.neverBlocked(l.Name) {
		add("invariant 5: never-block name was blocked")
	}
	// 7. case preserved, OPT mirrored, RRSIG only with DO
	if len(r.Question) != 1 || r.Question[0].Name != l.Name {
		add("invariant 7: question case not preserved")
	}
	if (req.IsEdns0() != nil) != (r.IsEdns0() != nil) {
		add("invariant 7: OPT not mirrored")
	}
	for _, rr := range r.Answer {
		if rr.Header().Rrtype == dns.TypeRRSIG && !l.DO {
			add("invariant 7: RRSIG sent to a client without DO")
		}
	}
	return bad
}

func rawEntry(c *DNSCache, key string) *CacheEntry {
	sh := c.shard(key)
	sh.mu.RLock()
	defer sh.mu.RUnlock()
	return sh.m[key]
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func runScenario(t *testing.T, e *replayEnv, lines []replayLine) (problems []string, results map[string]int) {
	results = map[string]int{}
	var last int64
	var mu sync.Mutex
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if l.TMs > last {
			e.ck.add(time.Duration(l.TMs-last) * time.Millisecond)
			last = l.TMs
		}
		switch l.Event {
		case "upstream_fail":
			e.up.fail.Store(true)
			continue
		case "upstream_ok":
			e.up.fail.Store(false)
			continue
		}
		if l.Concurrent { // a burst of simultaneous askers
			j := i
			for j < len(lines) && lines[j].Concurrent && lines[j].TMs == l.TMs {
				j++
			}
			var wg sync.WaitGroup
			for _, c := range lines[i:j] {
				wg.Add(1)
				go func(c replayLine) {
					defer wg.Done()
					p := e.query(c)
					mu.Lock()
					problems = append(problems, p...)
					mu.Unlock()
				}(c)
			}
			wg.Wait()
			i = j - 1
			continue
		}
		problems = append(problems, e.query(l)...)
	}
	return problems, results
}

func TestReplayScenarios(t *testing.T) {
	files, _ := filepath.Glob("testdata/replay/*.jsonl")
	if len(files) < 6 {
		t.Fatalf("replay corpus missing: %v", files)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		t.Run(name, func(t *testing.T) {
			e := newReplayEnv(t)
			if name == "smart_tv_boot" {
				e.up.delay.Store(int64(80 * time.Millisecond)) // make the askers overlap
			}
			lines := loadScenario(t, f)
			problems, _ := runScenario(t, e, lines)
			for _, p := range problems {
				t.Error(p)
			}
			// 6. every auto-pin host seen is pinned with Auto=true
			auto := map[string]bool{}
			for _, p := range e.s.pinned.List() {
				if p.Auto {
					auto[p.Name] = true
				}
			}
			for _, l := range lines {
				n := strings.TrimSuffix(strings.ToLower(l.Name), ".")
				if n != "" && (strings.HasSuffix(n, ".googlevideo.com") || strings.HasSuffix(n, ".nflxso.net") || strings.HasSuffix(n, ".nflxvideo.net")) && !auto[n] {
					t.Errorf("invariant 6: %s not auto-pinned", n)
				}
			}
			// 8. coalescing: N simultaneous askers -> one upstream call
			if name == "smart_tv_boot" {
				if c := e.up.count("tv-boot.googleapis.com.", dns.TypeA); c != 1 {
					t.Errorf("invariant 8: %d upstream calls for 6 simultaneous askers", c)
				}
				if c := e.up.count("www.netflix.com.", dns.TypeHTTPS); c != 1 {
					t.Errorf("invariant 8: %d upstream calls (HTTPS) for 6 simultaneous askers", c)
				}
			}
			if name == "wifi_drop_midstream" && e.s.stats.StaleHits.Load() == 0 {
				t.Error("wifi drop: nothing was served stale")
			}
			t.Logf("%s: %d queries, %d problems, upstream calls %d, stale %d", name, len(lines), len(problems), totalCalls(e.up), e.s.stats.StaleHits.Load())
		})
	}
}

func totalCalls(u *scriptedUp) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, c := range u.calls {
		n += c
	}
	return n
}

// The harness must have teeth: break the code paths the invariants protect and check
// that the matching scenario fails (mutation-style, spec 03 test plan).
func TestReplayCatchesRegressions(t *testing.T) {
	t.Run("staleFor=0 breaks wifi_drop", func(t *testing.T) {
		e := newReplayEnv(t)
		e.s.cache.staleFor = 0
		problems, _ := runScenario(t, e, loadScenario(t, "testdata/replay/wifi_drop_midstream.jsonl"))
		found := false
		for _, p := range problems {
			if strings.Contains(p, "invariant 1") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected invariant 1 failures with staleFor=0, got %v", problems)
		}
	})
	t.Run("no minTTLExempt breaks cdn_short_ttl", func(t *testing.T) {
		e := newReplayEnv(t)
		e.s.cache.minTTLExempt = nil
		problems, _ := runScenario(t, e, loadScenario(t, "testdata/replay/cdn_short_ttl.jsonl"))
		found := false
		for _, p := range problems {
			if strings.Contains(p, "invariant 3") {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected invariant 3 failures without the exempt list, got %v", problems)
		}
	})
}
