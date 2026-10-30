// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// latency histogram bucket upper bounds (ms); the last bucket is "slower than 1s".
var histBounds = []float64{0.1, 0.5, 1, 5, 10, 25, 50, 100, 250, 1000}

type Stats struct {
	DNSSECPass   atomic.Int64 // v2.6.0: SERVFAIL answers rescued by the CD=1 retry
	start        time.Time
	Queries      atomic.Int64
	Hits         atomic.Int64
	StaleHits    atomic.Int64
	StaleRescued atomic.Int64 // expired entry, but upstream answered within the stale timeout
	Misses       atomic.Int64
	Blocked      atomic.Int64
	Forwarded    atomic.Int64
	Failures     atomic.Int64
	Prefetches   atomic.Int64
	Refreshes    atomic.Int64
	Siblings     atomic.Int64 // AAAA / HTTPS prefetched alongside A
	KeepHot      atomic.Int64 // refreshes by "popular never expire"
	Warmed       atomic.Int64 // warm-up resolutions at start
	Pinned       atomic.Int64 // refreshes of pinned names
	Coalesced    atomic.Int64 // upstream lookups started for cache misses (deduplicated)
	Hist         [11]atomic.Int64
	QTypes       [256]atomic.Int64 // index = qtype (<256), 0 = other
	latMu        sync.Mutex
	lat          []int64 // ring of all query latencies (ns)
	latN         int
	hitLat       []int64
	hitN         int
}

func (s *Stats) record(d time.Duration, hit bool) {
	ms := float64(d.Nanoseconds()) / 1e6
	b := len(histBounds)
	for i, ub := range histBounds {
		if ms < ub {
			b = i
			break
		}
	}
	s.Hist[b].Add(1)
	s.latMu.Lock()
	s.lat[s.latN%len(s.lat)] = int64(d)
	s.latN++
	if hit {
		s.hitLat[s.hitN%len(s.hitLat)] = int64(d)
		s.hitN++
	}
	s.latMu.Unlock()
}

// Tuning holds the caching policy; all of it is set from flags and shown in Expert Mode.
type Tuning struct {
	StaleTimeout  time.Duration // RFC 8767 client response timeout before serving stale
	PrefetchHits  int64         // min hits before prefetch
	PrefetchAt    float64       // fraction of TTL remaining that triggers prefetch
	Siblings      bool          // on A fetch, also fetch AAAA + HTTPS
	KeepHotN      int           // top N names kept refreshed continuously (0 = off)
	KeepHotEvery  time.Duration
	WarmupN       int
	WarmupWorkers int
	WarmupRate    float64  // v2.6.0: preload names per second (0 = unlimited)
	WarmupList    []string // v2.6.0: names always preloaded first
}

type flight struct {
	done chan struct{}
	r    *dns.Msg // nil on failure; may be SERVFAIL/REFUSED (not cached)
	up   string
}

type DNSServer struct {
	cache                *DNSCache
	res                  *Resolver
	bl                   *Blocklist
	stats                *Stats
	logs                 *LogRing
	domains              *HostStats
	blocked              *HostStats
	clients              *HostStats
	names                *ClientNames
	devvol               *DeviceVolume // v2.6.0 per-device volume (feature device_volume)
	pinned               *Pinned
	inflight             sync.Map // key -> *flight (dedup of background refreshes)
	tune                 Tuning
	warming              atomic.Bool
	restored             atomic.Int64
	cacheFile, ptrServer string
	neverBlock           []string
	settings             *settingsStore
	profile              string // v2.6.0 performance profile (max | balanced)
	health               *Health
	devRules             atomic.Pointer[devRules] // v2.7.0 per-device rules (nil = none / off)
	insights             *Insights                // v2.7.0 live insights
	v27                  *V27
	live                 *Live // v2.6.1 Live graph
	ctx                  context.Context
	// v2.4
	local   atomic.Pointer[localZone]
	v282    *V282
	devices *Devices
	flight  *Flight
	alerts  *Alerts
	canary  *Canary
	ads     *AdsFilter
	v28     *V28 // v2.8.0 smart server
}

func NewDNSServer(ctx context.Context, c *DNSCache, r *Resolver, b *Blocklist) *DNSServer {
	s := newDNSServer(ctx, c, r, b)
	s.wireAds()
	return s
}

func newDNSServer(ctx context.Context, c *DNSCache, r *Resolver, b *Blocklist) *DNSServer {
	return &DNSServer{cache: c, res: r, bl: b, ctx: ctx,
		tune:    Tuning{StaleTimeout: 3 * time.Second, PrefetchHits: 2, PrefetchAt: 0.1, KeepHotEvery: 30 * time.Second, WarmupWorkers: 4},
		stats:   &Stats{start: time.Now(), lat: make([]int64, 8192), hitLat: make([]int64, 8192)},
		logs:    NewLogRing(5000), // v2.8.1: Pro query log
		health:  NewHealth(""),
		domains: NewHostStats(8192), blocked: NewHostStats(8192), clients: NewHostStats(1024), ads: newServerAds()}
}

func clientIP(w dns.ResponseWriter) string {
	if w == nil || w.RemoteAddr() == nil {
		return "?"
	}
	h, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		return w.RemoteAddr().String()
	}
	return h
}

func (s *DNSServer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer s.recoverDNS(w, req) // v2.8.2: a bug in one lookup never takes the server down
	t0 := time.Now()
	cl := clientIP(w)
	resp, result, up := s.HandleFrom(req, cl)
	if resp != nil {
		// keep UDP answers within the client's buffer (capped at 1232 to avoid IP
		// fragmentation over Wi-Fi, DNS Flag Day 2020); TC=1 makes the client retry over TCP.
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			resp.Truncate(udpLimit(req))
		}
		_ = w.WriteMsg(resp)
	}
	d := time.Since(t0)
	if len(req.Question) == 1 && isSelfTest(req.Question[0].Name) {
		return // watchdog self-queries are not traffic
	}
	s.stats.record(d, result == "cached")
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	if q.Qtype < 256 {
		s.stats.QTypes[q.Qtype].Add(1)
	} else {
		s.stats.QTypes[0].Add(1)
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	blk := blockedResult(result)
	s.clients.Record(cl, 1, boolInt(blk))
	s.devvol.Record(cl, blk)
	s.live.SeeClient(cl)
	if s.names != nil {
		s.names.Seen(cl)
	}
	s.domains.Record(name, 1, boolInt(blk))
	s.pinned.Observe(name)
	rc := -1
	if resp != nil {
		rc = resp.Rcode
	}
	s.v28.observe(name, q.Qtype, result, rc, d, cl)
	if blk {
		s.blocked.Record(name, 1, 0)
	}
	if s.insights != nil {
		s.insights.RecordName(name)
		if blk || result == "failed" {
			s.insights.RecordFeed(feedItem{T: t0.UnixMilli(), Client: cl, Name: name, Type: dns.TypeToString[q.Qtype], Result: result})
		}
	}
	s.logs.Add(LogEntry{Client: cl, Domain: name, Type: dns.TypeToString[q.Qtype], Result: result, LatencyMs: float64(d.Nanoseconds()) / 1e6, Upstream: up})
	s.devices.Record(cl, q.Qtype, result)
	s.v282.observe(cl, name, result, d)
	if s.flight != nil {
		fe := flightEntry{T: t0.UnixNano(), Client: cl, Name: name, Type: q.Qtype, Result: result, LatUs: d.Microseconds(), Up: up}
		if resp != nil {
			fe.Rcode, fe.AnCnt = resp.Rcode, len(resp.Answer)
		}
		s.flight.Add(fe)
	}
}

// ednsUDPSize is the UDP payload size we advertise and honour (DNS Flag Day 2020).
const ednsUDPSize = 1232

// udpLimit is the largest UDP response the client can take: 512 without EDNS, else its
// advertised size clamped to [512, 1232].
func udpLimit(req *dns.Msg) int {
	o := req.IsEdns0()
	if o == nil {
		return dns.MinMsgSize
	}
	return min(max(int(o.UDPSize()), dns.MinMsgSize), ednsUDPSize)
}

// dnssecType reports RR types that are only returned to DNSSEC-aware (DO=1) clients.
func dnssecType(t uint16) bool {
	switch t {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	}
	return false
}

func stripDNSSEC(rrs []dns.RR, qtype uint16) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if t := rr.Header().Rrtype; !dnssecType(t) || t == qtype {
			out = append(out, rr)
		}
	}
	return out
}

// shape turns a stored/upstream response (m, already a private copy) into the reply for
// req: id + question echoed exactly (0x20 case preserved), owner names that match the
// question rewritten to the client's spelling, EDNS0 OPT mirrored (DO bit and our
// 1232-byte size), DNSSEC records and the AD bit only for clients that asked for them.
func shape(m, req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	m.Id = req.Id
	m.Response = true
	m.Opcode = req.Opcode
	m.RecursionDesired = req.RecursionDesired
	m.RecursionAvailable = true
	m.CheckingDisabled = req.CheckingDisabled
	m.Question = []dns.Question{q}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range sec {
			if h := rr.Header(); h.Name != q.Name && strings.EqualFold(h.Name, q.Name) {
				h.Name = q.Name
			}
		}
	}
	m.Extra = stripOPT(m.Extra)
	o := req.IsEdns0()
	do := o != nil && o.Do()
	if !do {
		m.Answer = stripDNSSEC(m.Answer, q.Qtype)
		m.Ns = stripDNSSEC(m.Ns, q.Qtype)
		m.Extra = stripDNSSEC(m.Extra, q.Qtype)
	}
	if !do && !req.AuthenticatedData {
		m.AuthenticatedData = false // RFC 6840 5.8
	}
	if o != nil {
		m.SetEdns0(ednsUDPSize, do)
	}
	return m
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Handle answers one query. result: cached | stale | refreshed | blocked | forwarded | failed.
func (s *DNSServer) Handle(req *dns.Msg) (*dns.Msg, string, string) { return s.HandleFrom(req, "") }

// HandleFrom is Handle for a known client address (per-device Ads & Tracking filter).
func (s *DNSServer) HandleFrom(req *dns.Msg, client string) (*dns.Msg, string, string) {
	if len(req.Question) == 1 && !req.Response && isSelfTest(req.Question[0].Name) {
		return selfTestReply(req), "local", ""
	}
	s.stats.Queries.Add(1)
	if len(req.Question) != 1 || req.Response || req.Opcode != dns.OpcodeQuery {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeFormatError)
		return m, "failed", ""
	}
	q := req.Question[0]
	if o := req.IsEdns0(); o != nil && o.Version() != 0 { // RFC 6891 6.1.3
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeBadVers)
		m.SetEdns0(ednsUDPSize, false)
		return m, "failed", ""
	}
	if r := s.localAnswer(req); r != nil {
		return r, "local", ""
	}
	if s.bl.Blocked(q.Name) || s.ads.Block(q.Name, client) || s.deviceBlocked(client, time.Now()) {
		s.stats.Blocked.Add(1)
		return blockedReply(req), "blocked", ""
	}
	if r := s.v28.preCheck(q.Name); r != "" {
		s.stats.Blocked.Add(1)
		return blockedReply(req), r, ""
	}
	key := cacheKey(q.Name, q.Qtype, q.Qclass)
	now := s.cache.now()
	if e, fresh := s.cache.Get(key); e != nil {
		hits := e.Hits.Add(1)
		if fresh {
			s.stats.Hits.Add(1)
			// prefetch popular entries in their last PrefetchAt fraction of TTL
			left := e.Expires.Sub(now)
			if hits >= s.tune.PrefetchHits && e.OrigTTL > 0 && float64(left) < float64(time.Duration(e.OrigTTL)*time.Second)*s.tune.PrefetchAt && s.v28.allowPrefetch() {
				s.refresh(key, upstreamQuery(req), &s.stats.Prefetches)
			}
			return shape(e.Reply(req, now, false), req), "cached", ""
		}
		// RFC 8767: try upstream first, serve stale only if it is slow or failing. If the
		// internet just failed (e.g. Wi-Fi dropped), serve stale at once instead of making
		// every device wait out the timeout (RFC 8767 failure recheck).
		f := s.refresh(key, upstreamQuery(req), &s.stats.Refreshes)
		if s.tune.StaleTimeout > 0 && !s.res.Offline() && !s.v28.staleNow() { // v2.8.1: serve-stale answers at once, refreshes behind
			t := time.NewTimer(s.tune.StaleTimeout)
			select {
			case <-f.done:
				t.Stop()
				if validAnswer(f.r) {
					s.stats.StaleRescued.Add(1)
					return answerFrom(f.r, req), "refreshed", f.up
				}
			case <-t.C:
			}
		}
		s.stats.StaleHits.Add(1)
		return shape(e.Reply(req, now, true), req), "stale", ""
	}
	s.stats.Misses.Add(1)
	// Coalesce concurrent misses for the same name (a TV, phone and console asking
	// for the same host at once) into one upstream lookup.
	f := s.refresh(key, upstreamQuery(req), &s.stats.Coalesced)
	select {
	case <-f.done:
	case <-s.ctx.Done():
	}
	r := f.r
	if r == nil {
		s.stats.Failures.Add(1)
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		if req.IsEdns0() != nil {
			m.SetEdns0(ednsUDPSize, false)
		}
		return m, "failed", ""
	}
	s.stats.Forwarded.Add(1)
	if s.tune.Siblings && q.Qtype == dns.TypeA && q.Qclass == dns.ClassINET && r.Rcode == dns.RcodeSuccess {
		s.prefetchSiblings(q.Name)
	}
	return answerFrom(r, req), "forwarded", f.up
}

func answerFrom(r, req *dns.Msg) *dns.Msg {
	return shape(r.Copy(), req)
}

// prefetchSiblings warms AAAA and HTTPS (type 65) for a name whose A was just fetched.
func (s *DNSServer) prefetchSiblings(name string) {
	for _, t := range []uint16{dns.TypeAAAA, dns.TypeHTTPS} {
		k := cacheKey(name, t, dns.ClassINET)
		if e, fresh := s.cache.Get(k); e != nil && fresh {
			continue
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), t)
		s.refresh(k, upstreamQuery(m), &s.stats.Siblings)
	}
}

func upstreamQuery(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{req.Question[0]}
	m.CheckingDisabled = req.CheckingDisabled
	// Always ask with DO=1 so the cached answer carries RRSIGs for DNSSEC-aware clients;
	// shape() strips them for everyone else.
	m.SetEdns0(4096, true)
	return m
}

// refresh re-resolves a key in the background, at most once concurrently. The returned
// flight's done channel closes when it finishes (r is nil on failure).
func (s *DNSServer) refresh(key string, q *dns.Msg, ctr *atomic.Int64) *flight {
	f := &flight{done: make(chan struct{})}
	if old, busy := s.inflight.LoadOrStore(key, f); busy {
		return old.(*flight)
	}
	ctr.Add(1)
	go func() {
		defer close(f.done)
		defer s.inflight.Delete(key)
		r, u, err := s.res.Resolve(s.ctx, q)
		if err == nil && r != nil && r.Rcode == dns.RcodeServerFailure && s.res.DNSSECPass && !q.CheckingDisabled && !s.dnssecStrict() {
			// v2.6.0: every upstream said SERVFAIL. Often a broken DNSSEC signature: ask once
			// more with CD=1 and pass the answer through (not cached, so a fixed zone heals
			// at once). A real outage stays SERVFAIL / stale.
			cq := q.Copy()
			cq.CheckingDisabled = true
			if r2, u2, err2 := s.res.Resolve(s.ctx, cq); err2 == nil && validAnswer(r2) {
				s.stats.DNSSECPass.Add(1)
				f.r = r2
				if u2 != nil {
					f.up = u2.Name
				}
				return
			}
		}
		if err != nil || r == nil {
			return
		}
		if validAnswer(r) {
			s.cache.Set(key, r)
		}
		f.r = r
		if u != nil {
			f.up = u.Name
		}
	}()
	return f
}

// KeepHot keeps the top N names and every pinned name (A/AAAA/HTTPS) refreshed before
// they expire. Pinned names are resolved even when not cached yet.
func (s *DNSServer) KeepHot(ctx context.Context) {
	if s.tune.KeepHotN <= 0 && len(s.pinned.List()) == 0 && s.pinned.suffixesOrNil() == nil {
		return
	}
	t := time.NewTicker(s.tune.KeepHotEvery)
	defer t.Stop()
	for {
		s.sweep()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *DNSServer) sweep() {
	horizon := s.cache.now().Add(2 * s.tune.KeepHotEvery)
	visit := func(name string, pinned bool) {
		if s.bl.Blocked(name) {
			return
		}
		for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
			k := cacheKey(name, typ, dns.ClassINET)
			e, _ := s.cache.Get(k)
			if (e == nil && pinned) || (e != nil && e.Expires.Before(horizon)) {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(name), typ)
				ctr := &s.stats.KeepHot
				if pinned {
					ctr = &s.stats.Pinned
				}
				s.refresh(k, upstreamQuery(m), ctr)
			}
		}
	}
	for _, p := range s.pinned.List() {
		visit(p.Name, true)
	}
	if s.tune.KeepHotN > 0 {
		for _, h := range s.domains.Top(s.tune.KeepHotN) {
			visit(h.Host, false)
		}
	}
}

// Warmup resolves the given names (A, plus siblings if enabled) with low concurrency.
func (s *DNSServer) Warmup(ctx context.Context, names []string) {
	if len(names) == 0 {
		return
	}
	s.warming.Store(true)
	defer s.warming.Store(false)
	ch := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < max(s.tune.WarmupWorkers, 1); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := range ch {
				k := cacheKey(n, dns.TypeA, dns.ClassINET)
				if e, fresh := s.cache.Get(k); e != nil && fresh {
					continue
				}
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(n), dns.TypeA)
				<-s.refresh(k, upstreamQuery(m), &s.stats.Warmed).done
				if s.tune.Siblings {
					s.prefetchSiblings(n)
				}
			}
		}()
	}
	var tick <-chan time.Time
	if s.tune.WarmupRate > 0 {
		t := time.NewTicker(time.Duration(float64(time.Second) / s.tune.WarmupRate))
		defer t.Stop()
		tick = t.C
	}
	for _, n := range names {
		if s.bl.Blocked(n) {
			continue
		}
		if tick != nil {
			select {
			case <-tick:
			case <-ctx.Done():
			}
		}
		select {
		case ch <- n:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(ch)
	wg.Wait()
}

// blockedReply answers 0.0.0.0 / :: for A / AAAA and NODATA for other types.
func blockedReply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	if req.IsEdns0() != nil {
		m.SetEdns0(ednsUDPSize, false)
	}
	q := req.Question[0]
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60, Rrtype: q.Qtype}
	switch q.Qtype {
	case dns.TypeA:
		m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4zero}}
	case dns.TypeAAAA:
		m.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.IPv6zero}}
	}
	return m
}
