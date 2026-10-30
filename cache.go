// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"hash/maphash"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// CacheEntry holds a full upstream response for one (name,type,class).
type CacheEntry struct {
	Msg      *dns.Msg
	Stored   time.Time
	Expires  time.Time // fresh until
	OrigTTL  uint32
	Hits     atomic.Int64
	size     int64
	Negative bool
}

type cshard struct {
	mu    sync.RWMutex
	m     map[string]*CacheEntry
	bytes int64
}

// DNSCache is a sharded, byte- and entry-budgeted RAM cache honouring TTLs.
type DNSCache struct {
	shards     []*cshard
	seed       maphash.Seed
	budget     int64
	maxEntries int64
	staleFor   time.Duration
	minTTL     time.Duration
	maxTTL     time.Duration
	negMinTTL  time.Duration
	negMaxTTL  time.Duration
	// pinnedFloor (v2.5.0): minimum TTL for pinned names only (YouTube / Netflix / connectivity
	// checks), so they stay cached between keep-hot sweeps. Every other answer keeps its
	// upstream TTL unless -min-ttl is raised.
	pinnedFloor time.Duration
	isPinned    func(name string) bool
	// minTTLExempt: names (and subdomains) whose upstream TTL is honoured instead of
	// being raised to minTTL, so CDN failover (googlevideo, Netflix OCAs) keeps working.
	minTTLExempt []string
	// v2.8.0 adaptive TTL (nil = off): may stretch stable answers / shorten volatile ones.
	adapt     func(m *dns.Msg, d, floor time.Duration) time.Duration
	entries   atomic.Int64
	evictions atomic.Int64
	staleMax  atomic.Int64 // v2.8.1: ns; overrides staleFor when > 0
	now       func() time.Time
}

func NewDNSCache(budget, maxEntries int64, nShards int) *DNSCache {
	c := &DNSCache{seed: maphash.MakeSeed(), budget: budget, maxEntries: maxEntries,
		staleFor: time.Hour, minTTL: 0, maxTTL: 24 * time.Hour, negMinTTL: defaultNegMinTTL, negMaxTTL: defaultNegMaxTTL,
		pinnedFloor: defaultPinnedFloor, now: time.Now}
	for i := 0; i < nShards; i++ {
		c.shards = append(c.shards, &cshard{m: map[string]*CacheEntry{}})
	}
	return c
}

func cacheKey(name string, qtype, qclass uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + dns.TypeToString[qtype] + "|" + dns.ClassToString[qclass]
}

func (c *DNSCache) shard(k string) *cshard {
	return c.shards[maphash.String(c.seed, k)%uint64(len(c.shards))]
}

// Get returns the entry and its state: fresh, stale (servable per RFC 8767), or nil.
func (c *DNSCache) Get(k string) (e *CacheEntry, fresh bool) {
	s := c.shard(k)
	s.mu.RLock()
	e = s.m[k]
	s.mu.RUnlock()
	if e == nil {
		return nil, false
	}
	now := c.now()
	if now.Before(e.Expires) {
		return e, true
	}
	sf := c.staleFor
	if v := c.staleMax.Load(); v > 0 { // v2.8.1 serve-stale: up to a day
		sf = time.Duration(v)
	}
	if now.Before(e.Expires.Add(sf)) {
		return e, false
	}
	return nil, false
}

// RFC 2308 negative caching (v2.5.0): NXDOMAIN / NODATA are cached for
// min(SOA TTL, SOA MINIMUM), clamped to [negMinTTL, negMaxTTL]. Without an SOA in the
// authority section the answer is kept for negNoSOATTL only.
const (
	defaultNegMinTTL   = 5 * time.Second
	defaultNegMaxTTL   = 300 * time.Second
	negNoSOATTL        = 30 * time.Second
	defaultPinnedFloor = 300 * time.Second
)

// ttlFor computes the cache lifetime of a response.
func (c *DNSCache) ttlFor(m *dns.Msg) (time.Duration, bool) {
	neg := m.Rcode == dns.RcodeNameError || (m.Rcode == dns.RcodeSuccess && len(m.Answer) == 0)
	if neg {
		return c.negTTL(m), true
	}
	var ttl uint32 = 0
	first := true
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		if first || rr.Header().Ttl < ttl {
			ttl, first = rr.Header().Ttl, false
		}
	}
	d := time.Duration(ttl) * time.Second
	// Upstream TTLs are honoured (v2.5.0: the global 300 s minimum is gone, -min-ttl now
	// defaults to 0). exemptFloor keeps TTL-0 answers from being re-fetched on every query.
	floor := max(c.minTTL, exemptFloor)
	switch {
	case c.honourTTL(m):
		floor = exemptFloor // CDN / HTTPS / SVCB: never stretched, whatever -min-ttl says
	case c.pinnedName(m):
		floor = max(floor, c.pinnedFloor)
	default:
		if c.adapt != nil {
			d = max(d, floor)
			d = c.adapt(m, d, max(c.minTTL, 60*time.Second))
		}
	}
	return min(max(d, floor), max(c.maxTTL, exemptFloor)), false
}

// negTTL is the RFC 2308 section 5 negative-cache lifetime.
func (c *DNSCache) negTTL(m *dns.Msg) time.Duration {
	d := negNoSOATTL
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			d = time.Duration(min(soa.Hdr.Ttl, soa.Minttl)) * time.Second
			break
		}
	}
	lo, hi := c.negMinTTL, c.negMaxTTL
	if hi < lo {
		hi = lo
	}
	return min(max(d, lo), hi)
}

func (c *DNSCache) pinnedName(m *dns.Msg) bool {
	if c.isPinned == nil || c.pinnedFloor <= 0 || len(m.Question) == 0 {
		return false
	}
	return c.isPinned(strings.TrimSuffix(strings.ToLower(m.Question[0].Name), "."))
}

// exemptFloor stops TTL-0 answers from being re-fetched on every query.
const exemptFloor = 5 * time.Second

// honourTTL reports answers that must keep (nearly) their upstream TTL: HTTPS/SVCB
// (type 65/64, which carry ECH keys and alt endpoints that rotate) and names under the
// exempt CDN suffixes.
func (c *DNSCache) honourTTL(m *dns.Msg) bool {
	if len(m.Question) == 0 {
		return false
	}
	q := m.Question[0]
	if q.Qtype == dns.TypeHTTPS || q.Qtype == dns.TypeSVCB {
		return true
	}
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	for _, s := range c.minTTLExempt {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// Set caches a response (only NOERROR / NXDOMAIN are cached).
func (c *DNSCache) Set(k string, m *dns.Msg) *CacheEntry {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError || m.Truncated {
		return nil
	}
	ttl, neg := c.ttlFor(m)
	now := c.now()
	cp := m.Copy()
	cp.Extra = stripOPT(cp.Extra)
	e := &CacheEntry{Msg: cp, Stored: now, Expires: now.Add(ttl), OrigTTL: uint32(ttl / time.Second), Negative: neg}
	e.size = int64(cp.Len()) + int64(len(k)) + 256
	s := c.shard(k)
	per := c.budget / int64(len(c.shards))
	s.mu.Lock()
	if old, ok := s.m[k]; ok {
		s.bytes -= old.size
		e.Hits.Store(old.Hits.Load())
		c.entries.Add(-1)
	}
	s.m[k] = e
	s.bytes += e.size
	c.entries.Add(1)
	c.evictLocked(s, per, k)
	s.mu.Unlock()
	return e
}

// evictLocked drops expired-beyond-stale first, then least-hit sampled entries.
func (c *DNSCache) evictLocked(s *cshard, per int64, keep string) {
	perEntries := c.maxEntries / int64(len(c.shards))
	if perEntries < 1 {
		perEntries = 1
	}
	for s.bytes > per || int64(len(s.m)) > perEntries {
		var victim string
		var vh int64 = -1
		n := 0
		now := c.now()
		for k, e := range s.m { // random sample of 8 (map order is randomised)
			if k == keep {
				continue
			}
			if now.After(e.Expires.Add(c.staleFor)) {
				victim = k
				break
			}
			if h := e.Hits.Load(); vh < 0 || h < vh {
				victim, vh = k, h
			}
			if n++; n >= 8 {
				break
			}
		}
		if victim == "" {
			return
		}
		s.bytes -= s.m[victim].size
		delete(s.m, victim)
		c.entries.Add(-1)
		c.evictions.Add(1)
	}
}

func (c *DNSCache) Bytes() (b int64) {
	for _, s := range c.shards {
		s.mu.RLock()
		b += s.bytes
		s.mu.RUnlock()
	}
	return
}

func stripOPT(rr []dns.RR) []dns.RR {
	out := rr[:0]
	for _, r := range rr {
		if r.Header().Rrtype != dns.TypeOPT {
			out = append(out, r)
		}
	}
	return out
}

// Reply builds an answer for req from the entry, with TTLs decremented (or 30s if stale).
func (e *CacheEntry) Reply(req *dns.Msg, now time.Time, stale bool) *dns.Msg {
	m := e.Msg.Copy()
	m.Id = req.Id
	m.Response = true
	m.Question = req.Question
	var ttl uint32
	if stale {
		ttl = 30 // RFC 8767 recommends 30s
	} else {
		left := e.Expires.Sub(now) / time.Second
		if e.OrigTTL > 0 { // a wall-clock jump backwards must not stretch a restored entry
			left = min(left, time.Duration(e.OrigTTL))
		}
		ttl = uint32(max(left, 1))
	}
	for _, sec := range [][]dns.RR{m.Answer, m.Ns, m.Extra} {
		for _, rr := range sec {
			if rr.Header().Rrtype != dns.TypeOPT {
				rr.Header().Ttl = ttl
			}
		}
	}
	return m
}

// Flush drops every cached entry.
func (c *DNSCache) Flush() int64 {
	var n int64
	for _, s := range c.shards {
		s.mu.Lock()
		n += int64(len(s.m))
		s.m = map[string]*CacheEntry{}
		s.bytes = 0
		s.mu.Unlock()
	}
	c.entries.Add(-n)
	return n
}

// Delete drops one entry (v2.8.1 Pro cache inspector).
func (c *DNSCache) Delete(k string) bool {
	s := c.shard(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok {
		return false
	}
	s.bytes -= e.size
	delete(s.m, k)
	c.entries.Add(-1)
	return true
}

// Find returns up to limit entries whose key contains sub (lower-case), most-hit first.
func (c *DNSCache) Find(sub string, limit int) (keys []string, ents []*CacheEntry, total int) {
	sub = strings.ToLower(sub)
	type kv struct {
		k string
		e *CacheEntry
	}
	var all []kv
	for _, s := range c.shards {
		s.mu.RLock()
		for k, e := range s.m {
			if sub == "" || strings.Contains(k, sub) {
				total++
				if len(all) < 20000 { // bounded: a 1M-entry cache must not stall the server
					all = append(all, kv{k, e})
				}
			}
		}
		s.mu.RUnlock()
	}
	sort.Slice(all, func(i, j int) bool { return all[i].e.Hits.Load() > all[j].e.Hits.Load() })
	for i := 0; i < len(all) && i < limit; i++ {
		keys, ents = append(keys, all[i].k), append(ents, all[i].e)
	}
	return
}
