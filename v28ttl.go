// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.0 adaptive TTL: answers whose address set never changed over >= 3 fetches are kept
// up to 2x longer (max 1 h, never past -max-ttl); answers that change on most fetches are
// re-asked sooner (half, never under max(-min-ttl, 60 s)). CDN-exempt names, HTTPS/SVCB,
// pinned names and negative answers are never touched.

import (
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type volEntry struct {
	hash    uint64
	obs     uint16
	changes uint16
}

type Volatility struct {
	mu        sync.Mutex
	m         map[string]*volEntry
	max       int
	On        atomic.Bool
	Extended  atomic.Int64
	Shortened atomic.Int64
}

func NewVolatility(max int) *Volatility { return &Volatility{m: map[string]*volEntry{}, max: max} }

func addrHash(m *dns.Msg) (uint64, bool) {
	var ips []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		}
	}
	if len(ips) == 0 {
		return 0, false
	}
	sort.Strings(ips)
	h := fnv.New64a()
	h.Write([]byte(strings.Join(ips, ",")))
	return h.Sum64(), true
}

// Adapt observes m and returns the adjusted lifetime d (already floored by the cache).
func (v *Volatility) Adapt(m *dns.Msg, d, floor time.Duration) time.Duration {
	if v == nil || len(m.Question) == 0 {
		return d
	}
	q := m.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return d
	}
	h, ok := addrHash(m)
	if !ok {
		return d
	}
	k := strings.ToLower(q.Name) + dns.TypeToString[q.Qtype]
	v.mu.Lock()
	e := v.m[k]
	if e == nil {
		if len(v.m) >= v.max {
			n := 0
			for kk := range v.m { // drop ~10 % (random map order)
				delete(v.m, kk)
				if n++; n >= v.max/10+1 {
					break
				}
			}
		}
		e = &volEntry{hash: h}
		v.m[k] = e
	} else if e.hash != h {
		e.hash = h
		if e.changes < 60000 {
			e.changes++
		}
	}
	if e.obs < 60000 {
		e.obs++
	}
	obs, ch := e.obs, e.changes
	v.mu.Unlock()
	if !v.On.Load() {
		return d
	}
	switch {
	case obs >= 4 && int(ch)*2 > int(obs) && d > floor:
		v.Shortened.Add(1)
		return max(d/2, floor)
	case obs >= 3 && ch == 0 && d < time.Hour:
		v.Extended.Add(1)
		return min(2*d, time.Hour)
	}
	return d
}

func (v *Volatility) Size() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.m)
}
