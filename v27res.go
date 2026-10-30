// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.7.0 Live graph extras: process / host CPU %, memory, and active clients (distinct
// client IPs seen in the last 60 s). Sampled only while the Live view is open. Client
// IPs stay in memory; the API returns only the count unless "Devices by volume" is on.

import (
	"runtime/metrics"
	"sort"
	"sync"
	"time"
)

const activeWindow = 60 * time.Second

type cpuTimes struct {
	proc, busy, total float64 // seconds (proc, host busy, host total)
	ok                bool
}

type resSampler struct {
	last  cpuTimes
	lastT time.Time
	ms    []metrics.Sample
}

func newResSampler() *resSampler {
	return &resSampler{ms: []metrics.Sample{{Name: "/memory/classes/total:bytes"}}}
}

// sample returns process CPU % (of one machine, 0-100 across all cores), host CPU %,
// Go process memory MB and host memory used %. -1 = unknown.
func (r *resSampler) sample(now time.Time) (procPct, hostPct, memMB, hostMemPct float64) {
	procPct, hostPct, hostMemPct = -1, -1, -1
	c := readCPU()
	if c.ok && r.last.ok {
		wall := now.Sub(r.lastT).Seconds()
		if wall > 0 {
			procPct = clampPct(100 * (c.proc - r.last.proc) / wall / float64(numCPU()))
		}
		if dt := c.total - r.last.total; dt > 0 {
			hostPct = clampPct(100 * (c.busy - r.last.busy) / dt)
		}
	}
	r.last, r.lastT = c, now
	metrics.Read(r.ms)
	if r.ms[0].Value.Kind() == metrics.KindUint64 {
		memMB = float64(r.ms[0].Value.Uint64()) / (1 << 20)
	}
	if p, ok := hostMemUsedPct(); ok {
		hostMemPct = p
	}
	return
}

func clampPct(v float64) float64 { return min(max(v, 0), 100) }

// activeClients: last-seen time per client IP, memory only, capped.
type activeClients struct {
	mu   sync.Mutex
	seen map[string]int64
}

func (a *activeClients) See(ip string, now time.Time) {
	if ip == "" {
		return
	}
	a.mu.Lock()
	if a.seen == nil {
		a.seen = map[string]int64{}
	}
	if len(a.seen) < 65536 {
		a.seen[ip] = now.UnixNano()
	} else if _, ok := a.seen[ip]; ok {
		a.seen[ip] = now.UnixNano()
	}
	a.mu.Unlock()
}

// Count prunes entries older than 60 s and returns how many remain.
func (a *activeClients) Count(now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	cut := now.Add(-activeWindow).UnixNano()
	for k, t := range a.seen {
		if t < cut {
			delete(a.seen, k)
		}
	}
	return len(a.seen)
}

func (a *activeClients) List(now time.Time) []string {
	a.Count(now)
	a.mu.Lock()
	out := make([]string, 0, len(a.seen))
	for k := range a.seen {
		out = append(out, k)
	}
	a.mu.Unlock()
	sort.Strings(out)
	return out
}
