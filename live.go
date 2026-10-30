// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.6.1 Live graph: a 1-second in-memory ring (120 s) for the Health tab's "Live" view.
// Sampling runs only while someone has polled /api/health/live in the last 30 s, so it
// costs nothing when nobody is watching. Memory only, never persisted.

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

const (
	liveKeep  = 120
	liveIdle  = 30 * time.Second
	liveCount = 11 // len(Stats.Hist)
)

type liveSnap struct {
	q, hits, misses, fail int64
	hist                  [liveCount]int64
}

// LivePoint is one second of traffic.
type LivePoint struct {
	T       int64   `json:"t"` // unix seconds (end of the second)
	QPS     float64 `json:"qps"`
	AvgMS   float64 `json:"avg_ms"` // estimated from the latency histogram
	P95MS   float64 `json:"p95_ms"` // histogram bucket upper bound
	HitPct  float64 `json:"hit_pct"`
	FailPS  float64 `json:"fail_ps"`
	Answers int64   `json:"answers"`
	// v2.7.0: -1 = unknown on this system
	CPUProc    float64 `json:"cpu_proc"`     // GoProxy process, % of the whole machine
	CPUHost    float64 `json:"cpu_host"`     // whole machine
	MemMB      float64 `json:"mem_mb"`       // GoProxy (Go runtime total)
	HostMemPct float64 `json:"host_mem_pct"` // whole machine
	Clients    int     `json:"clients"`      // distinct client IPs in the last 60 s
}

type Live struct {
	mu      sync.Mutex
	pts     []LivePoint
	last    liveSnap
	lastT   time.Time
	primed  bool
	watched atomic.Int64 // unix nanos of the last poll
	now     func() time.Time
	res     *resSampler
	act     activeClients
}

func NewLive() *Live { return &Live{now: time.Now, res: newResSampler()} }

// SeeClient records a client IP for the active-clients count (only while watched).
func (l *Live) SeeClient(ip string) {
	if l != nil && l.Active() {
		l.act.See(ip, l.now())
	}
}

func (l *Live) Touch()       { l.watched.Store(l.now().UnixNano()) }
func (l *Live) Active() bool { return l.now().UnixNano()-l.watched.Load() < int64(liveIdle) }

// histMid: representative ms per histogram bin (bins end at histBounds; the last is > 1000 ms).
func histMid(i int) float64 {
	if i >= len(histBounds) {
		return 2000
	}
	lo := 0.0
	if i > 0 {
		lo = histBounds[i-1]
	}
	return (lo + histBounds[i]) / 2
}

func histHi(i int) float64 {
	if i >= len(histBounds) {
		return 2000
	}
	return histBounds[i]
}

// Sample records the deltas since the previous sample as one point.
func (l *Live) Sample(cur liveSnap) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if !l.primed || now.Sub(l.lastT) > 5*time.Second { // first sample or resumed after idle
		if l.primed { // gap: drop old points so the chart doesn't join across it
			l.pts = nil
		}
		l.last, l.lastT, l.primed = cur, now, true
		if l.res != nil {
			l.res.sample(now) // prime CPU deltas
		}
		return
	}
	dt := now.Sub(l.lastT).Seconds()
	if dt <= 0 {
		return
	}
	pos := func(a, b int64) int64 { return max(a-b, 0) }
	p := LivePoint{T: now.Unix()}
	q := pos(cur.q, l.last.q)
	p.QPS = float64(q) / dt
	p.FailPS = float64(pos(cur.fail, l.last.fail)) / dt
	h, m := pos(cur.hits, l.last.hits), pos(cur.misses, l.last.misses)
	if h+m > 0 {
		p.HitPct = 100 * float64(h) / float64(h+m)
	}
	var d [liveCount]int64
	var n int64
	var sum float64
	for i := range d {
		d[i] = pos(cur.hist[i], l.last.hist[i])
		n += d[i]
		sum += float64(d[i]) * histMid(i)
	}
	if n > 0 {
		p.Answers, p.AvgMS = n, sum/float64(n)
		need, acc := (n*95+99)/100, int64(0)
		for i := range d {
			if acc += d[i]; acc >= need {
				p.P95MS = histHi(i)
				break
			}
		}
	}
	p.CPUProc, p.CPUHost, p.MemMB, p.HostMemPct = -1, -1, 0, -1
	if l.res != nil {
		p.CPUProc, p.CPUHost, p.MemMB, p.HostMemPct = l.res.sample(now)
	}
	p.Clients = l.act.Count(now)
	l.last, l.lastT = cur, now
	l.pts = append(l.pts, p)
	if len(l.pts) > liveKeep {
		l.pts = append(l.pts[:0:0], l.pts[len(l.pts)-liveKeep:]...)
	}
}

func (l *Live) Points() []LivePoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]LivePoint(nil), l.pts...)
}

func (s *DNSServer) liveSnap() liveSnap {
	st := s.stats
	v := liveSnap{q: st.Queries.Load(), hits: st.Hits.Load() + st.StaleHits.Load(),
		misses: st.Misses.Load() + st.StaleRescued.Load(), fail: st.Failures.Load()}
	for i := range v.hist {
		v.hist[i] = st.Hist[i].Load()
	}
	return v
}

// RunLive samples once a second, only while the Live view is open somewhere.
func (s *DNSServer) RunLive(ctx context.Context) {
	if s.live == nil {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.live.Active() {
				s.live.Sample(s.liveSnap())
			}
		}
	}
}

func (s *DNSServer) serveHealthLive(w http.ResponseWriter, r *http.Request) {
	if s.live == nil {
		http.Error(w, "live view unavailable", http.StatusServiceUnavailable)
		return
	}
	if !s.live.Active() { // waking up: prime so the next second has a delta
		s.live.Touch()
		s.live.Sample(s.liveSnap())
	}
	s.live.Touch()
	var ips []string // names/IPs only behind the "Devices by volume" approval flag
	if s.settings != nil && s.settings.Get().Feature("device_volume") {
		ips = s.live.act.List(s.live.now())
	}
	serveLiveJSONClients(s.live, w, ips)
}

func serveLiveJSON(l *Live, w http.ResponseWriter) { serveLiveJSONClients(l, w, nil) }

func serveLiveJSONClients(l *Live, w http.ResponseWriter, ips []string) {
	m := map[string]any{"step_sec": 1, "keep": liveKeep, "points": l.Points(), "cpus": numCPU()}
	if ips != nil {
		m["client_ips"] = ips
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(m)
}
