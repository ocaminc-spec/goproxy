// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"
)

// Health history: one bucket per 10 minutes, 24 h kept (144 buckets), persisted to disk.
const (
	healthBucket = 10 * time.Minute
	healthKeep   = 144
)

// HealthBucket holds raw counter deltas for one 10-minute window; scores are derived.
type HealthBucket struct {
	Start    int64 `json:"start"` // unix seconds, aligned to 10 min
	Queries  int64 `json:"queries"`
	Hits     int64 `json:"hits"` // fresh + stale cache answers
	Misses   int64 `json:"misses"`
	Failures int64 `json:"failures"` // SERVFAIL sent to devices
	UpQ      int64 `json:"up_queries"`
	UpErr    int64 `json:"up_errors"`
	Fast     int64 `json:"fast"` // answered in < 50 ms
	Slow     int64 `json:"slow"` // answered in >= 250 ms
	Timed    int64 `json:"timed"`
	// v2.4: self-test canary cycles (kept out of Overall)
	CanaryOK   int64 `json:"canary_ok,omitempty"`
	CanaryFail int64 `json:"canary_fail,omitempty"`
	// v2.7.0: answers per latency band (histBounds; last = over 1 s) for the 24 h heat grid
	Hist [11]int64 `json:"hist,omitempty"`
}

type HealthScores struct {
	Overall  int `json:"overall"` // -1 = no data
	Upstream int `json:"upstream"`
	Cache    int `json:"cache"`
	Latency  int `json:"latency"`
	Errors   int `json:"errors"`
	Canary   int `json:"canary"` // v2.4, -1 = no self-test in this window; not part of Overall
}

func clamp100(v float64) int { return int(min(max(v, 0), 100)) }

// Scores maps a bucket to 0..100 per area (-1 = no traffic in the window).
//   - Upstream: share of upstream lookups that did not fail (errors x2 penalty).
//   - Cache: hit ratio, where 80 % or better scores 100.
//   - Latency: share of answers under 50 ms, minus a penalty for answers >= 250 ms.
//   - Errors: 100 minus 10 points per 1 % of queries answered SERVFAIL.
//
// Overall: the average, but never more than 15 above the weakest area.
func (b HealthBucket) Scores() HealthScores {
	canary := -1
	if t := b.CanaryOK + b.CanaryFail; t > 0 {
		canary = clamp100(100 * float64(b.CanaryOK) / float64(t))
	}
	if b.Queries == 0 {
		return HealthScores{-1, -1, -1, -1, -1, canary}
	}
	s := HealthScores{Upstream: 100, Canary: canary}
	if b.UpQ > 0 {
		s.Upstream = clamp100(100 - 200*float64(b.UpErr)/float64(b.UpQ))
	}
	s.Cache = 100
	if t := b.Hits + b.Misses; t > 0 {
		s.Cache = clamp100(float64(b.Hits) / float64(t) / 0.8 * 100)
	}
	s.Latency = 100
	if b.Timed > 0 {
		s.Latency = clamp100(100*float64(b.Fast)/float64(b.Timed) - 300*float64(b.Slow)/float64(b.Timed))
	}
	s.Errors = clamp100(100 - 1000*float64(b.Failures)/float64(b.Queries))
	lo := min(s.Upstream, s.Cache, s.Latency, s.Errors)
	s.Overall = min((s.Upstream+s.Cache+s.Latency+s.Errors)/4, lo+15)
	return s
}

type healthSnap struct {
	q, hits, misses, fail, upq, uperr, fast, slow, timed int64
	hist                                                 [11]int64
}

type Health struct {
	mu      sync.Mutex
	buckets []HealthBucket // oldest first
	fine    []HealthBucket // v2.6.1: 5 s buckets, last 5 min, memory only
	last    healthSnap
	primed  bool
	path    string
	now     func() time.Time
}

func NewHealth(path string) *Health { return &Health{path: path, now: time.Now} }

func (s *DNSServer) healthSnap() healthSnap {
	st := s.stats
	var h healthSnap
	h.q = st.Queries.Load()
	h.hits = st.Hits.Load() + st.StaleHits.Load()
	h.misses = st.Misses.Load() + st.StaleRescued.Load()
	h.fail = st.Failures.Load()
	for _, u := range append(append([]*Upstream{}, s.res.Ups()...), s.res.Fallback...) {
		h.upq += u.Queries.Load()
		h.uperr += u.Errors.Load()
	}
	for i := range st.Hist {
		v := st.Hist[i].Load()
		h.hist[i] = v
		h.timed += v
		if i < len(histBounds) && histBounds[i] <= 50 {
			h.fast += v
		}
		if i >= 9 { // >= 250 ms
			h.slow += v
		}
	}
	return h
}

// Sample adds the counter deltas since the last sample to the current bucket.
func (h *Health) Sample(cur healthSnap) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.primed {
		h.last, h.primed = cur, true
		return
	}
	d, l := cur, h.last
	h.last = cur
	start := h.now().Truncate(healthBucket).Unix()
	if n := len(h.buckets); n == 0 || h.buckets[n-1].Start != start {
		h.buckets = append(h.buckets, HealthBucket{Start: start})
		if len(h.buckets) > healthKeep {
			h.buckets = append([]HealthBucket(nil), h.buckets[len(h.buckets)-healthKeep:]...)
		}
	}
	pos := func(a, b int64) int64 { return max(a-b, 0) } // counters restored from disk never go backwards
	delta := HealthBucket{Queries: pos(d.q, l.q), Hits: pos(d.hits, l.hits), Misses: pos(d.misses, l.misses),
		Failures: pos(d.fail, l.fail), UpQ: pos(d.upq, l.upq), UpErr: pos(d.uperr, l.uperr),
		Fast: pos(d.fast, l.fast), Slow: pos(d.slow, l.slow), Timed: pos(d.timed, l.timed)}
	for i := range delta.Hist {
		delta.Hist[i] = pos(d.hist[i], l.hist[i])
	}
	h.buckets[len(h.buckets)-1].add(delta)
	h.fineBucket().add(delta)
}

func (b *HealthBucket) add(d HealthBucket) {
	b.Queries += d.Queries
	b.Hits += d.Hits
	b.Misses += d.Misses
	b.Failures += d.Failures
	b.UpQ += d.UpQ
	b.UpErr += d.UpErr
	b.Fast += d.Fast
	b.Slow += d.Slow
	b.Timed += d.Timed
	b.CanaryOK += d.CanaryOK
	b.CanaryFail += d.CanaryFail
	for i := range b.Hist {
		b.Hist[i] += d.Hist[i]
	}
}

// v2.6.1: short windows. A rolling in-memory ring of 5 s buckets (5 min kept, not persisted)
// backs the Health tab's 1-minute (12 x 5 s) and 5-minute (20 x 15 s) views.
const (
	fineBucket = 5 * time.Second
	fineKeep   = 60
)

// healthWindows: window name -> bucket size and count. "" / "24h" is the persisted 10-minute history.
var healthWindows = map[string]struct {
	step time.Duration
	n    int
}{"1m": {5 * time.Second, 12}, "5m": {15 * time.Second, 20}}

// fineBucket returns the current 5 s bucket (caller holds h.mu).
func (h *Health) fineBucket() *HealthBucket {
	start := h.now().Truncate(fineBucket).Unix()
	if n := len(h.fine); n == 0 || h.fine[n-1].Start != start {
		h.fine = append(h.fine, HealthBucket{Start: start})
		if len(h.fine) > fineKeep {
			h.fine = append(h.fine[:0:0], h.fine[len(h.fine)-fineKeep:]...)
		}
	}
	return &h.fine[len(h.fine)-1]
}

// WindowView returns n aligned buckets of size step (a multiple of 5 s) built from the fine ring.
func (h *Health) WindowView(step time.Duration, n int) []healthView {
	h.mu.Lock()
	defer h.mu.Unlock()
	cur := h.now().Truncate(step)
	first := cur.Add(-time.Duration(n-1) * step).Unix()
	ss := int64(step / time.Second)
	out := make([]healthView, n)
	for i := range out {
		out[i].Start = first + int64(i)*ss
	}
	for _, b := range h.fine {
		if b.Start < first {
			continue
		}
		i := int((b.Start - first) / ss)
		if i >= n {
			continue
		}
		start := out[i].Start
		out[i].HealthBucket.add(b)
		out[i].Start = start
	}
	for i := range out {
		out[i].End = out[i].Start + ss
		out[i].Scores = out[i].HealthBucket.Scores()
	}
	return out
}

// AddCanary records canary cycles in the current bucket.
func (h *Health) AddCanary(ok, fail int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	start := h.now().Truncate(healthBucket).Unix()
	if n := len(h.buckets); n == 0 || h.buckets[n-1].Start != start {
		h.buckets = append(h.buckets, HealthBucket{Start: start})
		if len(h.buckets) > healthKeep {
			h.buckets = append([]HealthBucket(nil), h.buckets[len(h.buckets)-healthKeep:]...)
		}
	}
	h.buckets[len(h.buckets)-1].CanaryOK += ok
	h.buckets[len(h.buckets)-1].CanaryFail += fail
	f := h.fineBucket()
	f.CanaryOK += ok
	f.CanaryFail += fail
}

type healthView struct {
	HealthBucket
	End    int64        `json:"end"`
	Scores HealthScores `json:"scores"`
}

// View returns the last 24 h as 144 aligned buckets (empty ones included).
func (h *Health) View() []healthView {
	h.mu.Lock()
	defer h.mu.Unlock()
	by := map[int64]HealthBucket{}
	for _, b := range h.buckets {
		by[b.Start] = b
	}
	cur := h.now().Truncate(healthBucket)
	out := make([]healthView, 0, healthKeep)
	for i := healthKeep - 1; i >= 0; i-- {
		st := cur.Add(-time.Duration(i) * healthBucket).Unix()
		b, ok := by[st]
		if !ok {
			b = HealthBucket{Start: st}
		}
		out = append(out, healthView{b, st + int64(healthBucket/time.Second), b.Scores()})
	}
	return out
}

func (h *Health) Save() error {
	if h.path == "" {
		return nil
	}
	h.mu.Lock()
	b, err := json.Marshal(h.buckets)
	h.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.WriteFile(h.path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(h.path+".tmp", h.path)
}

func (h *Health) Load() error {
	if h.path == "" {
		return nil
	}
	b, err := os.ReadFile(h.path)
	if err != nil {
		return err
	}
	var bs []HealthBucket
	if err := json.Unmarshal(b, &bs); err != nil {
		return err
	}
	cutoff := h.now().Add(-healthKeep * healthBucket).Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, x := range bs {
		if x.Start > cutoff {
			h.buckets = append(h.buckets, x)
		}
	}
	if len(h.buckets) > healthKeep {
		h.buckets = h.buckets[len(h.buckets)-healthKeep:]
	}
	return nil
}

// RunHealth samples every 5 s (v2.6.1, for the 1-minute view) and saves every 10 min.
func (s *DNSServer) RunHealth(ctx context.Context) {
	s.health.Sample(s.healthSnap())
	t := time.NewTicker(fineBucket)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.health.Sample(s.healthSnap())
			if n++; n%120 == 0 {
				_ = s.health.Save()
			}
		}
	}
}

func (s *DNSServer) serveHealth(w http.ResponseWriter, r *http.Request) {
	s.health.Sample(s.healthSnap()) // include the last few seconds
	serveHealthJSON(s.health, w, r)
}

func serveHealthJSON(h *Health, w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if wv, ok := healthWindows[r.URL.Query().Get("window")]; ok {
		_ = json.NewEncoder(w).Encode(map[string]any{"window": r.URL.Query().Get("window"), "bucket_sec": int(wv.step / time.Second), "buckets": h.WindowView(wv.step, wv.n)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"window": "24h", "bucket_sec": int(healthBucket / time.Second), "buckets": h.View()})
}
