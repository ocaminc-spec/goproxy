// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.0 smart upstreams: every upstream is probed the same way once a minute (fair latency
// + success rate), lookups race only the best N (default 3) plus a rotating explorer every
// exploreEvery lookups, slow or failing upstreams are demoted for a while, and self-healing
// can widen the race back to everybody.

import (
	"context"
	"sort"
	"time"

	"github.com/miekg/dns"
)

const (
	exploreEvery  = 20
	defaultSmartN = 3
	demoteFor     = 5 * time.Minute
	unknownScore  = 10_000.0
)

var probeNames = []string{"www.google.com.", "www.cloudflare.com.", "www.apple.com.", "www.microsoft.com."}

func (rs *Resolver) smartOn() bool {
	return rs.Smart.Load() && rs.clock().UnixNano() >= rs.widenUntil.Load()
}

func (rs *Resolver) smartN() int {
	if n := int(rs.SmartN.Load()); n > 0 {
		return n
	}
	return defaultSmartN
}

// Widen races every upstream again until d from now (self-healing).
func (rs *Resolver) Widen(d time.Duration) { rs.widenUntil.Store(rs.clock().Add(d).UnixNano()) }

func (rs *Resolver) Widened() bool { return rs.clock().UnixNano() < rs.widenUntil.Load() }

func (u *Upstream) demoted(now int64) bool { return now < u.demoteUntil.Load() }

// smartScore: lower is better. Probe latency (ms) inflated by the failure rate, with big
// penalties for an open breaker or a demotion. Unmeasured upstreams rank after measured ones.
func (u *Upstream) smartScore(now int64) float64 {
	pe := float64(u.probeEWMA.Load()) / 1e6
	if pe == 0 {
		pe = float64(u.ewma.Load()) / 1e6
	}
	sc := unknownScore
	if pe > 0 {
		sc = pe * (1 + 4*float64(u.errPPM.Load())/1e6)
	}
	if u.open() {
		sc += 1e6
	}
	if u.demoted(now) {
		sc += 1e5
	}
	return sc
}

// smartRank: encrypted upstreams best first (all upstreams if none is encrypted).
func (rs *Resolver) smartRank() (ranked, plain []*Upstream) {
	now := rs.clock().UnixNano()
	for _, u := range rs.Ups() {
		if u.Encrypted() {
			ranked = append(ranked, u)
		} else {
			plain = append(plain, u)
		}
	}
	if len(ranked) == 0 {
		ranked, plain = plain, nil
	}
	sc := make(map[*Upstream]float64, len(ranked))
	for _, u := range ranked {
		sc[u] = u.smartScore(now)
	}
	sort.SliceStable(ranked, func(i, j int) bool { return sc[ranked[i]] < sc[ranked[j]] })
	return ranked, plain
}

// smartSplit: race the top N (+ an explorer now and then); everything else is a fallback.
func (rs *Resolver) smartSplit() (raced, fallback []*Upstream) {
	ranked, plain := rs.smartRank()
	n := min(rs.smartN(), len(ranked))
	raced = append(raced, ranked[:n]...)
	rest := ranked[n:]
	if len(rest) > 0 {
		if c := rs.exploreCtr.Add(1); c%exploreEvery == 0 {
			i := int(c/exploreEvery) % len(rest)
			raced = append(raced, rest[i])
			rest = append(append([]*Upstream{}, rest[:i]...), rest[i+1:]...)
		}
	}
	fallback = append(append(fallback, rest...), plain...)
	seen := map[string]bool{}
	for _, u := range append(append([]*Upstream{}, raced...), fallback...) {
		seen[u.URL] = true
	}
	for _, u := range rs.Fallback {
		if !seen[u.URL] {
			fallback = append(fallback, u)
		}
	}
	return raced, fallback
}

// Probe asks every live upstream the same small question and records the outcome.
func (rs *Resolver) Probe(ctx context.Context, n int) {
	name := probeNames[n%len(probeNames)]
	done := make(chan struct{})
	ups := rs.Ups()
	for _, u := range ups {
		go func() {
			defer func() { done <- struct{}{} }()
			q := new(dns.Msg)
			q.SetQuestion(name, dns.TypeA)
			q.RecursionDesired = true
			q.SetEdns0(1232, false)
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			t0 := time.Now()
			r, _, err := u.exchange(c, q)
			u.lastProbe.Store(time.Now().UnixNano())
			if err == nil && validAnswer(r) {
				ns := time.Since(t0).Nanoseconds()
				if old := u.probeEWMA.Load(); old == 0 {
					u.probeEWMA.Store(ns)
				} else {
					u.probeEWMA.Store(old + (ns-old)/4)
				}
			}
		}()
	}
	for range ups {
		<-done
	}
}

// autoDemote returns the upstreams it just demoted (failure rate > 30 % or 3x slower than
// the best and above 150 ms). Never demotes the last healthy N.
func (rs *Resolver) autoDemote() []*Upstream {
	now := rs.clock().UnixNano()
	ranked, _ := rs.smartRank()
	var best int64
	healthy := 0
	for _, u := range ranked {
		if pe := u.probeEWMA.Load(); pe > 0 && !u.open() && (best == 0 || pe < best) {
			best = pe
		}
		if !u.open() && !u.demoted(now) {
			healthy++
		}
	}
	var out []*Upstream
	for i := len(ranked) - 1; i >= 0; i-- {
		u := ranked[i]
		if u.demoted(now) || healthy <= rs.smartN() {
			continue
		}
		pe := u.probeEWMA.Load()
		bad := float64(u.errPPM.Load())/1e6 > 0.30 || (best > 0 && pe > 3*best && pe > int64(150*time.Millisecond))
		if bad {
			u.demoteUntil.Store(now + int64(demoteFor))
			healthy--
			out = append(out, u)
		}
	}
	return out
}

// DemoteWorstRaced demotes the worst of the currently raced upstreams (self-healing).
func (rs *Resolver) DemoteWorstRaced(d time.Duration) *Upstream {
	ranked, _ := rs.smartRank()
	n := min(rs.smartN(), len(ranked))
	if n < 2 || len(ranked) <= n {
		return nil
	}
	u := ranked[n-1]
	u.demoteUntil.Store(rs.clock().Add(d).UnixNano())
	return u
}

type SmartStat struct {
	Name     string  `json:"name"`
	Label    string  `json:"label,omitempty"`
	Kind     string  `json:"kind"`
	Rank     int     `json:"rank"`
	Raced    bool    `json:"raced"`
	Demoted  bool    `json:"demoted"`
	DemoteS  float64 `json:"demote_sec,omitempty"`
	Breaker  bool    `json:"breaker"`
	Score    float64 `json:"score"`
	ProbeMs  float64 `json:"probe_ms"`
	EwmaMs   float64 `json:"ewma_ms"`
	Success  float64 `json:"success"`
	WinRate  float64 `json:"win_rate"`
	Wins     int64   `json:"wins"`
	Queries  int64   `json:"queries"`
	ProbeAgo float64 `json:"probe_ago_sec,omitempty"`
}

func (rs *Resolver) SmartStats() []SmartStat {
	now := rs.clock().UnixNano()
	ranked, plain := rs.smartRank()
	n := min(rs.smartN(), len(ranked))
	var total int64
	all := append(append([]*Upstream{}, ranked...), plain...)
	for _, u := range all {
		total += u.Wins.Load()
	}
	out := make([]SmartStat, 0, len(all))
	for i, u := range all {
		s := SmartStat{Name: u.Name, Label: u.Label(), Kind: u.Proto(), Rank: i + 1, Raced: i < n || !rs.smartOn(), Demoted: u.demoted(now), Breaker: u.open(),
			Score: u.smartScore(now), ProbeMs: float64(u.probeEWMA.Load()) / 1e6, EwmaMs: float64(u.ewma.Load()) / 1e6,
			Success: 1 - float64(u.errPPM.Load())/1e6, Wins: u.Wins.Load(), Queries: u.Queries.Load()}
		if i >= len(ranked) {
			s.Raced = false
		}
		if s.Demoted {
			s.DemoteS = float64(u.demoteUntil.Load()-now) / 1e9
		}
		if total > 0 {
			s.WinRate = float64(s.Wins) / float64(total)
		}
		if t := u.lastProbe.Load(); t > 0 {
			s.ProbeAgo = float64(now-t) / 1e9
		}
		out = append(out, s)
	}
	return out
}
