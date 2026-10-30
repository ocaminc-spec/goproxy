// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.7.0 live insights: top domains (rolling 1 and 5 min), a feed of blocked and failed
// lookups, and the upstream race (win share and latency per second). Top domains and the
// race are only collected while someone has the Insights view open (idle after 60 s);
// the feed is a small fixed ring filled only by blocked / failed answers.

import (
	"net/http"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	topMaxNames = 20000 // per minute bucket; beyond that new names are not counted
	feedKeep    = 200
	raceKeep    = 120
	insightIdle = 60 * time.Second
)

type feedItem struct {
	T      int64  `json:"t"` // unix ms
	Client string `json:"client"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Result string `json:"result"` // blocked | failed
}

type racePoint struct {
	T   int64             `json:"t"`
	Ups map[string]raceUp `json:"ups"`
}

type raceUp struct {
	Wins  int64   `json:"wins"`
	Share float64 `json:"share"` // of all wins this second, 0..1
	AvgMS float64 `json:"avg_ms"`
}

type raceSnap struct{ wins, latSum, latN int64 }

type Insights struct {
	watched atomic.Int64
	now     func() time.Time

	tmu   sync.Mutex
	tmin  [5]int64
	tmaps [5]map[string]int32

	fmu  sync.Mutex
	feed []feedItem
	fpos int

	rmu   sync.Mutex
	race  []racePoint
	rlast map[string]raceSnap
	rT    time.Time
}

func NewInsights() *Insights { return &Insights{now: time.Now} }

func (in *Insights) Touch() { in.watched.Store(in.now().UnixNano()) }
func (in *Insights) Active() bool {
	return in != nil && in.now().UnixNano()-in.watched.Load() < int64(insightIdle)
}

// RecordName counts one lookup for the top-domains view (no-op unless watched).
func (in *Insights) RecordName(name string) {
	if !in.Active() || name == "" {
		return
	}
	m := in.now().Unix() / 60
	i := int(m % 5)
	in.tmu.Lock()
	if in.tmin[i] != m || in.tmaps[i] == nil {
		in.tmin[i], in.tmaps[i] = m, map[string]int32{}
	}
	if c, ok := in.tmaps[i][name]; ok || len(in.tmaps[i]) < topMaxNames {
		in.tmaps[i][name] = c + 1
	}
	in.tmu.Unlock()
}

type topRow struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

// Top returns the busiest names over the last `minutes` (1..5) minute buckets.
func (in *Insights) Top(minutes, limit int) ([]topRow, int64) {
	cur := in.now().Unix() / 60
	sum := map[string]int64{}
	var total int64
	in.tmu.Lock()
	for i := range in.tmaps {
		if in.tmaps[i] == nil || cur-in.tmin[i] >= int64(minutes) || in.tmin[i] > cur {
			continue
		}
		for k, v := range in.tmaps[i] {
			sum[k] += int64(v)
			total += int64(v)
		}
	}
	in.tmu.Unlock()
	out := make([]topRow, 0, len(sum))
	for k, v := range sum {
		out = append(out, topRow{k, v})
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Count != out[b].Count {
			return out[a].Count > out[b].Count
		}
		return out[a].Name < out[b].Name
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, total
}

// RecordFeed keeps blocked and failed lookups (always on; a fixed ring of 200).
func (in *Insights) RecordFeed(it feedItem) {
	if in == nil || (it.Result != "blocked" && it.Result != "failed") {
		return
	}
	in.fmu.Lock()
	if len(in.feed) < feedKeep {
		in.feed = append(in.feed, it)
	} else {
		in.feed[in.fpos] = it
		in.fpos = (in.fpos + 1) % feedKeep
	}
	in.fmu.Unlock()
}

// Feed returns the newest items first, only those after `since` (unix ms).
func (in *Insights) Feed(since int64, limit int) []feedItem {
	in.fmu.Lock()
	defer in.fmu.Unlock()
	out := []feedItem{}
	n := len(in.feed)
	for k := 0; k < n && len(out) < limit; k++ {
		i := (in.fpos - 1 - k + 2*n) % n
		if n < feedKeep {
			i = n - 1 - k
		}
		if in.feed[i].T <= since {
			continue
		}
		out = append(out, in.feed[i])
	}
	return out
}

// SampleRace adds one point from the cumulative per-upstream counters.
func (in *Insights) SampleRace(cur map[string]raceSnap) {
	in.rmu.Lock()
	defer in.rmu.Unlock()
	now := in.now()
	if in.rlast == nil || now.Sub(in.rT) > 5*time.Second {
		if in.rlast != nil {
			in.race = nil
		}
		in.rlast, in.rT = cur, now
		return
	}
	p := racePoint{T: now.Unix(), Ups: map[string]raceUp{}}
	var all int64
	for k, c := range cur {
		l := in.rlast[k]
		u := raceUp{Wins: max(c.wins-l.wins, 0)}
		if dn := c.latN - l.latN; dn > 0 {
			u.AvgMS = float64(c.latSum-l.latSum) / float64(dn) / 1e6
		}
		all += u.Wins
		p.Ups[k] = u
	}
	for k, u := range p.Ups {
		if all > 0 {
			u.Share = float64(u.Wins) / float64(all)
		}
		p.Ups[k] = u
	}
	in.rlast, in.rT = cur, now
	in.race = append(in.race, p)
	if len(in.race) > raceKeep {
		in.race = append(in.race[:0:0], in.race[len(in.race)-raceKeep:]...)
	}
}

func (in *Insights) Race() []racePoint {
	in.rmu.Lock()
	defer in.rmu.Unlock()
	return append([]racePoint(nil), in.race...)
}

func (s *DNSServer) raceSnap() map[string]raceSnap {
	m := map[string]raceSnap{}
	for _, u := range s.res.Ups() {
		k := u.URL
		if l := u.label.Load(); l != nil && *l != "" {
			k = *l
		}
		m[k] = raceSnap{u.Wins.Load(), u.latSum.Load(), u.latN.Load()}
	}
	return m
}

// RunInsights samples the race once a second while the view is open.
func (s *DNSServer) RunInsights(stop <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if s.insights.Active() {
				s.insights.SampleRace(s.raceSnap())
			}
		}
	}
}

// GET /api/v27/insights?window=1|5&since=<ms>
func (s *DNSServer) serveInsights(w http.ResponseWriter, r *http.Request) {
	in := s.insights
	if !in.Active() {
		in.Touch()
		in.SampleRace(s.raceSnap())
	}
	in.Touch()
	win, _ := strconv.Atoi(r.URL.Query().Get("window"))
	if win != 5 {
		win = 1
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	top, total := in.Top(win, 15)
	feed := in.Feed(since, 50)
	if s.settings == nil || !s.settings.Get().Feature("device_volume") {
		for i := range feed { // client addresses only behind the Devices-by-volume approval
			feed[i].Client = ""
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"window_min": win, "top": top, "top_total": total, "feed": feed,
		"race": in.Race(), "blocked_total": s.stats.Blocked.Load(), "failed_total": s.stats.Failures.Load(), "blocking_on": s.bl.On()})
}
