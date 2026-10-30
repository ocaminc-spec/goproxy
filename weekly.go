// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// Weekly summary (v2.4.2): per-day totals (queries, cache answers, blocked, filter blocks,
// failures, average health), top domains of the last 7 days, outages and the health trend.
// Kept on this PC in goproxy-weekly.json (35 days). Read-only; changes nothing.

type dayTotals struct {
	Date       string `json:"date"`
	Queries    int64  `json:"queries"`
	Hits       int64  `json:"hits"`
	Blocked    int64  `json:"blocked"`
	Failures   int64  `json:"failures"`
	HealthSum  int64  `json:"health_sum"`
	HealthN    int64  `json:"health_n"`
	CanaryFail int64  `json:"canary_fail,omitempty"`
}

type weeklyFile struct {
	Days  []dayTotals           `json:"days"`
	Snaps map[string][]hostStat `json:"snaps"` // date -> domain counters at the start of that day
}

type Weekly struct {
	mu    sync.Mutex
	path  string
	s     *DNSServer
	out   *Outages
	f     weeklyFile
	last  map[string]int64
	now   func() time.Time
	lastH int64 // last health bucket start sampled
}

func NewWeekly(path string, s *DNSServer, out *Outages) *Weekly {
	w := &Weekly{path: path, s: s, out: out, now: time.Now, f: weeklyFile{Snaps: map[string][]hostStat{}}}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &w.f)
		if w.f.Snaps == nil {
			w.f.Snaps = map[string][]hostStat{}
		}
	}
	return w
}

func (w *Weekly) counters() map[string]int64 {
	st := w.s.stats
	return map[string]int64{"q": st.Queries.Load(), "h": st.Hits.Load() + st.StaleHits.Load(), "b": st.Blocked.Load(), "f": st.Failures.Load()}
}

func (w *Weekly) dayLocked(date string) *dayTotals {
	if n := len(w.f.Days); n > 0 && w.f.Days[n-1].Date == date {
		return &w.f.Days[n-1]
	}
	w.f.Days = append(w.f.Days, dayTotals{Date: date})
	if len(w.f.Days) > 35 {
		w.f.Days = w.f.Days[len(w.f.Days)-35:]
	}
	return &w.f.Days[len(w.f.Days)-1]
}

// Sample adds the counter deltas since the last sample to today and records the health score.
func (w *Weekly) Sample() {
	now := w.now()
	date := now.Format("2006-01-02")
	cur := w.counters()
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.f.Snaps[date]; !ok {
		w.f.Snaps[date] = w.s.domains.Top(1000)
		cut := now.AddDate(0, 0, -8).Format("2006-01-02")
		for k := range w.f.Snaps {
			if k < cut {
				delete(w.f.Snaps, k)
			}
		}
	}
	d := w.dayLocked(date)
	if w.last != nil {
		pos := func(k string) int64 { return max(cur[k]-w.last[k], 0) }
		d.Queries += pos("q")
		d.Hits += pos("h")
		d.Blocked += pos("b")
		d.Failures += pos("f")
	}
	w.last = cur
	if w.s.health != nil {
		hv := w.s.health.View()
		if n := len(hv); n >= 2 {
			b := hv[n-2] // last complete 10-minute bucket
			if b.Start != w.lastH {
				w.lastH = b.Start
				if sc := b.Scores; sc.Overall >= 0 {
					d.HealthSum += int64(sc.Overall)
					d.HealthN++
				}
				d.CanaryFail += b.CanaryFail
			}
		}
	}
}

func (w *Weekly) Save() error {
	if w == nil || w.path == "" {
		return nil
	}
	w.mu.Lock()
	b, _ := json.Marshal(w.f)
	w.mu.Unlock()
	if err := os.WriteFile(w.path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(w.path+".tmp", w.path)
}

func (w *Weekly) Run(ctx context.Context) {
	w.Sample()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			_ = w.Save()
			return
		case <-t.C:
		}
		w.Sample()
		if n++; n%10 == 0 {
			_ = w.Save()
		}
	}
}

type weeklyDay struct {
	Date     string  `json:"date"`
	Queries  int64   `json:"queries"`
	CachePct float64 `json:"cache_pct"`
	Blocked  int64   `json:"blocked"`
	AdsBlock int64   `json:"filter_blocked"`
	Failures int64   `json:"failures"`
	Health   int     `json:"health"` // -1 = no data
}

type weeklyView struct {
	From       string       `json:"from"`
	To         string       `json:"to"`
	Days       []weeklyDay  `json:"days"`
	Queries    int64        `json:"queries"`
	Blocked    int64        `json:"blocked"`
	AdsBlocked int64        `json:"filter_blocked"`
	Failures   int64        `json:"failures"`
	CachePct   float64      `json:"cache_pct"`
	Health     int          `json:"health"`
	Trend      string       `json:"trend"`
	TopDomains []hostStat   `json:"top_domains"`
	TopSince   string       `json:"top_since"`
	Outages    []outageView `json:"outages"`
	OutageMin  float64      `json:"outage_minutes"`
}

func pct1(a, b int64) float64 {
	if b <= 0 {
		return 0
	}
	return float64(int(1000*float64(a)/float64(b))) / 10
}

func (w *Weekly) View() weeklyView {
	now := w.now()
	ads := map[string]int64{}
	for _, d := range w.s.ads.Days(7) {
		ads[d.Date] = d.Count
	}
	w.mu.Lock()
	by := map[string]dayTotals{}
	for _, d := range w.f.Days {
		by[d.Date] = d
	}
	// top domains over the last 7 days: counters now minus the oldest snapshot in range
	since := ""
	var base []hostStat
	for i := 6; i >= 0; i-- {
		k := now.AddDate(0, 0, -i).Format("2006-01-02")
		if s, ok := w.f.Snaps[k]; ok {
			since, base = k, s
			break
		}
	}
	w.mu.Unlock()
	v := weeklyView{From: now.AddDate(0, 0, -6).Format("2006-01-02"), To: now.Format("2006-01-02"), Health: -1}
	var hits, hsum, hn int64
	var first, last []int
	for i := 6; i >= 0; i-- {
		k := now.AddDate(0, 0, -i).Format("2006-01-02")
		d := by[k]
		wd := weeklyDay{Date: k, Queries: d.Queries, CachePct: pct1(d.Hits, d.Queries), Blocked: d.Blocked, AdsBlock: ads[k], Failures: d.Failures, Health: -1}
		if d.HealthN > 0 {
			wd.Health = int(d.HealthSum / d.HealthN)
			if i >= 4 {
				first = append(first, wd.Health)
			} else {
				last = append(last, wd.Health)
			}
		}
		v.Days = append(v.Days, wd)
		v.Queries += d.Queries
		v.Blocked += d.Blocked
		v.AdsBlocked += ads[k]
		v.Failures += d.Failures
		hits += d.Hits
		hsum += d.HealthSum
		hn += d.HealthN
	}
	v.CachePct = pct1(hits, v.Queries)
	if hn > 0 {
		v.Health = int(hsum / hn)
	}
	avg := func(a []int) float64 {
		t := 0
		for _, x := range a {
			t += x
		}
		return float64(t) / float64(len(a))
	}
	switch {
	case len(first) == 0 || len(last) == 0:
		v.Trend = "not enough days yet"
	case avg(last)-avg(first) >= 3:
		v.Trend = "improving"
	case avg(first)-avg(last) >= 3:
		v.Trend = "getting worse"
	default:
		v.Trend = "steady"
	}
	// top domains
	b := map[string]int64{}
	for _, h := range base {
		b[h.Host] = h.Requests
	}
	var top []hostStat
	for _, h := range w.s.domains.Top(2000) {
		if d := h.Requests - b[h.Host]; d > 0 {
			top = append(top, hostStat{Host: h.Host, Requests: d})
		}
	}
	sort.Slice(top, func(i, j int) bool {
		return top[i].Requests > top[j].Requests || top[i].Requests == top[j].Requests && top[i].Host < top[j].Host
	})
	if len(top) > 10 {
		top = top[:10]
	}
	v.TopDomains, v.TopSince = top, since
	// outages
	cut := now.AddDate(0, 0, -7).Unix()
	for _, o := range w.out.View("") {
		if o.StartSec >= cut {
			v.Outages = append(v.Outages, o)
			v.OutageMin += o.Minutes
		}
	}
	return v
}

func (w *Weekly) serve(rw http.ResponseWriter, r *http.Request) { writeJSON(rw, w.View()) }
