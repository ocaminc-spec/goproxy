// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Outage log (item f): every period when all upstreams failed (internet down) or the PC
// had no network, with start, end and duration. Monthly CSV export for ISP credit requests.
type outage struct {
	Kind   string `json:"kind"` // internet | lan
	Start  int64  `json:"start"`
	End    int64  `json:"end,omitempty"` // 0 = still going
	Reason string `json:"reason"`
}

func (o outage) duration(now time.Time) time.Duration {
	end := o.End
	if end == 0 {
		end = now.Unix()
	}
	return time.Duration(end-o.Start) * time.Second
}

type Outages struct {
	mu       sync.Mutex
	list     []outage
	path     string
	settings *settingsStore
	alerts   *Alerts
	now      func() time.Time
	MinDur   time.Duration // shorter blips are not recorded
}

func NewOutages(path string, st *settingsStore, al *Alerts) *Outages {
	o := &Outages{path: path, settings: st, alerts: al, now: time.Now, MinDur: 10 * time.Second}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &o.list)
	}
	// an outage left open by a crash or power cut ends at the last save we know of
	for i := range o.list {
		if o.list[i].End == 0 {
			o.list[i].End = o.list[i].Start
			if fi, err := os.Stat(path); err == nil {
				o.list[i].End = fi.ModTime().Unix()
			}
			o.list[i].Reason += " (GoProxy stopped during this outage)"
		}
	}
	return o
}

func (o *Outages) enabled() bool { return o != nil && o.settings.Get().Feature("outage_log") }

func (o *Outages) Begin(kind, reason string) { o.BeginAt(kind, reason, o.now()) }

func (o *Outages) BeginAt(kind, reason string, at time.Time) {
	if !o.enabled() {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, x := range o.list {
		if x.Kind == kind && x.End == 0 {
			return
		}
	}
	o.list = append(o.list, outage{Kind: kind, Start: at.Unix(), Reason: reason})
	o.saveLocked()
}

func (o *Outages) End(kind string) { o.EndAt(kind, o.now()) }

func (o *Outages) EndAt(kind string, at time.Time) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := len(o.list) - 1; i >= 0; i-- {
		if o.list[i].Kind == kind && o.list[i].End == 0 {
			o.list[i].End = max(at.Unix(), o.list[i].Start)
			if time.Duration(o.list[i].End-o.list[i].Start)*time.Second < o.MinDur {
				o.list = append(o.list[:i], o.list[i+1:]...)
			}
			o.saveLocked()
			return
		}
	}
}

func (o *Outages) saveLocked() {
	keep := orInt(o.settings.Get().OutageMonths, 24)
	cut := o.now().AddDate(0, -keep, 0).Unix()
	for len(o.list) > 0 && o.list[0].End != 0 && o.list[0].End < cut {
		o.list = o.list[1:]
	}
	if o.path == "" {
		return
	}
	b, _ := json.Marshal(o.list)
	if os.WriteFile(o.path+".tmp", b, 0o644) == nil {
		_ = os.Rename(o.path+".tmp", o.path)
	}
}

func (o *Outages) Open() *outage {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := len(o.list) - 1; i >= 0; i-- {
		if o.list[i].End == 0 {
			x := o.list[i]
			return &x
		}
	}
	return nil
}

type outageView struct {
	Kind     string  `json:"kind"`
	Start    string  `json:"start"`
	End      string  `json:"end,omitempty"`
	Minutes  float64 `json:"minutes"`
	Reason   string  `json:"reason"`
	Ongoing  bool    `json:"ongoing"`
	StartSec int64   `json:"start_unix"`
}

func (o *Outages) View(month string) []outageView {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	now := o.now()
	var out []outageView
	for i := len(o.list) - 1; i >= 0; i-- {
		x := o.list[i]
		st := time.Unix(x.Start, 0)
		if month != "" && st.Format("2006-01") != month {
			continue
		}
		v := outageView{Kind: x.Kind, Start: st.Format(time.RFC3339), Minutes: float64(int(x.duration(now).Minutes()*10)) / 10, Reason: x.Reason, Ongoing: x.End == 0, StartSec: x.Start}
		if x.End != 0 {
			v.End = time.Unix(x.End, 0).Format(time.RFC3339)
		}
		out = append(out, v)
	}
	return out
}

// Watch turns the resolver's "internet looks down" state into outage records and alerts.
func (o *Outages) Watch(ctx context.Context, rs *Resolver) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	alerted := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if rs.Offline() {
			o.BeginAt("internet", "every upstream DNS server failed (internet down?)", time.Unix(0, rs.lastFail.Load()))
			if cur := o.Open(); cur != nil && !alerted && cur.duration(o.now()) > time.Minute {
				alerted = true
				o.alerts.Raise(Alert{Key: "outage", Kind: "outage", Title: "Internet looks down", Message: "Every upstream DNS server has been failing for over a minute. Cached answers are still served."})
			}
		} else if cur := o.Open(); cur != nil && cur.Kind == "internet" {
			end := o.now()
			if ok := rs.lastOK.Load(); ok > 0 {
				end = time.Unix(0, ok)
			}
			d := end.Sub(time.Unix(cur.Start, 0)).Round(time.Second)
			o.EndAt("internet", end)
			alerted = false
			o.alerts.Clear("outage", fmt.Sprintf("Internet is back after %v.", d))
		}
	}
}

func (o *Outages) serveJSON(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"enabled": o.enabled(), "outages": o.View(r.URL.Query().Get("month")), "open": o.Open()})
}

// GET /api/outages.csv?month=2026-10 (default: this month)
func (o *Outages) serveCSV(w http.ResponseWriter, r *http.Request) {
	month := r.URL.Query().Get("month")
	if month == "" {
		month = o.now().Format("2006-01")
	}
	if _, err := time.Parse("2006-01", month); err != nil {
		http.Error(w, "month must look like 2026-10", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="goproxy-outages-`+month+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"start", "end", "duration_minutes", "kind", "reason"})
	views := o.View(month)
	total := 0.0
	for i := len(views) - 1; i >= 0; i-- {
		v := views[i]
		end := v.End
		if v.Ongoing {
			end = "ongoing"
		}
		total += v.Minutes
		_ = cw.Write([]string{strings.Replace(v.Start, "T", " ", 1), strings.Replace(end, "T", " ", 1), fmt.Sprintf("%.1f", v.Minutes), v.Kind, v.Reason})
	}
	_ = cw.Write([]string{"total", "", fmt.Sprintf("%.1f", total), "", fmt.Sprintf("%d outage(s) in %s", len(views), month)})
	cw.Flush()
}
