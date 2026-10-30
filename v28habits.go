// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.0 habit learning: which names are popular in each hour of the week (168 slots,
// top 60 names each, older weeks decay by half). Aggregate only: no device data. A few
// minutes before an hour starts, its usual names are pre-warmed (bounded).

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const habitTop = 60

type habitName struct {
	N string  `json:"n"`
	C float64 `json:"c"`
}

type Habits struct {
	mu      sync.Mutex
	path    string
	Slots   [168][]habitName `json:"slots"`
	cur     map[string]uint32
	curSlot int
	On      atomic.Bool
	Warmed  atomic.Int64
	now     func() time.Time
}

func hourOfWeek(t time.Time) int { return int(t.Weekday())*24 + t.Hour() }

func NewHabits(path string) *Habits {
	h := &Habits{path: path, cur: map[string]uint32{}, now: time.Now}
	h.curSlot = hourOfWeek(h.now())
	if b, err := os.ReadFile(path); err == nil {
		var f struct {
			Slots [168][]habitName `json:"slots"`
		}
		if json.Unmarshal(b, &f) == nil {
			h.Slots = f.Slots
		}
	}
	return h
}

func (h *Habits) Record(name string) {
	if h == nil || !h.On.Load() {
		return
	}
	h.mu.Lock()
	if c, ok := h.cur[name]; ok {
		h.cur[name] = c + 1
	} else if len(h.cur) < 5000 {
		h.cur[name] = 1
	}
	h.mu.Unlock()
}

// Roll merges the finished hour into its slot (call often; acts on hour change).
func (h *Habits) Roll() bool {
	slot := hourOfWeek(h.now())
	h.mu.Lock()
	if slot == h.curSlot {
		h.mu.Unlock()
		return false
	}
	cur, old := h.cur, h.curSlot
	h.cur, h.curSlot = map[string]uint32{}, slot
	m := map[string]float64{}
	for _, x := range h.Slots[old] {
		m[x.N] = x.C / 2
	}
	for n, c := range cur {
		m[n] += float64(c)
	}
	var l []habitName
	for n, c := range m {
		if c >= 1 {
			l = append(l, habitName{n, c})
		}
	}
	sort.Slice(l, func(i, j int) bool { return l[i].C > l[j].C || (l[i].C == l[j].C && l[i].N < l[j].N) })
	if len(l) > habitTop {
		l = l[:habitTop]
	}
	h.Slots[old] = l
	h.mu.Unlock()
	h.Save()
	return true
}

func (h *Habits) Save() {
	if h.path == "" {
		return
	}
	h.mu.Lock()
	b, err := json.Marshal(map[string]any{"slots": h.Slots})
	h.mu.Unlock()
	if err == nil {
		tmp := h.path + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, h.path)
		}
	}
}

// Upcoming: the usual names of the hour starting within `ahead`, else the current hour.
func (h *Habits) Upcoming(ahead time.Duration, n int) []string {
	slot := hourOfWeek(h.now().Add(ahead))
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for i, x := range h.Slots[slot] {
		if i >= n {
			break
		}
		out = append(out, x.N)
	}
	return out
}

// Heat: total learned weight per hour-of-week (for the dashboard), plus each hour's top 3.
func (h *Habits) Heat() ([168]float64, [168][]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var w [168]float64
	var top [168][]string
	for i, l := range h.Slots {
		for j, x := range l {
			w[i] += x.C
			if j < 3 {
				top[i] = append(top[i], x.N)
			}
		}
	}
	return w, top
}
