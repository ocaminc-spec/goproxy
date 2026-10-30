// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Flight recorder (item j): the last ~10 minutes of queries and answers, in memory only,
// written to a file when the health score drops, the canary fails, or the watchdog fires.
// Files stay on this PC (flight\ in the data folder, last 10 kept) and are never uploaded.
type flightEntry struct {
	T      int64  // unix nano
	Client string // device IP
	Name   string
	Type   uint16
	Result string
	Rcode  int
	AnCnt  int
	LatUs  int64
	Up     string
}

type Flight struct {
	mu       sync.Mutex
	buf      []flightEntry
	pos      int
	n        int
	window   time.Duration
	lastDump time.Time
	dir      string
	on       func() bool
	now      func() time.Time
	MinGap   time.Duration
	rec      atomic.Bool // recording on (feature switch)
}

func NewFlight(capacity int, window time.Duration, dir string) *Flight {
	f := &Flight{buf: make([]flightEntry, capacity), window: window, dir: dir, now: time.Now, MinGap: 15 * time.Minute, on: func() bool { return true }}
	f.rec.Store(true)
	return f
}

func (f *Flight) Add(e flightEntry) {
	if f == nil || !f.rec.Load() {
		return
	}
	f.mu.Lock()
	f.buf[f.pos] = e
	f.pos = (f.pos + 1) % len(f.buf)
	if f.n < len(f.buf) {
		f.n++
	}
	f.mu.Unlock()
}

func (f *Flight) SetWindow(d time.Duration) {
	f.mu.Lock()
	f.window = d
	f.mu.Unlock()
}

// Snapshot returns the entries inside the window, oldest first.
func (f *Flight) Snapshot() []flightEntry {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cut := f.now().Add(-f.window).UnixNano()
	out := make([]flightEntry, 0, f.n)
	start := (f.pos - f.n + len(f.buf)) % len(f.buf)
	for i := 0; i < f.n; i++ {
		e := f.buf[(start+i)%len(f.buf)]
		if e.T >= cut {
			out = append(out, e)
		}
	}
	return out
}

type flightLine struct {
	Time    string  `json:"time"`
	Client  string  `json:"client"`
	Name    string  `json:"name"`
	Type    string  `json:"type"`
	Result  string  `json:"result"`
	Rcode   string  `json:"rcode"`
	Answers int     `json:"answers"`
	Ms      float64 `json:"ms"`
	Up      string  `json:"upstream,omitempty"`
}

// Dump writes the window to a JSON-lines file (rate limited unless force).
func (f *Flight) Dump(reason string, force bool) string {
	if f == nil || f.dir == "" || (!force && !f.on()) {
		return ""
	}
	f.mu.Lock()
	if !force && !f.lastDump.IsZero() && f.now().Sub(f.lastDump) < f.MinGap {
		f.mu.Unlock()
		return ""
	}
	f.lastDump = f.now()
	f.mu.Unlock()
	entries := f.Snapshot()
	_ = os.MkdirAll(f.dir, 0o755)
	name := filepath.Join(f.dir, "goproxy-flight-"+f.now().Format("20060102-150405")+".jsonl")
	fh, err := os.Create(name)
	if err != nil {
		return ""
	}
	bw := bufio.NewWriter(fh)
	hdr, _ := json.Marshal(map[string]any{"goproxy": Version, "reason": reason, "at": f.now().Format(time.RFC3339), "entries": len(entries)})
	bw.Write(append(hdr, '\n'))
	for _, e := range entries {
		b, _ := json.Marshal(flightLine{Time: time.Unix(0, e.T).Format("15:04:05.000"), Client: e.Client, Name: e.Name, Type: dns.TypeToString[e.Type], Result: e.Result,
			Rcode: dns.RcodeToString[e.Rcode], Answers: e.AnCnt, Ms: float64(e.LatUs) / 1000, Up: e.Up})
		bw.Write(append(b, '\n'))
	}
	bw.Flush()
	fh.Close()
	old, _ := filepath.Glob(filepath.Join(f.dir, "goproxy-flight-*.jsonl"))
	sort.Strings(old)
	for len(old) > 10 {
		_ = os.Remove(old[0])
		old = old[1:]
	}
	log.Printf("flight recorder: %d queries written to %s (%s)", len(entries), name, reason)
	return name
}

func (f *Flight) Files() []string {
	if f == nil || f.dir == "" {
		return nil
	}
	l, _ := filepath.Glob(filepath.Join(f.dir, "goproxy-flight-*.jsonl"))
	sort.Sort(sort.Reverse(sort.StringSlice(l)))
	for i := range l {
		l[i] = filepath.Base(l[i])
	}
	return l
}
