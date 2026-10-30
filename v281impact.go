// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.1 Update impact: every version start is recorded as a marker (goproxy-versions.json),
// and a fixed-size ring (goproxy-impact.bin, 30 days x 1 min, ~6 MB) keeps cold and cached
// latency histograms plus process CPU and memory, so each update can be compared 24 h
// before vs 24 h after.

import (
	"encoding/binary"
	"encoding/json"
	"math"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	impSlots   = 43200
	impRec     = 144
	impBuckets = 16
	impWindow  = 24 * time.Hour
)

// bucket upper bounds in ms (last = overflow, treated as 2000 ms)
var impBounds = func() (b [impBuckets]float64) {
	v := 0.05
	for i := range b {
		b[i] = v
		v *= 2
	}
	b[impBuckets-1] = 2000
	return
}()

func impBucket(msv float64) int {
	for i, b := range impBounds {
		if msv <= b {
			return i
		}
	}
	return impBuckets - 1
}

type impAcc struct {
	min    int64
	cold   [impBuckets]atomic.Uint32
	cached [impBuckets]atomic.Uint32
}

type impRecord struct {
	Min    int64
	Cold   [impBuckets]uint32
	Cached [impBuckets]uint32
	CPU    uint32 // centi-percent of the whole machine
	RSSKB  uint32
}

type VersionMarker struct {
	Version   string `json:"version"`
	T         int64  `json:"t"`
	Estimated bool   `json:"estimated,omitempty"`
}

type Impact struct {
	path, vpath string
	ts          *TSDB
	mu          sync.Mutex
	f           *os.File
	mem         map[int64]impRecord // when there is no file (tests / portable without a folder)
	cur         atomic.Pointer[impAcc]
	lastCPU     cpuTimes
	lastWall    time.Time
	markers     []VersionMarker
	now         func() time.Time
}

func OpenImpact(path, vpath string, ts *TSDB) *Impact {
	im := &Impact{path: path, vpath: vpath, ts: ts, now: time.Now, mem: map[int64]impRecord{}}
	im.cur.Store(&impAcc{min: im.now().Unix() / 60})
	if path != "" {
		if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err == nil {
			if st, _ := f.Stat(); st != nil && st.Size() != impSlots*impRec {
				_ = f.Truncate(impSlots * impRec)
			}
			im.f = f
		}
	}
	im.lastCPU, im.lastWall = readCPU(), im.now()
	im.loadMarkers()
	return im
}

func (im *Impact) loadMarkers() {
	if im.vpath != "" {
		if b, err := os.ReadFile(im.vpath); err == nil {
			_ = json.Unmarshal(b, &im.markers)
		}
	}
	if len(im.markers) == 0 && Version != "2.8.0" && im.ts != nil {
		// 2.8.0 did not keep markers: estimate its install time from the oldest history minute.
		if t := im.ts.Oldest(); t > 0 {
			im.markers = append(im.markers, VersionMarker{"2.8.0", t, true})
		}
	}
	if n := len(im.markers); n == 0 || im.markers[n-1].Version != Version {
		im.markers = append(im.markers, VersionMarker{Version: Version, T: im.now().Unix()})
		im.saveMarkers()
	}
}

func (im *Impact) saveMarkers() {
	if im.vpath == "" {
		return
	}
	if len(im.markers) > 200 {
		im.markers = im.markers[len(im.markers)-200:]
	}
	b, _ := json.MarshalIndent(im.markers, "", " ")
	tmp := im.vpath + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, im.vpath)
	}
}

func (im *Impact) Markers() []VersionMarker {
	if im == nil {
		return nil
	}
	im.mu.Lock()
	defer im.mu.Unlock()
	return append([]VersionMarker(nil), im.markers...)
}

func (im *Impact) Observe(result string, d time.Duration) {
	if im == nil {
		return
	}
	a := im.cur.Load()
	b := impBucket(float64(d.Microseconds()) / 1000)
	switch result {
	case "cached", "stale":
		a.cached[b].Add(1)
	case "forwarded", "refreshed":
		a.cold[b].Add(1)
	}
}

func rssKB() uint32 {
	if b, err := os.ReadFile("/proc/self/statm"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 1 {
			if p, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				return uint32(p * int64(os.Getpagesize()) / 1024)
			}
		}
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return uint32(m.Sys / 1024)
}

// Tick (every second): closes the minute, sampling CPU and memory.
func (im *Impact) Tick() {
	if im == nil {
		return
	}
	m := im.now().Unix() / 60
	a := im.cur.Load()
	if a.min == m {
		return
	}
	old := im.cur.Swap(&impAcc{min: m})
	r := impRecord{Min: old.min}
	for i := range impBuckets {
		r.Cold[i], r.Cached[i] = old.cold[i].Load(), old.cached[i].Load()
	}
	c, w := readCPU(), im.now()
	if wall := w.Sub(im.lastWall).Seconds(); wall > 0 && c.proc >= im.lastCPU.proc {
		r.CPU = uint32(math.Round((c.proc - im.lastCPU.proc) / wall / float64(numCPU()) * 10000))
	}
	im.lastCPU, im.lastWall = c, w
	r.RSSKB = rssKB()
	im.write(r)
}

func (im *Impact) write(r impRecord) {
	im.mu.Lock()
	defer im.mu.Unlock()
	if im.f == nil {
		im.mem[r.Min] = r
		return
	}
	var b [impRec]byte
	binary.LittleEndian.PutUint32(b[0:], uint32(r.Min))
	for i := range impBuckets {
		binary.LittleEndian.PutUint32(b[4+4*i:], r.Cold[i])
		binary.LittleEndian.PutUint32(b[68+4*i:], r.Cached[i])
	}
	binary.LittleEndian.PutUint32(b[132:], r.CPU)
	binary.LittleEndian.PutUint32(b[136:], r.RSSKB)
	_, _ = im.f.WriteAt(b[:], (r.Min%impSlots)*impRec)
}

func (im *Impact) read(min int64) (impRecord, bool) {
	if im.f == nil {
		r, ok := im.mem[min]
		return r, ok
	}
	var b [impRec]byte
	if _, err := im.f.ReadAt(b[:], (min%impSlots)*impRec); err != nil {
		return impRecord{}, false
	}
	if int64(binary.LittleEndian.Uint32(b[0:])) != min {
		return impRecord{}, false
	}
	r := impRecord{Min: min}
	for i := range impBuckets {
		r.Cold[i] = binary.LittleEndian.Uint32(b[4+4*i:])
		r.Cached[i] = binary.LittleEndian.Uint32(b[68+4*i:])
	}
	r.CPU, r.RSSKB = binary.LittleEndian.Uint32(b[132:]), binary.LittleEndian.Uint32(b[136:])
	return r, true
}

func (im *Impact) Close() {
	if im != nil && im.f != nil {
		im.mu.Lock()
		_ = im.f.Close()
		im.f = nil
		im.mu.Unlock()
	}
}

// quantile over a histogram with log interpolation inside the bucket.
func histQ(h [impBuckets]uint64, q float64) float64 {
	var n uint64
	for _, c := range h {
		n += c
	}
	if n == 0 {
		return 0
	}
	target := q * float64(n)
	var acc float64
	for i, c := range h {
		if c == 0 {
			continue
		}
		if acc+float64(c) >= target {
			lo := 0.025
			if i > 0 {
				lo = impBounds[i-1]
			}
			f := (target - acc) / float64(c)
			return lo * math.Pow(impBounds[i]/lo, f)
		}
		acc += float64(c)
	}
	return impBounds[impBuckets-1]
}

type ImpactWindow struct {
	From      int64   `json:"from"`
	To        int64   `json:"to"`
	Minutes   int     `json:"minutes"`
	Lookups   uint64  `json:"lookups"`
	ColdN     uint64  `json:"cold_n"`
	CachedN   uint64  `json:"cached_n"`
	ColdMed   float64 `json:"cold_median_ms"`
	ColdP95   float64 `json:"cold_p95_ms"`
	ColdAvg   float64 `json:"cold_avg_ms"` // from the history file (exists since 2.8.0)
	CachedMed float64 `json:"cached_median_ms"`
	CachedP95 float64 `json:"cached_p95_ms"`
	HitPct    float64 `json:"hit_pct"`
	FailPct   float64 `json:"fail_pct"`
	CPUPct    float64 `json:"cpu_pct"`
	MemMB     float64 `json:"mem_mb"`
	Detail    bool    `json:"detail"` // cold/cached percentiles, CPU and memory available
}

func (im *Impact) Window(from, to int64) ImpactWindow {
	w := ImpactWindow{From: from, To: to}
	var cold, cached [impBuckets]uint64
	var cpu, mem float64
	var nres int
	im.mu.Lock()
	for m := from / 60; m < to/60; m++ {
		if r, ok := im.read(m); ok {
			for i := range impBuckets {
				cold[i] += uint64(r.Cold[i])
				cached[i] += uint64(r.Cached[i])
			}
			cpu += float64(r.CPU) / 100
			mem += float64(r.RSSKB) / 1024
			nres++
		}
	}
	im.mu.Unlock()
	if nres > 0 {
		w.Detail = true
		w.CPUPct, w.MemMB = cpu/float64(nres), mem/float64(nres)
		w.ColdMed, w.ColdP95 = histQ(cold, .5), histQ(cold, .95)
		w.CachedMed, w.CachedP95 = histQ(cached, .5), histQ(cached, .95)
		for i := range impBuckets {
			w.ColdN += cold[i]
			w.CachedN += cached[i]
		}
	}
	if im.ts != nil {
		s := im.ts.Sum(from, to)
		w.Lookups = uint64(s.Q)
		w.Minutes = int((to - from) / 60)
		w.HitPct = 100 * s.HitRate()
		if s.Q > 0 {
			w.FailPct = 100 * float64(s.Failed) / float64(s.Q)
		}
		w.ColdAvg = s.FwdAvgMs
	}
	return w
}

type ImpactCompare struct {
	Version   string       `json:"version"`
	T         int64        `json:"t"`
	Estimated bool         `json:"estimated,omitempty"`
	Prev      string       `json:"prev,omitempty"`
	Before    ImpactWindow `json:"before"`
	After     ImpactWindow `json:"after"`
	AfterHrs  float64      `json:"after_hours"`
	Complete  bool         `json:"complete"` // a full 24 h after the update has passed
}

func (im *Impact) Compare() []ImpactCompare {
	ms := im.Markers()
	now := im.now().Unix()
	var out []ImpactCompare
	for i, m := range ms {
		end := min(m.T+int64(impWindow.Seconds()), now)
		if i+1 < len(ms) {
			end = min(end, ms[i+1].T)
		}
		c := ImpactCompare{Version: m.Version, T: m.T, Estimated: m.Estimated, Before: im.Window(m.T/60*60-int64(impWindow.Seconds()), m.T/60*60), After: im.Window(m.T/60*60, end)}
		if i > 0 {
			c.Prev = ms[i-1].Version
		}
		c.AfterHrs = float64(end-m.T) / 3600
		c.Complete = end-m.T >= int64(impWindow.Seconds())
		out = append(out, c)
	}
	return out
}

func (im *Impact) serve(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"markers": im.Markers(), "compare": im.Compare(), "current": Version, "window_hours": impWindow.Hours()})
}
