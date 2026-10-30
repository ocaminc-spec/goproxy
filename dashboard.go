// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"runtime"
	"sort"
	"sync"
	"time"

	"strconv"
	"strings"

	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"
)

//go:embed static/index.html static/v24.js static/v26.js static/v27.js static/v28.js static/v281.js static/v282.js
var staticFS embed.FS

func dashboardHandler() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.FileServer(http.FS(sub))
}

type LogEntry struct {
	Seq       int64   `json:"seq"`
	Time      string  `json:"time"`
	Client    string  `json:"client"`
	Domain    string  `json:"domain"`
	Type      string  `json:"type"`
	Result    string  `json:"result"`
	LatencyMs float64 `json:"latency_ms"`
	Upstream  string  `json:"upstream,omitempty"`
}

type LogRing struct {
	mu  sync.Mutex
	buf []LogEntry
	seq int64
}

func NewLogRing(n int) *LogRing { return &LogRing{buf: make([]LogEntry, n)} }

func (l *LogRing) Add(e LogEntry) {
	l.mu.Lock()
	l.seq++
	e.Seq = l.seq
	e.Time = time.Now().Format("15:04:05.000")
	l.buf[l.seq%int64(len(l.buf))] = e
	l.mu.Unlock()
}

func (l *LogRing) Since(seq int64) ([]LogEntry, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	from := seq + 1
	if m := l.seq - int64(len(l.buf)) + 1; from < m {
		from = m
	}
	if l.seq-from > 200 {
		from = l.seq - 200
	}
	var out []LogEntry
	for s := from; s <= l.seq; s++ {
		if s > 0 {
			out = append(out, l.buf[s%int64(len(l.buf))])
		}
	}
	return out, l.seq
}

type StatsMsg struct {
	Queries      int64          `json:"queries"`
	Hits         int64          `json:"hits"`
	StaleHits    int64          `json:"stale_hits"`
	Misses       int64          `json:"misses"`
	Blocked      int64          `json:"blocked"`
	Forwarded    int64          `json:"forwarded"`
	Failures     int64          `json:"failures"`
	Prefetches   int64          `json:"prefetches"`
	Refreshes    int64          `json:"refreshes"`
	QPS          float64        `json:"qps"`
	HitRatio     float64        `json:"hit_ratio"`
	BlockedRatio float64        `json:"blocked_ratio"`
	P50Ms        float64        `json:"p50_ms"`
	P99Ms        float64        `json:"p99_ms"`
	HitP50Ms     float64        `json:"hit_p50_ms"`
	HitP99Ms     float64        `json:"hit_p99_ms"`
	CPUPercent   float64        `json:"cpu_percent"`
	NumCPU       int            `json:"num_cpu"`
	GOMAXPROCS   int            `json:"gomaxprocs"`
	Goroutines   int            `json:"goroutines"`
	HeapGB       float64        `json:"heap_gb"`
	SysGB        float64        `json:"sys_gb"`
	HostUsedGB   float64        `json:"host_mem_used_gb"`
	HostTotalGB  float64        `json:"host_mem_total_gb"`
	CacheBytes   int64          `json:"cache_bytes"`
	CacheLimit   int64          `json:"cache_limit"`
	CacheEntries int64          `json:"cache_entries"`
	Evictions    int64          `json:"evictions"`
	NumGC        uint32         `json:"num_gc"`
	GCPausesMs   []float64      `json:"gc_pauses_ms"`
	BlockSize    int            `json:"blocklist_size"`
	BlockUpdated int64          `json:"blocklist_updated"`
	BlockPaused  bool           `json:"blocking_paused"`
	BlockOn      bool           `json:"blocking_available"`
	Parallel     int            `json:"parallel"`
	RaceFirst    int            `json:"race_first"`
	ParallelAll  bool           `json:"parallel_all"`
	LastWinner   string         `json:"last_winner,omitempty"`
	Hedged       int64          `json:"hedged"`
	Upstreams    []UpstreamStat `json:"upstreams"`
	UDPListeners int            `json:"udp_listeners"`
	TopDomains   []hostStat     `json:"top_domains"`
	TopBlocked   []hostStat     `json:"top_blocked"`
	TopClients   []hostStat     `json:"top_clients"`
	Logs         []LogEntry     `json:"logs,omitempty"`
	UptimeSec    int64          `json:"uptime_sec"`
	// v2.1.0
	CPUPerCore    []float64        `json:"cpu_per_core"`
	StaleRescued  int64            `json:"stale_rescued"`
	DNSSECPass    int64            `json:"dnssec_passthrough"`
	Profile       string           `json:"profile"`
	Siblings      int64            `json:"sibling_prefetches"`
	KeepHot       int64            `json:"keephot_refreshes"`
	Warmed        int64            `json:"warmed"`
	Warming       bool             `json:"warming"`
	Hist          []int64          `json:"latency_hist"`
	HistBounds    []float64        `json:"latency_hist_bounds"`
	QTypes        map[string]int64 `json:"qtypes"`
	Clients       []clientView     `json:"clients"`
	BlockUpdating bool             `json:"blocklist_updating"`
	Settings      map[string]any   `json:"settings"`
	CacheRestored int64            `json:"cache_restored"`
	PinnedList    []pinView        `json:"pinned"`
	PinnedRefresh int64            `json:"pinned_refreshes"`
}

type clientView struct {
	IP      string `json:"ip"`
	Name    string `json:"name"`
	Queries int64  `json:"queries"`
	Blocked int64  `json:"blocked"`
}

func qtypeName(t uint16) string {
	if t == 0 {
		return "OTHER"
	}
	if n, ok := dns.TypeToString[t]; ok {
		return n
	}
	return "TYPE" + strconv.Itoa(int(t))
}

func qtypeFromName(n string) uint16 {
	if n == "OTHER" {
		return 0
	}
	if t, ok := dns.StringToType[n]; ok {
		return t
	}
	if v, err := strconv.Atoi(strings.TrimPrefix(n, "TYPE")); err == nil && v < 256 {
		return uint16(v)
	}
	return 0
}

var (
	cpuMu    sync.Mutex
	cpuLast  float64
	cpuCores []float64
	cpuAt    time.Time
)

// cpuPercent returns total and per-core CPU %, sampled at most every 200 ms.
func cpuPercent() (float64, []float64) {
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if time.Since(cpuAt) > 200*time.Millisecond {
		if v, err := cpu.Percent(0, true); err == nil && len(v) > 0 {
			cpuCores = v
			t := 0.0
			for _, x := range v {
				t += x
			}
			cpuLast = t / float64(len(v))
		}
		cpuAt = time.Now()
	}
	return cpuLast, append([]float64(nil), cpuCores...)
}

func pct(ring []int64, n int) (p50, p99 float64) {
	if n > len(ring) {
		n = len(ring)
	}
	if n == 0 {
		return
	}
	l := append([]int64(nil), ring[:n]...)
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
	return float64(l[n/2]) / 1e6, float64(l[n*99/100]) / 1e6
}

var udpListeners int

func (s *DNSServer) snapshot() StatsMsg {
	st := s.stats
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	o := StatsMsg{Queries: st.Queries.Load(), Hits: st.Hits.Load(), StaleHits: st.StaleHits.Load(), Misses: st.Misses.Load(),
		Blocked: st.Blocked.Load(), Forwarded: st.Forwarded.Load(), Failures: st.Failures.Load(), Prefetches: st.Prefetches.Load(), Refreshes: st.Refreshes.Load(),
		NumCPU: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), Goroutines: runtime.NumGoroutine(),
		HeapGB: float64(ms.HeapAlloc) / float64(gb), SysGB: float64(ms.Sys) / float64(gb),
		CacheBytes: s.cache.Bytes(), CacheLimit: s.cache.budget, CacheEntries: s.cache.entries.Load(), Evictions: s.cache.evictions.Load(), NumGC: ms.NumGC,
		BlockSize: s.bl.Size(), BlockUpdated: s.bl.Updated.Load(), BlockPaused: s.bl.paused.Load(), BlockOn: s.bl.On(), Parallel: s.res.Parallel, Upstreams: s.res.Stats(),
		UDPListeners: udpListeners, TopDomains: s.domains.Top(10), TopBlocked: s.blocked.Top(10), TopClients: s.clients.Top(10), UptimeSec: int64(time.Since(st.start).Seconds())}
	o.CPUPercent, o.CPUPerCore = cpuPercent()
	o.DNSSECPass, o.Profile = st.DNSSECPass.Load(), s.profile
	o.StaleRescued, o.Siblings, o.KeepHot, o.Warmed, o.Warming = st.StaleRescued.Load(), st.Siblings.Load(), st.KeepHot.Load(), st.Warmed.Load(), s.warming.Load()
	o.HistBounds = histBounds
	for i := range st.Hist {
		o.Hist = append(o.Hist, st.Hist[i].Load())
	}
	o.QTypes = map[string]int64{}
	for i := range st.QTypes {
		if v := st.QTypes[i].Load(); v > 0 {
			o.QTypes[qtypeName(uint16(i))] = v
		}
	}
	for _, c := range s.clients.Top(25) {
		o.Clients = append(o.Clients, clientView{IP: c.Host, Name: s.names.Name(c.Host), Queries: c.Requests, Blocked: c.Bytes})
	}
	o.BlockUpdating = s.bl.Updating.Load()
	o.PinnedList, o.PinnedRefresh = s.pinned.List(), st.Pinned.Load()
	o.CacheRestored = s.restored.Load()
	t := s.tune
	o.Settings = map[string]any{"stale_timeout_ms": t.StaleTimeout.Milliseconds(), "stale_max_age_sec": int64(s.cache.staleFor.Seconds()),
		"min_ttl_sec": int64(s.cache.minTTL.Seconds()), "max_ttl_sec": int64(s.cache.maxTTL.Seconds()), "prefetch_hits": t.PrefetchHits, "prefetch_at": t.PrefetchAt,
		"siblings": t.Siblings, "keep_hot": t.KeepHotN, "keep_hot_every_sec": int64(t.KeepHotEvery.Seconds()), "warmup": t.WarmupN, "warmup_workers": t.WarmupWorkers,
		"cache_file": s.cacheFile, "never_block": s.neverBlock, "auto_pin": s.pinned.suffixesOrNil(), "ptr_server": s.ptrServer}
	if o.Parallel <= 0 || o.Parallel > len(s.res.Ups()) {
		o.Parallel = len(s.res.Ups())
	}
	o.RaceFirst = s.res.First
	o.ParallelAll, o.LastWinner = s.res.ParallelAll.Load(), s.res.LastWinner()
	if o.RaceFirst <= 0 {
		o.RaceFirst = 2
	}
	o.RaceFirst = min(o.RaceFirst, o.Parallel)
	o.Hedged = s.res.Hedged.Load()
	if vm, err := mem.VirtualMemory(); err == nil {
		o.HostUsedGB, o.HostTotalGB = float64(vm.Used)/float64(gb), float64(vm.Total)/float64(gb)
	}
	if d := o.Hits + o.StaleHits + o.Misses; d > 0 {
		o.HitRatio = float64(o.Hits+o.StaleHits) / float64(d)
	}
	if o.Queries > 0 {
		o.BlockedRatio = float64(o.Blocked) / float64(o.Queries)
	}
	for i := 0; i < 10 && i < int(ms.NumGC); i++ {
		o.GCPausesMs = append(o.GCPausesMs, float64(ms.PauseNs[(int(ms.NumGC)-1-i+256)%256])/1e6)
	}
	st.latMu.Lock()
	o.P50Ms, o.P99Ms = pct(st.lat, st.latN)
	o.HitP50Ms, o.HitP99Ms = pct(st.hitLat, st.hitN)
	st.latMu.Unlock()
	return o
}

func (s *DNSServer) serveStatsJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.snapshot())
}

// POST /api/blocking?enabled=true|false toggles ad blocking.
func (s *DNSServer) serveBlocking(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if !s.bl.On() {
			http.Error(w, "ad blocking is off; start GoProxy with -blocking=true", http.StatusConflict)
			return
		}
		s.setBlockingPaused(r.URL.Query().Get("enabled") == "false", remoteIP(r))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"enabled": s.bl.On() && !s.bl.paused.Load(), "available": s.bl.On()})
}

// POST /api/flush empties the cache.
func (s *DNSServer) serveFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	n := s.cache.Flush()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"flushed": n})
}

// POST /api/blocklist/update re-downloads the blocklists in the background.
func (s *DNSServer) serveBlocklistUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	s.bl.UpdateNow()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"started": true})
}

var upgrader = websocket.Upgrader{CheckOrigin: sameOrigin}

func (s *DNSServer) serveWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				c.Close()
				return
			}
		}
	}()
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	var seq int64
	lastQ, lastT := s.stats.Queries.Load(), time.Now()
	for range t.C {
		msg := s.snapshot()
		msg.Logs, seq = s.logs.Since(seq)
		now := time.Now()
		msg.QPS = float64(msg.Queries-lastQ) / now.Sub(lastT).Seconds()
		lastQ, lastT = msg.Queries, now
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if err := c.WriteJSON(msg); err != nil {
			return
		}
	}
}

// setBlockingPaused pauses/resumes filtering and persists ONLY that field (v2.6.0 fix: the
// old code saved Settings{BlockingPaused: x}, wiping every other saved setting).
func (s *DNSServer) setBlockingPaused(p bool, by string) {
	s.bl.paused.Store(p)
	if s.settings == nil {
		return
	}
	if _, _, err := s.settings.Update(by, map[bool]string{true: "filter paused", false: "filter resumed"}[p], func(st *Settings) error {
		st.BlockingPaused = p
		return nil
	}); err != nil {
		log.Printf("settings: %v", err)
	}
}

// All returns every kept entry, newest first (v2.8.1 Pro query log).
func (l *LogRing) All() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := int64(len(l.buf))
	var out []LogEntry
	for s := l.seq; s > 0 && s > l.seq-n; s-- {
		out = append(out, l.buf[s%n])
	}
	return out
}
