// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.0 "smart server": smart upstreams, rate-bounded prefetch, habit pre-warming,
// self-healing, weekly report card, threat feeds (off), tunneling/DGA detection (alert-only),
// DNSSEC strict mode (off), adaptive TTL and a bounded on-disk query time-series.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var defaultThreatLists = []string{
	"https://urlhaus.abuse.ch/downloads/hostfile/",
	"https://phishing.army/download/phishing_army_blocklist.txt",
}

type V28Config struct {
	SmartOff       bool     `json:"smart_off,omitempty"`
	SmartN         int      `json:"smart_n,omitempty"` // default 3
	PrefetchOff    bool     `json:"prefetch_off,omitempty"`
	PrefetchRate   int      `json:"prefetch_rate,omitempty"` // per second, default 20
	HabitsOff      bool     `json:"habits_off,omitempty"`
	HealOff        bool     `json:"heal_off,omitempty"`
	ThreatOn       bool     `json:"threat_on,omitempty"`
	ThreatLists    []string `json:"threat_lists,omitempty"`
	DetectOff      bool     `json:"detect_off,omitempty"`
	DetectBlock    bool     `json:"detect_block,omitempty"`
	DNSSECStrict   bool     `json:"dnssec_strict,omitempty"`
	AdaptiveTTLOff bool     `json:"adaptive_ttl_off,omitempty"`
	// v2.8.1 speed (each can be switched off; HTTP/3 is opt-in)
	WarmOff       bool `json:"warm_off,omitempty"`        // keep encrypted connections warm
	H3On          bool `json:"h3_on,omitempty"`           // try DoH over HTTP/3 (QUIC), fall back to HTTP/2
	AnycastOff    bool `json:"anycast_off,omitempty"`     // dial the nearest address of the same provider
	ServeStaleOff bool `json:"serve_stale_off,omitempty"` // RFC 8767: answer expired entries at once (30 s TTL, up to 1 day)
}

func (c V28Config) smartN() int       { return min(orInt(c.SmartN, defaultSmartN), 16) }
func (c V28Config) prefetchRate() int { return orInt(c.PrefetchRate, 20) }
func (c V28Config) threatLists() []string {
	if len(c.ThreatLists) == 0 {
		return defaultThreatLists
	}
	return c.ThreatLists
}

func validateV28(c *V28Config) error {
	if c.SmartN < 0 || c.SmartN > 16 || c.PrefetchRate < 0 || c.PrefetchRate > 500 {
		return errors.New("smart: race 1-16 upstreams, prefetch 1-500 per second")
	}
	if len(c.ThreatLists) > 10 {
		return errors.New("at most 10 threat feeds")
	}
	for _, u := range c.ThreatLists {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return fmt.Errorf("threat feed %q: must be an http(s) URL", u)
		}
	}
	return nil
}

type HealEvent struct {
	T      int64  `json:"t"`
	Kind   string `json:"kind"` // latency | hit_rate | failures | demote | recovered
	Detail string `json:"detail"`
	Action string `json:"action"`
}

type V28 struct {
	s      *DNSServer
	ts     *TSDB
	vol    *Volatility
	threat *Blocklist
	det    *Detector
	hab    *Habits
	weekly *Weekly
	dir    string

	prefetchOn  atomic.Bool
	strict      atomic.Bool
	tokens      atomic.Int64
	rate        atomic.Int64
	Prefetched  atomic.Int64
	PrefSkipped atomic.Int64
	Threats     atomic.Int64

	mu     sync.Mutex
	events []HealEvent
	healOn atomic.Bool
	probes atomic.Int64
	now    func() time.Time

	sp     *Speed  // v2.8.1
	imp    *Impact // v2.8.1
	spBusy atomic.Bool
	acBusy atomic.Bool
}

func NewV28(s *DNSServer, dir string, wk *Weekly) *V28 {
	x := &V28{s: s, dir: dir, weekly: wk, now: time.Now, vol: NewVolatility(100_000), det: NewDetector()}
	tsPath, habPath := "", ""
	if dir != "" {
		tsPath, habPath = filepath.Join(dir, "goproxy-tsdb.bin"), filepath.Join(dir, "goproxy-habits.json")
	}
	x.ts = OpenTSDB(tsPath)
	x.sp = NewSpeed(s)
	impPath, verPath := "", ""
	if dir != "" {
		impPath, verPath = filepath.Join(dir, "goproxy-impact.bin"), filepath.Join(dir, "goproxy-versions.json")
	}
	x.imp = OpenImpact(impPath, verPath, x.ts)
	versionMarkers = x.imp.Markers
	x.hab = NewHabits(habPath)
	x.threat = NewBlocklist(nil, nil, nil)
	x.threat.Enabled = false
	x.det.raise = func(e DetectEvent) {
		what := map[string]string{"dga": "Random-looking domain", "tunnel": "Possible DNS tunneling"}[e.Kind]
		act := "alert only"
		if x.det.Block.Load() {
			act = "now blocked for 24 h"
		}
		s.alerts.Raise(Alert{Key: "v28:det:" + e.Domain, Kind: "security", Title: what, Message: fmt.Sprintf("%s: %s (%s).", e.Domain, e.Reason, act)})
	}
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, "goproxy-heal.json")); err == nil {
			_ = json.Unmarshal(b, &x.events)
		}
	}
	s.cache.adapt = x.vol.Adapt
	s.v28 = x
	return x
}

func (s *DNSServer) applyV28(st Settings) {
	x := s.v28
	if x == nil {
		return
	}
	c := st.V28
	s.res.Smart.Store(!c.SmartOff)
	s.res.SmartN.Store(int32(c.smartN()))
	x.prefetchOn.Store(!c.PrefetchOff)
	x.rate.Store(int64(c.prefetchRate()))
	x.hab.On.Store(!c.HabitsOff)
	x.healOn.Store(!c.HealOff)
	x.det.On.Store(!c.DetectOff)
	x.det.Block.Store(!c.DetectOff && c.DetectBlock)
	x.strict.Store(c.DNSSECStrict)
	x.vol.On.Store(!c.AdaptiveTTLOff)
	x.threat.SetSources(c.ThreatOn, c.threatLists(), nil, nil)
	x.sp.apply(c)
}

// ---- hot path hooks ----

// allowPrefetch: token bucket (refilled every second by Run).
func (x *V28) allowPrefetch() bool {
	if x == nil {
		return true
	}
	if !x.prefetchOn.Load() {
		return false
	}
	if x.tokens.Add(-1) < 0 {
		x.tokens.Add(1)
		x.PrefSkipped.Add(1)
		return false
	}
	x.Prefetched.Add(1)
	return true
}

// preCheck: "threat" / "flagged" when the name must be sinkholed, else "".
func (x *V28) preCheck(name string) string {
	if x == nil {
		return ""
	}
	if x.threat.Blocked(name) {
		x.Threats.Add(1)
		return "threat"
	}
	if x.det.ShouldBlock(name) {
		return "flagged"
	}
	return ""
}

func (x *V28) observe(name string, qtype uint16, result string, rcode int, d time.Duration, client string) {
	if x == nil {
		return
	}
	x.ts.Observe(result, qtype, rcode, d, client)
	x.imp.Observe(result, d)
	switch result {
	case "blocked", "threat", "flagged", "local":
		return
	}
	if qtype == dns.TypeA || qtype == dns.TypeAAAA {
		x.hab.Record(name)
	}
	if result != "cached" && result != "stale" {
		x.det.Observe(name, qtype)
	}
}

func blockedResult(r string) bool { return r == "blocked" || r == "threat" || r == "flagged" }

func (s *DNSServer) dnssecStrict() bool { return s.v28 != nil && s.v28.strict.Load() }

// ---- background ----

func (x *V28) Run(ctx context.Context) {
	x.s.applyV28(x.s.settings.Get())
	go x.threat.Run(ctx, 6*time.Hour)
	go func() { // first probe at once so the ranking is measured
		x.s.res.Probe(ctx, 0)
		x.probes.Add(1)
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	defer x.ts.Flush()
	n := 0
	for {
		select {
		case <-ctx.Done():
			x.hab.Save()
			return
		case <-t.C:
		}
		n++
		x.tokens.Store(x.rate.Load())
		x.ts.Tick()
		x.imp.Tick()
		if n%int(warmEvery/time.Second) == 0 && x.spBusy.CompareAndSwap(false, true) {
			go func() { defer x.spBusy.Store(false); x.sp.Warm(ctx) }()
		}
		if (n == 20 || n%int(anycastEvery/time.Second) == 0) && x.acBusy.CompareAndSwap(false, true) {
			go func() { defer x.acBusy.Store(false); x.sp.PickAnycast(ctx) }()
		}
		if n%60 == 0 && x.s.res.Smart.Load() {
			x.s.res.Probe(ctx, n/60)
			x.probes.Add(1)
			for _, u := range x.s.res.autoDemote() {
				x.addEvent(HealEvent{Kind: "demote", Detail: fmt.Sprintf("%s is slow or failing (%.0f ms, %.0f%% errors)", upName(u), float64(u.probeEWMA.Load())/1e6, float64(u.errPPM.Load())/1e4), Action: "kept out of the race for 5 min"})
			}
		}
		if n%30 == 0 {
			x.heal()
		}
		if n%300 == 0 {
			x.det.Reset()
		}
		if n%60 == 0 {
			x.hab.Roll()
		}
		if n%300 == 150 && x.hab.On.Load() {
			x.prewarm(ctx)
		}
	}
}

func upName(u *Upstream) string {
	if l := u.Label(); l != "" {
		return l + " (" + u.Proto() + ")"
	}
	return u.Name
}

// prewarm resolves the usual names of the coming hour that are not cached (max 40, 5/s).
func (x *V28) prewarm(ctx context.Context) {
	names := x.hab.Upcoming(10*time.Minute, 40)
	tk := time.NewTicker(200 * time.Millisecond)
	defer tk.Stop()
	for _, n := range names {
		if x.s.bl.Blocked(n) || x.threat.Blocked(n) {
			continue
		}
		k := cacheKey(n, dns.TypeA, dns.ClassINET)
		if e, fresh := x.s.cache.Get(k); e != nil && fresh {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(n), dns.TypeA)
		x.s.refresh(k, upstreamQuery(m), &x.hab.Warmed)
	}
}

func (x *V28) addEvent(e HealEvent) {
	e.T = x.now().Unix()
	x.mu.Lock()
	x.events = append(x.events, e)
	if len(x.events) > 300 {
		x.events = x.events[len(x.events)-300:]
	}
	b, _ := json.Marshal(x.events)
	x.mu.Unlock()
	log.Printf("smart: %s: %s (%s)", e.Kind, e.Detail, e.Action)
	if x.dir != "" {
		p := filepath.Join(x.dir, "goproxy-heal.json")
		if os.WriteFile(p+".tmp", b, 0o600) == nil {
			_ = os.Rename(p+".tmp", p)
		}
	}
}

func (x *V28) Events(since int64) []HealEvent {
	x.mu.Lock()
	defer x.mu.Unlock()
	var out []HealEvent
	for i := len(x.events) - 1; i >= 0; i-- {
		if x.events[i].T >= since {
			out = append(out, x.events[i])
		}
	}
	return out
}

// heal compares the last 5 minutes with the hour before and reacts.
func (x *V28) heal() {
	if !x.healOn.Load() {
		return
	}
	now := x.now().Unix()
	cur := x.ts.Sum(now-300, now)
	base := x.ts.Sum(now-3900, now-300)
	al, res := x.s.alerts, x.s.res
	// latency spike on forwarded lookups
	if cur.Fwd >= 30 && base.Fwd >= 100 && cur.FwdAvgMs > max(2.5*base.FwdAvgMs, 150) {
		act := "racing every upstream for 10 min"
		res.Widen(10 * time.Minute)
		if u := res.DemoteWorstRaced(10 * time.Minute); u != nil {
			act += "; " + upName(u) + " demoted for 10 min"
		}
		if !x.active("v28:heal:lat") {
			x.addEvent(HealEvent{Kind: "latency", Detail: fmt.Sprintf("lookups took %.0f ms on average (usual %.0f ms)", cur.FwdAvgMs, base.FwdAvgMs), Action: act})
		}
		al.Raise(Alert{Key: "v28:heal:lat", Kind: "heal", Title: "Self-healing: DNS got slow", Message: fmt.Sprintf("Uncached lookups averaged %.0f ms (usual %.0f ms). Action: %s.", cur.FwdAvgMs, base.FwdAvgMs, act)})
	} else if cur.Fwd >= 10 && x.active("v28:heal:lat") && cur.FwdAvgMs < max(1.5*base.FwdAvgMs, 100) {
		al.Clear("v28:heal:lat", "Lookup speed is back to normal")
		x.addEvent(HealEvent{Kind: "recovered", Detail: "lookup speed back to normal", Action: "none"})
	}
	// cache hit rate drop
	if cur.Q >= 100 && base.Q >= 500 && base.HitRate() >= 0.5 && cur.HitRate() < base.HitRate()-0.25 {
		if !x.active("v28:heal:hit") {
			go x.s.sweep()
			go x.prewarm(x.s.ctx)
			x.addEvent(HealEvent{Kind: "hit_rate", Detail: fmt.Sprintf("cache answered %.0f%% (usual %.0f%%)", 100*cur.HitRate(), 100*base.HitRate()), Action: "re-warmed popular and usual names"})
		}
		al.Raise(Alert{Key: "v28:heal:hit", Kind: "heal", Level: "info", Title: "Self-healing: cache hit rate dropped", Message: fmt.Sprintf("The cache answered %.0f%% of lookups (usual %.0f%%). Popular names were re-warmed.", 100*cur.HitRate(), 100*base.HitRate())})
	} else if cur.Q >= 50 && x.active("v28:heal:hit") && cur.HitRate() >= base.HitRate()-0.1 {
		al.Clear("v28:heal:hit", "Cache hit rate is back to normal")
	}
	// failures
	if cur.Q >= 30 && 100*cur.Failed > 10*cur.Q {
		if !x.active("v28:heal:fail") {
			res.Widen(10 * time.Minute)
			x.addEvent(HealEvent{Kind: "failures", Detail: fmt.Sprintf("%d of %d lookups failed", cur.Failed, cur.Q), Action: "racing every upstream for 10 min"})
		}
		al.Raise(Alert{Key: "v28:heal:fail", Kind: "heal", Title: "Self-healing: lookups failing", Message: fmt.Sprintf("%d of %d lookups failed in 5 minutes. Racing every upstream for 10 minutes.", cur.Failed, cur.Q)})
	} else if cur.Q >= 10 && x.active("v28:heal:fail") && 100*cur.Failed <= 3*cur.Q {
		al.Clear("v28:heal:fail", "Lookups are working again")
	}
}

func (x *V28) active(key string) bool {
	for _, a := range x.s.alerts.Active() {
		if a.Key == key {
			return true
		}
	}
	return false
}

// ---- API ----

func (x *V28) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v28/status", x.serveStatus)
	mux.HandleFunc("/api/v28/config", x.serveConfig)
	mux.HandleFunc("/api/v28/series", x.serveSeries)
	mux.HandleFunc("/api/v28/report", x.serveReport)
	mux.HandleFunc("/api/v28/impact", x.imp.serve)
	mux.HandleFunc("/api/v28/speed", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, x.sp.Status()) })
	x.registerPro(mux)
}

func (x *V28) serveStatus(w http.ResponseWriter, r *http.Request) {
	st := x.s.settings.Get()
	heat, top := x.hab.Heat()
	writeJSON(w, map[string]any{
		"config": st.V28, "default_threat_lists": defaultThreatLists,
		"speed":    x.sp.Status(),
		"smart":    map[string]any{"on": !st.V28.SmartOff, "n": st.V28.smartN(), "widened": x.s.res.Widened(), "upstreams": x.s.res.SmartStats(), "probes": x.probes.Load(), "explore_every": exploreEvery},
		"prefetch": map[string]any{"on": x.prefetchOn.Load(), "rate": x.rate.Load(), "done": x.Prefetched.Load(), "skipped": x.PrefSkipped.Load()},
		"habits":   map[string]any{"on": x.hab.On.Load(), "warmed": x.hab.Warmed.Load(), "heat": heat, "top": top, "now": hourOfWeek(x.now())},
		"heal":     map[string]any{"on": x.healOn.Load(), "events": x.Events(x.now().Add(-7 * 24 * time.Hour).Unix())},
		"threat":   map[string]any{"on": st.V28.ThreatOn, "size": x.threat.Size(), "updated": x.threat.Updated.Load(), "updating": x.threat.Updating.Load(), "blocked": x.Threats.Load()},
		"detect":   map[string]any{"on": x.det.On.Load(), "block": x.det.Block.Load(), "dga": x.det.DGA.Load(), "tunnel": x.det.Tunnel.Load(), "blocked": x.det.Blocked.Load(), "events": x.det.Events()},
		"dnssec":   map[string]any{"strict": x.strict.Load(), "passthrough": x.s.stats.DNSSECPass.Load()},
		"ttl":      map[string]any{"on": x.vol.On.Load(), "tracked": x.vol.Size(), "extended": x.vol.Extended.Load(), "shortened": x.vol.Shortened.Load()},
		"tsdb":     map[string]any{"bytes": x.ts.FileBytes(), "max_bytes": tsSlots * tsRecSize, "days": tsSlots / 1440},
	})
}

func (x *V28) serveConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{"config": x.s.settings.Get().V28})
		return
	}
	if !postOnly(w, r) {
		return
	}
	var in V28Config
	if err := readJSON(r, &in); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	by := "dashboard"
	if x.s.v27 != nil {
		by = x.s.v27.v.by(r)
	}
	next, diff, err := x.s.settings.Update(by, "v2.8 smart settings saved", func(st *Settings) error {
		if err := validateV28(&in); err != nil {
			return err
		}
		st.V28 = in
		return nil
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	x.s.applyV28(next)
	writeJSON(w, map[string]any{"ok": true, "diff": diff, "config": next.V28})
}

var seriesRanges = map[string][2]int64{"1h": {3600, 60}, "24h": {86400, 600}, "7d": {7 * 86400, 3600}, "30d": {30 * 86400, 4 * 3600}}

func (x *V28) serveSeries(w http.ResponseWriter, r *http.Request) {
	rg, ok := seriesRanges[r.URL.Query().Get("range")]
	if !ok {
		rg = seriesRanges["24h"]
	}
	if s, err := strconv.Atoi(r.URL.Query().Get("step")); err == nil && s >= 60 {
		rg[1] = int64(s)
	}
	now := x.now().Unix()
	pts := x.ts.Series(now-rg[0], now, rg[1])
	sum := x.ts.Sum(now-rg[0], now)
	prev := x.ts.Sum(now-2*rg[0], now-rg[0])
	writeJSON(w, map[string]any{"step": rg[1], "from": now - rg[0], "to": now, "points": pts, "total": sum, "hit_rate": sum.HitRate(), "p95_ms": sum.P95(),
		"prev_total": prev, "prev_hit_rate": prev.HitRate(), "prev_p95_ms": prev.P95()})
}

type reportView struct {
	From      int64         `json:"from"`
	To        int64         `json:"to"`
	This      TSPoint       `json:"this"`
	Prev      TSPoint       `json:"prev"`
	HitRate   [2]float64    `json:"hit_rate"`
	P95       [2]float64    `json:"p95_ms"`
	Days      []TSPoint     `json:"days"`
	Top       []hostStat    `json:"top_domains"`
	Heal      []HealEvent   `json:"heal"`
	Detect    []DetectEvent `json:"detect"`
	Anomalies []string      `json:"anomalies"`
	Grade     string        `json:"grade"`
	Outages   int           `json:"outages"`
	OutageMin float64       `json:"outage_minutes"`
}

func (x *V28) Report() reportView {
	now := x.now().Unix()
	wk := int64(7 * 86400)
	v := reportView{From: now - wk, To: now}
	v.This, v.Prev = x.ts.Sum(now-wk, now), x.ts.Sum(now-2*wk, now-wk)
	v.HitRate = [2]float64{v.This.HitRate(), v.Prev.HitRate()}
	v.P95 = [2]float64{v.This.P95(), v.Prev.P95()}
	_, off := x.now().Zone()
	start := now - wk
	start -= (start + int64(off)) % 86400
	v.Days = x.ts.Series(start, now, 86400)
	v.Heal = x.Events(now - wk)
	for _, e := range x.det.Events() {
		if e.T >= now-wk {
			v.Detect = append(v.Detect, e)
		}
	}
	if x.weekly != nil {
		wv := x.weekly.View()
		v.Top = wv.TopDomains
		if len(v.Top) > 10 {
			v.Top = v.Top[:10]
		}
		v.Outages, v.OutageMin = len(wv.Outages), wv.OutageMin
	}
	// anomalies: days far from the weekly mean, spikes in failures, detections, heals
	var mean float64
	for _, d := range v.Days {
		mean += float64(d.Q)
	}
	if len(v.Days) > 0 {
		mean /= float64(len(v.Days))
	}
	for _, d := range v.Days {
		day := time.Unix(d.T, 0).Format("Mon Jan 2")
		if len(v.Days) >= 3 && mean > 500 && float64(d.Q) > 2*mean {
			v.Anomalies = append(v.Anomalies, fmt.Sprintf("%s: %s lookups, about %.1fx a usual day", day, fmtInt(int64(d.Q)), float64(d.Q)/mean))
		}
		if d.Q >= 200 && 100*d.Failed > 5*d.Q {
			v.Anomalies = append(v.Anomalies, fmt.Sprintf("%s: %.1f%% of lookups failed", day, 100*float64(d.Failed)/float64(d.Q)))
		}
	}
	if n := len(v.Detect); n > 0 {
		v.Anomalies = append(v.Anomalies, fmt.Sprintf("%d suspicious domain(s) flagged (DGA / tunneling)", n))
	}
	if n := len(v.Heal); n > 0 {
		v.Anomalies = append(v.Anomalies, fmt.Sprintf("self-healing acted %d time(s)", n))
	}
	if v.Outages > 0 {
		v.Anomalies = append(v.Anomalies, fmt.Sprintf("%d internet outage(s), %.0f min in total", v.Outages, v.OutageMin))
	}
	switch hr, p := v.HitRate[0], v.P95[0]; {
	case v.This.Q == 0:
		v.Grade = "–"
	case hr >= 0.8 && p <= 50 && v.This.Failed*100 <= v.This.Q:
		v.Grade = "A"
	case hr >= 0.6 && p <= 100:
		v.Grade = "B"
	case p <= 250:
		v.Grade = "C"
	default:
		v.Grade = "D"
	}
	return v
}

func fmtInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func (x *V28) serveReport(w http.ResponseWriter, r *http.Request) { writeJSON(w, x.Report()) }
