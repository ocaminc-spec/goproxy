// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// DNS benchmark (item t): on demand, compares candidate upstreams over DoH and plain UDP
// from this PC. It uses its own Upstream objects and connections, so the live resolver's
// stats, circuit breakers and connections are never touched; queries are paced and the run
// is limited to one every few minutes. Results are kept in goproxy-bench.json.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type benchCandidate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	DoH      string `json:"doh"`
	UDP      string `json:"udp,omitempty"`
	ECS      bool   `json:"ecs,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

var benchCandidates = []benchCandidate{
	{ID: "cloudflare", Name: "Cloudflare", Provider: "Cloudflare", DoH: "https://1.1.1.1/dns-query", UDP: "1.1.1.1:53"},
	{ID: "quad9", Name: "Quad9", Provider: "Quad9", DoH: "https://9.9.9.9/dns-query", UDP: "9.9.9.9:53"},
	{ID: "quad9ecs", Name: "Quad9 with ECS", Provider: "Quad9", DoH: quad9ECS, UDP: "9.9.9.11:53", ECS: true},
	{ID: "google", Name: "Google", Provider: "Google", DoH: "https://8.8.8.8/dns-query", UDP: "8.8.8.8:53", ECS: true},
	{ID: "adguard", Name: "AdGuard (unfiltered)", Provider: "AdGuard", DoH: "https://unfiltered.adguard-dns.com/dns-query", UDP: "94.140.14.140:53"},
	{ID: "nextdns", Name: "NextDNS (free, no profile)", Provider: "NextDNS", DoH: "https://dns.nextdns.io/dns-query", UDP: "45.90.28.0:53", Optional: true},
	// v2.5.1: UltraDNS Public has no DoH/DoT, so it is measured over plain UDP only
	{ID: "ultradns", Name: "UltraDNS Public", Provider: "UltraDNS", UDP: "64.6.64.6:53"},
	{ID: "ultradns2", Name: "UltraDNS Public (2)", Provider: "UltraDNS", UDP: "64.6.65.6:53"},
}

var benchPopular = []string{"google.com.", "www.google.com.", "facebook.com.", "instagram.com.", "amazon.com.", "apple.com.", "microsoft.com.", "wikipedia.org.", "reddit.com.", "whatsapp.net.", "spotify.com.", "bing.com."}
var benchStreaming = []string{"www.youtube.com.", "youtubei.googleapis.com.", "i.ytimg.com.", "redirector.googlevideo.com.", "www.netflix.com.", "api-global.netflix.com.", "assets.nflxext.com.", "occ-0-1-2.1.nflxso.net."}
var benchRandomParents = []string{"google.com.", "cloudflare.com.", "wikipedia.org.", "netflix.com.", "apple.com.", "amazon.com."}

type benchRow struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Provider  string  `json:"provider"`
	Proto     string  `json:"proto"` // DoH | UDP
	Addr      string  `json:"addr"`
	Current   bool    `json:"current"`
	ECS       bool    `json:"ecs,omitempty"`
	ColdMed   float64 `json:"cold_median_ms"`
	ColdP95   float64 `json:"cold_p95_ms"`
	CachedMed float64 `json:"cached_median_ms"`
	CachedP95 float64 `json:"cached_p95_ms"`
	Queries   int     `json:"queries"`
	Success   float64 `json:"success_pct"`
	Servfail  float64 `json:"servfail_pct"`
	DNSSEC    string  `json:"dnssec"` // validating | no | unknown
	Score     float64 `json:"score"`
	Rank      int     `json:"rank"`
	Error     string  `json:"error,omitempty"`
}

type benchRun struct {
	At        string     `json:"at"`
	By        string     `json:"by"`
	Seconds   float64    `json:"seconds"`
	Rows      []benchRow `json:"rows"`
	Recommend string     `json:"recommendation"`
	Fastest   []string   `json:"fastest"` // DoH URLs for the Fastest preset
}

type Bench struct {
	mu       sync.Mutex
	path     string
	running  bool
	progress string
	runs     []benchRun
	lastRun  time.Time
	Cooldown time.Duration
	Pace     time.Duration
	current  func() []string // running DoH URLs
	cands    []benchCandidate
}

func NewBench(path string, current func() []string) *Bench {
	b := &Bench{path: path, Cooldown: 3 * time.Minute, Pace: 60 * time.Millisecond, current: current, cands: benchCandidates}
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &b.runs)
	}
	return b
}

func (b *Bench) Latest() *benchRun {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.runs) == 0 {
		return nil
	}
	r := b.runs[len(b.runs)-1]
	return &r
}

// Start launches a run in the background. It refuses while one is running or within the cooldown.
func (b *Bench) Start(by string, withNextDNS bool) error {
	b.mu.Lock()
	if b.running {
		b.mu.Unlock()
		return errors.New("a benchmark is already running")
	}
	if wait := b.Cooldown - time.Since(b.lastRun); !b.lastRun.IsZero() && wait > 0 {
		b.mu.Unlock()
		return fmt.Errorf("please wait %d s before the next benchmark (it is rate-limited)", int(wait.Seconds())+1)
	}
	b.running, b.progress, b.lastRun = true, "starting", time.Now()
	b.mu.Unlock()
	go func() {
		run := b.run(by, withNextDNS)
		b.mu.Lock()
		b.runs = append(b.runs, run)
		if len(b.runs) > 20 {
			b.runs = b.runs[len(b.runs)-20:]
		}
		raw, _ := json.MarshalIndent(b.runs, "", " ")
		b.running, b.progress = false, ""
		b.mu.Unlock()
		if b.path != "" {
			if os.WriteFile(b.path+".tmp", raw, 0o644) == nil {
				_ = os.Rename(b.path+".tmp", b.path)
			}
		}
		auditf(by, "benchmark finished", run.Recommend)
	}()
	return nil
}

type benchTarget struct {
	row benchRow
	up  *Upstream
}

func (b *Bench) targets(withNextDNS bool) []benchTarget {
	cur := map[string]bool{}
	if b.current != nil {
		for _, u := range b.current() {
			cur[u] = true
		}
	}
	var ts []benchTarget
	seen := map[string]bool{}
	for _, c := range b.cands {
		if c.Optional && !withNextDNS {
			continue
		}
		if c.DoH != "" {
			ts = append(ts, benchTarget{benchRow{ID: c.ID, Name: c.Name, Provider: c.Provider, Proto: "DoH", Addr: c.DoH, Current: cur[c.DoH], ECS: c.ECS}, NewUpstream(c.DoH, nil)})
			seen[c.DoH] = true
		}
		if c.UDP != "" {
			ts = append(ts, benchTarget{benchRow{ID: c.ID + "-udp", Name: c.Name, Provider: c.Provider, Proto: "UDP", Addr: c.UDP, Current: cur[c.UDP], ECS: c.ECS}, NewUpstream(c.UDP, nil)})
			seen[c.UDP] = true
		}
	}
	for u := range cur { // current upstreams that are not in the candidate list (e.g. 1.0.0.1)
		if seen[u] {
			continue
		}
		d := serverFromString(u)
		up := newUpstreamFor(d, nil)
		host := up.Name
		ts = append(ts, benchTarget{benchRow{ID: "cur-" + host, Name: "Current: " + d.Name, Provider: providerOf(u), Proto: up.Proto(), Addr: u, Current: true, ECS: u == quad9ECS}, up})
	}
	return ts
}

func providerOf(u string) string {
	switch {
	case strings.Contains(u, "1.1.1.1"), strings.Contains(u, "1.0.0.1"), strings.Contains(u, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(u, "9.9.9"), strings.Contains(u, "149.112.112"), strings.Contains(u, "quad9"):
		return "Quad9"
	case strings.Contains(u, "8.8.8.8"), strings.Contains(u, "8.8.4.4"), strings.Contains(u, "dns.google"):
		return "Google"
	case strings.Contains(u, "adguard"), strings.Contains(u, "94.140.14"):
		return "AdGuard"
	case strings.Contains(u, "nextdns"), strings.Contains(u, "45.90.2"), strings.Contains(u, "45.90.3"):
		return "NextDNS"
	case strings.Contains(u, "64.6.64.6"), strings.Contains(u, "64.6.65.6"), strings.Contains(u, "ultradns"):
		return "UltraDNS"
	}
	return "Other"
}

func randLabel() string {
	x := make([]byte, 6)
	_, _ = rand.Read(x)
	return "gpbench-" + hex.EncodeToString(x)
}

func (b *Bench) setProgress(s string) { b.mu.Lock(); b.progress = s; b.mu.Unlock() }

func (b *Bench) run(by string, withNextDNS bool) benchRun {
	t0 := time.Now()
	ts := b.targets(withNextDNS)
	var randoms []string
	for _, p := range benchRandomParents {
		randoms = append(randoms, randLabel()+"."+p)
	}
	sem := make(chan struct{}, 4) // at most 4 servers measured at once, each paced
	var wg sync.WaitGroup
	var done sync.Mutex
	n := 0
	for i := range ts {
		wg.Add(1)
		go func(t *benchTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			b.measure(t, randoms)
			done.Lock()
			n++
			b.setProgress(fmt.Sprintf("%d of %d servers measured", n, len(ts)))
			done.Unlock()
		}(&ts[i])
	}
	wg.Wait()
	rows := make([]benchRow, len(ts))
	for i, t := range ts {
		rows[i] = t.row
	}
	rankRows(rows)
	run := benchRun{At: time.Now().Format(time.RFC3339), By: by, Seconds: math.Round(time.Since(t0).Seconds()*10) / 10, Rows: rows}
	run.Fastest = fastestPair(rows)
	run.Recommend = recommend(rows, run.Fastest)
	return run
}

func (b *Bench) ask(up *Upstream, name string, qt uint16, do bool) (*dns.Msg, float64, error) {
	q := new(dns.Msg)
	q.SetQuestion(name, qt)
	q.SetEdns0(1232, do)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	t := time.Now()
	r, err := up.Exchange(ctx, q)
	ms := float64(time.Since(t).Microseconds()) / 1000
	time.Sleep(b.Pace)
	return r, ms, err
}

func (b *Bench) measure(t *benchTarget, randoms []string) {
	row := &t.row
	up := t.up
	defer up.closeIdle()
	// connection warm-up (TLS handshake), not counted; an unreachable server is not
	// hammered with the full list (each try would wait for the timeout)
	if _, _, err := b.ask(up, "example.com.", dns.TypeA, false); err != nil && !isServfail(err) {
		if _, _, err2 := b.ask(up, "example.com.", dns.TypeA, false); err2 != nil && !isServfail(err2) {
			row.Error = "unreachable from this PC: " + shortErr(err2)
			row.DNSSEC, row.ColdMed, row.ColdP95, row.CachedMed, row.CachedP95 = "unknown", -1, -1, -1, -1
			return
		}
	}
	streak := 0
	var cold, cached []float64
	ok, sf, total := 0, 0, 0
	count := func(r *dns.Msg, err error, nxOK bool) bool {
		total++
		if err != nil && !isServfail(err) {
			streak++
		} else {
			streak = 0
		}
		if isServfail(err) {
			sf++
			return false
		}
		if err != nil || r == nil {
			return false
		}
		switch r.Rcode {
		case dns.RcodeSuccess:
			ok++
			return true
		case dns.RcodeNameError:
			if nxOK {
				ok++
				return true
			}
		case dns.RcodeServerFailure:
			sf++
		}
		return false
	}
	for _, n := range randoms { // never asked before anywhere: a true cold lookup
		if streak >= 4 {
			break
		}
		r, ms, err := b.ask(up, n, dns.TypeA, false)
		if count(r, err, true) {
			cold = append(cold, ms)
		}
	}
	for _, n := range append(append([]string{}, benchPopular...), benchStreaming...) {
		if streak >= 4 {
			row.Error = "stopped early: 4 lookups in a row got no answer"
			break
		}
		r, _, err := b.ask(up, n, dns.TypeA, false) // first ask: warms the server's cache
		count(r, err, false)
		r, ms, err := b.ask(up, n, dns.TypeA, false) // second ask: what a cached answer costs
		if count(r, err, false) {
			cached = append(cached, ms)
		}
	}
	// DNSSEC: a validating resolver sets AD on a signed name and refuses a broken one
	row.DNSSEC = "unknown"
	r1, _, e1 := b.ask(up, "cloudflare.com.", dns.TypeA, true)
	r2, _, e2 := b.ask(up, "dnssec-failed.org.", dns.TypeA, true)
	broken := isServfail(e2) || (e2 == nil && r2 != nil && r2.Rcode == dns.RcodeServerFailure)
	if e1 == nil && r1 != nil && (broken || (e2 == nil && r2 != nil)) {
		if r1.AuthenticatedData && broken {
			row.DNSSEC = "validating"
		} else {
			row.DNSSEC = "no"
		}
	}
	row.Queries = total
	if total > 0 {
		row.Success = math.Round(float64(ok)/float64(total)*1000) / 10
		row.Servfail = math.Round(float64(sf)/float64(total)*1000) / 10
	}
	row.ColdMed, row.ColdP95 = benchPct(cold, 50), benchPct(cold, 95)
	row.CachedMed, row.CachedP95 = benchPct(cached, 50), benchPct(cached, 95)
	if ok == 0 && row.Error == "" {
		row.Error = "no answers"
	}
}

// isServfail: Upstream.Exchange reports SERVFAIL/REFUSED replies as errors.
func isServfail(err error) bool {
	return err != nil && strings.Contains(err.Error(), "SERVFAIL")
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

func benchPct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return -1
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	i := int(math.Ceil(p/100*float64(len(s)))) - 1
	i = min(max(i, 0), len(s)-1)
	return math.Round(s[i]*10) / 10
}

// rankRows: lower score is better; unreliable servers go to the bottom.
func rankRows(rows []benchRow) {
	for i := range rows {
		r := &rows[i]
		if r.ColdMed < 0 || r.CachedMed < 0 {
			r.Score = 1e9
			continue
		}
		r.Score = math.Round((0.35*r.ColdMed+0.25*r.ColdP95+0.25*r.CachedMed+0.15*r.CachedP95+(100-r.Success)*40)*10) / 10
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Score < rows[j].Score })
	for i := range rows {
		rows[i].Rank = i + 1
	}
}

// fastestPair: the two best DoH servers from different providers (redundancy), reliable ones only.
func fastestPair(rows []benchRow) []string {
	var out []string
	used := map[string]bool{}
	for _, r := range rows {
		if r.Proto != "DoH" || r.Success < 98 || r.Score >= 1e9 || used[r.Provider] {
			continue
		}
		out = append(out, r.Addr)
		used[r.Provider] = true
		if len(out) == 2 {
			break
		}
	}
	return out
}

func recommend(rows []benchRow, fastest []string) string {
	var best, cur *benchRow
	for i := range rows {
		r := &rows[i]
		if r.Proto != "DoH" || r.Score >= 1e9 {
			continue
		}
		if best == nil {
			best = r
		}
		if r.Current && cur == nil {
			cur = r
		}
	}
	if best == nil {
		return "No encrypted (DoH) server answered from this PC. Check the internet connection and run the benchmark again."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Fastest encrypted server from your house: %s (%.0f ms for a new name, %.0f ms for a popular one).", best.Name, best.ColdMed, best.CachedMed)
	if cur != nil && cur != best {
		diff := cur.Score - best.Score
		if diff < 8 {
			fmt.Fprintf(&b, " Your current setup (%s) is about as fast; there is no need to change.", cur.Name)
		} else {
			fmt.Fprintf(&b, " That is noticeably quicker than your current best (%s, %.0f / %.0f ms).", cur.Name, cur.ColdMed, cur.CachedMed)
		}
	} else if cur == best {
		b.WriteString(" It is already one of your upstreams.")
	}
	if len(fastest) == 2 {
		b.WriteString(" The Fastest preset would use: " + strings.Join(fastest, " + ") + ".")
	}
	if best.ECS {
		b.WriteString(" Note: it sends part of your public IP subnet to websites' DNS (better CDN choice for YouTube/Netflix, a little less private).")
	}
	for _, r := range rows {
		if r.Proto == "UDP" && r.CachedMed >= 0 && r.CachedMed < 2 && best.CachedMed > 3*r.CachedMed+3 {
			b.WriteString(" Plain UDP to " + r.Name + " answers in under 2 ms, faster than physically possible over the internet: something on your network or at your ISP may be answering DNS itself (interception). Encrypted DoH avoids that.")
			break
		}
	}
	for _, r := range rows {
		if r.Proto == "UDP" && r.Rank < best.Rank {
			b.WriteString(" Plain UDP looks a bit faster, but it is unencrypted (your ISP can read and change it), so GoProxy only uses it as a fallback unless you move it into the top of the DNS Servers list.")
			break
		}
	}
	return b.String()
}

// ---------------- presets ----------------

var presetNames = []string{"fastest", "privacy", "streaming", "reliability", "default"}

const (
	cfA, cfB = "https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"
	q9A, q9B = "https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"
	googleA  = "https://8.8.8.8/dns-query"
)

// applyPreset changes only upstream-related settings.
func applyPreset(st *Settings, preset string, latest *benchRun) (string, error) {
	resetRace := func() { st.Tune.RaceFirst = nil }
	switch preset {
	case "fastest":
		if latest == nil || len(latest.Fastest) < 2 {
			return "", errors.New("run the benchmark first: Fastest uses its top 2 servers")
		}
		st.DNSServers = nil
		st.UpstreamSet, st.Quad9ECS = strings.Join(latest.Fastest, ","), false
		resetRace()
		return "Fastest: " + strings.Join(latest.Fastest, " + "), nil
	case "privacy":
		st.DNSServers = nil // a preset replaces the DNS Servers list (defaults derived from it)
		st.UpstreamSet, st.Quad9ECS = strings.Join([]string{cfA, cfB, q9A, q9B}, ","), false
		resetRace()
		return "Privacy: Cloudflare + Quad9 over DoH only, no ECS", nil
	case "streaming":
		st.DNSServers = nil // a preset replaces the DNS Servers list (defaults derived from it)
		st.UpstreamSet, st.Quad9ECS = "", true
		if st.Features == nil {
			st.Features = map[string]bool{}
		}
		delete(st.Features, "canary") // back to default (on): keeps checking YouTube/Netflix
		resetRace()
		return "Streaming: Quad9 with ECS + Cloudflare; YouTube/Netflix stay pinned and kept hot", nil
	case "reliability":
		st.DNSServers = nil // a preset replaces the DNS Servers list (defaults derived from it)
		st.UpstreamSet, st.Quad9ECS = strings.Join([]string{cfA, q9A, googleA}, ","), false
		two := int64(2)
		st.Tune.RaceFirst = &two
		return "Reliability: Cloudflare + Quad9 + Google (3 providers)", nil
	case "default":
		st.DNSServers = nil // a preset replaces the DNS Servers list (defaults derived from it)
		st.UpstreamSet, st.Quad9ECS, st.ExtraUpstream, st.ExtraBoot = "", false, "", ""
		resetRace()
		return "Default: Google + Cloudflare (as shipped)", nil
	}
	return "", fmt.Errorf("unknown preset %q", preset)
}

// ---------------- HTTP ----------------

func (v *V24) registerBench(mux *http.ServeMux, b *Bench) {
	mux.HandleFunc("/api/bench", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				NextDNS bool `json:"nextdns"`
			}
			_ = readJSON(r, &req)
			if err := b.Start(v.by(r), req.NextDNS); err != nil {
				jsonErr(w, 429, err.Error())
				return
			}
			auditf(v.by(r), "benchmark started", "")
			writeJSON(w, map[string]any{"ok": true})
			return
		}
		b.mu.Lock()
		hist := make([]map[string]any, 0, len(b.runs))
		for i := len(b.runs) - 1; i >= 0; i-- {
			x := b.runs[i]
			top := ""
			if len(x.Rows) > 0 {
				top = x.Rows[0].Name + " " + x.Rows[0].Proto
			}
			hist = append(hist, map[string]any{"at": x.At, "seconds": x.Seconds, "top": top, "index": i})
		}
		var latest *benchRun
		if idx := r.URL.Query().Get("run"); idx != "" {
			var i int
			if _, err := fmt.Sscan(idx, &i); err == nil && i >= 0 && i < len(b.runs) {
				x := b.runs[i]
				latest = &x
			}
		} else if len(b.runs) > 0 {
			x := b.runs[len(b.runs)-1]
			latest = &x
		}
		resp := map[string]any{"running": b.running, "progress": b.progress, "run": latest, "history": hist, "presets": presetNames, "preset": v.s.settings.Get().Preset}
		b.mu.Unlock()
		writeJSON(w, resp)
	})
	mux.HandleFunc("/api/bench/preset", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var req struct {
			Preset string `json:"preset"`
		}
		if readJSON(r, &req) != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		latest := b.Latest()
		var summary string
		next, diff, err := v.s.settings.Update(v.by(r), "preset "+req.Preset, func(s *Settings) error {
			var e error
			summary, e = applyPreset(s, req.Preset, latest)
			if e != nil {
				return e
			}
			s.Preset = req.Preset
			return validateSettings(s)
		})
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		_ = v.applyLive(next)
		writeJSON(w, map[string]any{"ok": true, "summary": summary, "diff": diff, "restart_needed": restartNeeded(v.started, next),
			"upstreams_next": upstreamList(v.upFlag, next, v.explicit["upstreams"])})
	})
}
