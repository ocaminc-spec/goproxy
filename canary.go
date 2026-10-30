// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// connectivityNames are what phones, PCs and TVs look up to decide "is there internet?".
// If these fail, devices show "no internet" even when browsing would work (item i): they
// are pinned (kept hot), never blocked, and checked by the canary.
var connectivityNames = []string{"connectivitycheck.gstatic.com", "connectivitycheck.android.com", "clients3.google.com", "captive.apple.com",
	"www.msftconnecttest.com", "dns.msftncsi.com", "detectportal.firefox.com"}

// driftNames are watched for record-type / CNAME-chain changes (item o).
var driftNames = []string{"youtube.com", "www.youtube.com", "youtubei.googleapis.com", "netflix.com", "www.netflix.com"}

type canaryResult struct {
	Name   string  `json:"name"`
	Kind   string  `json:"kind"`
	OK     bool    `json:"ok"`
	Result string  `json:"result"`
	Rcode  string  `json:"rcode"`
	Ms     float64 `json:"ms"`
	Detail string  `json:"detail,omitempty"`
	Fails  int     `json:"consecutive_fails"`
}

type driftEvent struct {
	At   string `json:"at"`
	Name string `json:"name"`
	Old  string `json:"old"`
	New  string `json:"new"`
}

// Canary (spec 03 B) resolves a fixed list through the in-process query path. It is a
// signal only: a failure never changes how anything resolves.
type Canary struct {
	s       *DNSServer
	mu      sync.Mutex
	fails   map[string]int
	results []canaryResult
	last    time.Time
	drift   map[string]string // name/type -> signature (baseline)
	pending map[string]string
	events  []driftEvent
	path    string // drift baseline file
	onFail  func(reason string)
	now     func() time.Time
}

func NewCanary(s *DNSServer, driftPath string) *Canary {
	c := &Canary{s: s, fails: map[string]int{}, drift: map[string]string{}, pending: map[string]string{}, path: driftPath, now: time.Now}
	if b, err := os.ReadFile(driftPath); err == nil {
		var saved struct {
			Baseline map[string]string `json:"baseline"`
			Events   []driftEvent      `json:"events"`
		}
		if json.Unmarshal(b, &saved) == nil && saved.Baseline != nil {
			c.drift, c.events = saved.Baseline, saved.Events
		}
	}
	return c
}

type canaryCase struct{ name, kind string }

func (c *Canary) cases() []canaryCase {
	cs := []canaryCase{{selfTestName, "self"}, {"www.youtube.com.", "youtube"}, {"www.netflix.com.", "netflix"}}
	for _, p := range c.s.pinned.List() {
		if p.Auto {
			cs = append(cs, canaryCase{dns.Fqdn(p.Name), "auto-pin"})
			break
		}
	}
	if z := c.s.local.Load(); z != nil && len(*z) > 0 {
		cs = append(cs, canaryCase{dns.Fqdn(z.names()[0]), "local"})
	}
	cs = append(cs, canaryCase{"goproxy-canary-nx.invalid.", "nxdomain"})
	for _, n := range connectivityNames {
		cs = append(cs, canaryCase{dns.Fqdn(n), "connectivity"})
	}
	return cs
}

func canaryPass(kind string, r *dns.Msg, result string) (bool, string) {
	if r == nil || result == "failed" {
		return false, "no answer"
	}
	if kind == "nxdomain" {
		if r.Rcode == dns.RcodeNameError {
			return true, ""
		}
		return false, "expected NXDOMAIN, got " + dns.RcodeToString[r.Rcode]
	}
	if r.Rcode != dns.RcodeSuccess {
		return false, "rcode " + dns.RcodeToString[r.Rcode]
	}
	for _, rr := range r.Answer {
		if t := rr.Header().Rrtype; t == dns.TypeA || t == dns.TypeAAAA {
			return true, ""
		}
	}
	return false, "no address in the answer"
}

// RunOnce runs one canary cycle and returns whether everything passed (a name only counts
// as failing after 2 failures in a row).
func (c *Canary) RunOnce() bool {
	var res []canaryResult
	okAll := true
	var bad []string
	for _, cs := range c.cases() {
		q := new(dns.Msg)
		q.SetQuestion(cs.name, dns.TypeA)
		t0 := time.Now()
		r, result, _ := c.s.Handle(q)
		ok, detail := canaryPass(cs.kind, r, result)
		cr := canaryResult{Name: strings.TrimSuffix(cs.name, "."), Kind: cs.kind, OK: ok, Result: result, Ms: float64(time.Since(t0).Microseconds()) / 1000, Detail: detail}
		if r != nil {
			cr.Rcode = dns.RcodeToString[r.Rcode]
		}
		c.mu.Lock()
		if ok {
			c.fails[cs.name] = 0
		} else {
			c.fails[cs.name]++
		}
		cr.Fails = c.fails[cs.name]
		c.mu.Unlock()
		if cr.Fails >= 2 {
			okAll = false
			bad = append(bad, cr.Name+" ("+detail+")")
		}
		res = append(res, cr)
	}
	c.mu.Lock()
	c.results, c.last = res, c.now()
	c.mu.Unlock()
	if okAll {
		c.s.health.AddCanary(1, 0)
		c.s.alerts.Clear("canary", "All self-test lookups pass again.")
	} else {
		c.s.health.AddCanary(0, 1)
		msg := "These test lookups keep failing: " + strings.Join(bad, ", ")
		c.s.alerts.Raise(Alert{Key: "canary", Kind: "canary", Level: "info", Title: "DNS self-test failing", Message: msg})
		if c.onFail != nil {
			c.onFail(msg)
		}
	}
	if c.s.settings.Get().Feature("drift_alert") {
		c.checkDrift()
	}
	return okAll
}

// signature: record types + CNAME targets of a cached answer (IPs rotate all the time and
// are deliberately ignored).
func signature(m *dns.Msg) string {
	if m == nil {
		return ""
	}
	var parts []string
	seen := map[string]bool{}
	for _, rr := range m.Answer {
		var p string
		switch x := rr.(type) {
		case *dns.CNAME:
			p = "CNAME>" + strings.ToLower(x.Target)
		default:
			p = dns.TypeToString[rr.Header().Rrtype]
		}
		if !dnssecType(rr.Header().Rrtype) && !seen[p] {
			seen[p] = true
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return "NODATA/" + dns.RcodeToString[m.Rcode]
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (c *Canary) checkDrift() {
	changed := false
	for _, n := range driftNames {
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
			e, _ := c.s.cache.Get(cacheKey(n, t, dns.ClassINET))
			if e == nil {
				continue
			}
			k := n + "/" + dns.TypeToString[t]
			sig := signature(e.Msg)
			c.mu.Lock()
			base, ok := c.drift[k]
			switch {
			case !ok:
				c.drift[k], changed = sig, true
			case base == sig:
				delete(c.pending, k)
			case c.pending[k] == sig: // seen twice in a row: real change
				c.events = append(c.events, driftEvent{At: c.now().Format(time.RFC3339), Name: k, Old: base, New: sig})
				if len(c.events) > 50 {
					c.events = c.events[len(c.events)-50:]
				}
				c.drift[k], changed = sig, true
				delete(c.pending, k)
				c.mu.Unlock()
				c.s.alerts.Raise(Alert{Key: "drift:" + k, Kind: "drift", Level: "info", Title: "Streaming DNS records changed: " + k,
					Message: fmt.Sprintf("%s changed from [%s] to [%s]. Usually harmless (YouTube/Netflix moved things around); worth knowing if a TV app starts failing.", k, base, sig)})
				continue
			default:
				c.pending[k] = sig
			}
			c.mu.Unlock()
		}
	}
	if changed && c.path != "" {
		c.mu.Lock()
		b, _ := json.Marshal(map[string]any{"baseline": c.drift, "events": c.events})
		c.mu.Unlock()
		if os.WriteFile(c.path+".tmp", b, 0o644) == nil {
			_ = os.Rename(c.path+".tmp", c.path)
		}
	}
}

type canaryView struct {
	Enabled bool           `json:"enabled"`
	Last    string         `json:"last,omitempty"`
	OK      bool           `json:"ok"`
	Results []canaryResult `json:"results"`
	Drift   []driftEvent   `json:"drift_events"`
}

func (c *Canary) View() canaryView {
	if c == nil {
		return canaryView{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v := canaryView{Enabled: c.s.settings.Get().Feature("canary"), Results: append([]canaryResult(nil), c.results...), Drift: append([]driftEvent(nil), c.events...), OK: true}
	if !c.last.IsZero() {
		v.Last = c.last.Format(time.RFC3339)
	}
	for _, r := range c.results {
		if r.Fails >= 2 {
			v.OK = false
		}
	}
	return v
}

func (c *Canary) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(45 * time.Second): // let warm-up fill the cache first
	}
	for {
		st := c.s.settings.Get()
		if st.Feature("canary") {
			c.RunOnce()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(orInt(st.CanaryMinutes, 5)) * time.Minute):
		}
	}
}
