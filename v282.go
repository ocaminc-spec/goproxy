// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// GoProxy DNS v2.8.2: per-device lookup view (aggregated, local only, size-capped),
// automatic .home names from the router's reverse lookups, panic recovery on the query
// path, and a Stability card (cache restored, health, last backup, watchdog).

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

const (
	v282MaxDevices = 256 // devices tracked in the per-device view
	v282MaxDomains = 400 // live domains per device (trimmed to the top 60 on disk)
	v282DiskTop    = 60
	v282Hours      = 48 // hourly buckets kept per device
)

type devAgg struct {
	Q, Blocked, Failed, Cached int64
	LatUs                      int64 // sum of answer times (µs), for the average
	Hours                      [v282Hours]int64
	HourBase                   int64 // unix hour of Hours[0]
	Domains                    map[string]int64
	Last                       int64
}

type V282 struct {
	s       *DNSServer
	path    string
	opsPath string
	mu      sync.Mutex
	dev     map[string]*devAgg
	auto    atomic.Pointer[map[string]net.IP]
	panics  atomic.Int64
	started time.Time
	now     func() time.Time
}

func NewV282(s *DNSServer, dir string) *V282 {
	x := &V282{s: s, dev: map[string]*devAgg{}, started: time.Now(), now: time.Now}
	if dir != "" {
		x.path = filepath.Join(dir, "goproxy-devstats.json")
		x.opsPath = filepath.Join(dir, "goproxy-ops.json")
		if b, err := os.ReadFile(x.path); err == nil {
			var m map[string]*devAgg
			if json.Unmarshal(b, &m) == nil {
				for k, v := range m {
					if v.Domains == nil {
						v.Domains = map[string]int64{}
					}
					x.dev[k] = v
				}
			}
		}
	}
	s.v282 = x
	return x
}

// ---- panic recovery ----

func (s *DNSServer) recoverDNS(w dns.ResponseWriter, req *dns.Msg) {
	r := recover()
	if r == nil {
		return
	}
	if s.v282 != nil {
		s.v282.panics.Add(1)
	}
	log.Printf("PANIC in DNS handler (recovered): %v\n%s", r, debug.Stack())
	if req != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	}
}

func recoverHTTP(x *V282, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				x.panics.Add(1)
				log.Printf("PANIC in %s (recovered): %v", r.URL.Path, v)
				http.Error(w, "internal error", 500)
			}
		}()
		h(w, r)
	}
}

// ---- per-device aggregation (query path: one short lock) ----

func (x *V282) observe(ip, name, result string, d time.Duration) {
	if x == nil || ip == "" {
		return
	}
	now := x.now()
	hr := now.Unix() / 3600
	x.mu.Lock()
	a := x.dev[ip]
	if a == nil {
		if len(x.dev) >= v282MaxDevices {
			x.mu.Unlock()
			return
		}
		a = &devAgg{Domains: map[string]int64{}, HourBase: hr - v282Hours + 1}
		x.dev[ip] = a
	}
	a.shift(hr)
	a.Q++
	a.Hours[v282Hours-1]++
	a.LatUs += d.Microseconds()
	a.Last = now.Unix()
	switch {
	case blockedResult(result):
		a.Blocked++
	case result == "failed":
		a.Failed++
	case result == "cached" || result == "stale":
		a.Cached++
	}
	if name != "" {
		if _, ok := a.Domains[name]; !ok && len(a.Domains) >= v282MaxDomains {
			a.trim(v282MaxDomains / 2)
		}
		a.Domains[name]++
	}
	x.mu.Unlock()
}

// shift moves the hourly window so the last bucket is hour hr.
func (a *devAgg) shift(hr int64) {
	last := a.HourBase + v282Hours - 1
	if hr <= last {
		return
	}
	k := hr - last
	if k >= v282Hours {
		a.Hours = [v282Hours]int64{}
	} else {
		copy(a.Hours[:], a.Hours[k:])
		for i := v282Hours - int(k); i < v282Hours; i++ {
			a.Hours[i] = 0
		}
	}
	a.HourBase = hr - v282Hours + 1
}

func (a *devAgg) top(n int) []kv {
	out := make([]kv, 0, len(a.Domains))
	for k, v := range a.Domains {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N > out[j].N || out[i].N == out[j].N && out[i].K < out[j].K })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (a *devAgg) trim(n int) {
	keep := a.top(n)
	a.Domains = make(map[string]int64, len(keep)*2)
	for _, e := range keep {
		a.Domains[e.K] = e.N
	}
}

type kv struct {
	K string `json:"name"`
	N int64  `json:"count"`
}

func (x *V282) Save() error {
	if x.path == "" {
		return nil
	}
	x.mu.Lock()
	out := make(map[string]*devAgg, len(x.dev))
	for k, a := range x.dev {
		c := *a
		c.Domains = map[string]int64{}
		for _, e := range a.top(v282DiskTop) {
			c.Domains[e.K] = e.N
		}
		out[k] = &c
	}
	x.mu.Unlock()
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(x.path+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(x.path+".tmp", x.path)
}

// ---- names ----

func (x *V282) displayName(ip string) (name, home string) {
	if x.s.devices != nil {
		x.s.devices.mu.Lock()
		if m := x.s.devices.g.Devices[ip]; m != nil && m.Alias != "" {
			name = m.Alias
		}
		x.s.devices.mu.Unlock()
	}
	if st := x.s.settings; st != nil {
		for n, v := range st.Get().LocalNames {
			for _, f := range splitList(v) {
				if f == ip {
					home = n
				}
			}
		}
	}
	if home == "" {
		if am := x.auto.Load(); am != nil {
			for n, aip := range *am {
				if aip.String() == ip {
					home = n
				}
			}
		}
	}
	if name == "" && x.s.names != nil {
		name = x.s.names.Name(ip)
	}
	if name == "" {
		name = home
	}
	return
}

func (x *V282) autoName(key string) ([]net.IP, bool) {
	am := x.auto.Load()
	if am == nil || !strings.HasSuffix(key, ".home") {
		return nil, false
	}
	ip, ok := (*am)[key]
	if !ok {
		return nil, false
	}
	return []net.IP{ip}, true
}

// homeLabel turns a router PTR name ("Alexs-iPhone.lan") into "alexs-iphone".
func homeLabel(ptr string) string {
	ptr = strings.ToLower(strings.TrimSuffix(ptr, "."))
	if i := strings.IndexByte(ptr, '.'); i > 0 {
		ptr = ptr[:i]
	}
	var b strings.Builder
	for _, r := range ptr {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == ' ':
			b.WriteByte('-')
		}
	}
	l := strings.Trim(b.String(), "-")
	if len(l) > 63 || l == "" || l == "localhost" || l == "this-pc" || net.ParseIP(ptr) != nil {
		return ""
	}
	if strings.Count(l, "-") >= 3 && strings.IndexFunc(l, func(r rune) bool { return r >= 'a' && r <= 'z' }) < 0 {
		return "" // all-digit "192-168-0-5" style
	}
	return l
}

func (x *V282) rebuildAuto() {
	cn := x.s.names
	if cn == nil {
		return
	}
	manual := x.s.settings.Get().LocalNames
	m := map[string]net.IP{}
	cn.mu.Lock()
	for ip, e := range cn.m {
		l := homeLabel(e.name)
		pip := net.ParseIP(ip)
		if l == "" || pip == nil || pip.IsLoopback() {
			continue
		}
		n := l + ".home"
		if _, taken := manual[n]; taken {
			continue
		}
		if _, dup := m[n]; dup && pip.To4() == nil {
			continue // prefer the IPv4 address
		}
		m[n] = pip
	}
	cn.mu.Unlock()
	x.auto.Store(&m)
}

// seedNames is a no-op in the public build.
func (x *V282) seedNames() {} // release build: no default names; add yours in Settings › Local names

func (x *V282) Run(ctx context.Context) {
	x.seedNames()
	x.rebuildAuto()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			_ = x.Save()
			return
		case <-t.C:
		}
		n++
		x.rebuildAuto()
		if n%10 == 0 {
			if err := x.Save(); err != nil {
				log.Printf("devstats: %v", err)
			}
		}
	}
}

// ---- API ----

func (x *V282) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v282/devices", recoverHTTP(x, x.serveDevices))
	mux.HandleFunc("/api/v282/stability", recoverHTTP(x, x.serveStability))
	mux.HandleFunc("/api/v282/names", recoverHTTP(x, x.serveNames))
}

type devRow struct {
	IP      string  `json:"ip"`
	Name    string  `json:"name,omitempty"`
	Home    string  `json:"home,omitempty"`
	Q       int64   `json:"queries"`
	Blocked int64   `json:"blocked"`
	Failed  int64   `json:"failed"`
	HitPct  float64 `json:"hit_pct"`
	AvgMs   float64 `json:"avg_ms"`
	Last    int64   `json:"last"`
	Hours   []int64 `json:"hours"`
	Top     []kv    `json:"top"`
}

func (x *V282) serveDevices(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	ntop := 5
	if r.URL.Query().Get("ip") != "" {
		ntop = 25
	}
	hr := x.now().Unix() / 3600
	type raw struct {
		ip string
		a  devAgg
		t  []kv
	}
	var rows []raw
	x.mu.Lock()
	for ip, a := range x.dev {
		if f := r.URL.Query().Get("ip"); f != "" && f != ip {
			continue
		}
		a.shift(hr)
		rows = append(rows, raw{ip, *a, a.top(ntop)})
	}
	x.mu.Unlock()
	out := make([]devRow, 0, len(rows))
	for _, e := range rows {
		name, home := x.displayName(e.ip)
		if q != "" && !strings.Contains(strings.ToLower(e.ip+" "+name+" "+home), q) {
			found := false
			for _, d := range e.t {
				if strings.Contains(d.K, q) {
					found = true
				}
			}
			if !found {
				continue
			}
		}
		v := devRow{IP: e.ip, Name: name, Home: home, Q: e.a.Q, Blocked: e.a.Blocked, Failed: e.a.Failed, Last: e.a.Last, Top: e.t}
		v.Hours = append([]int64(nil), e.a.Hours[24:]...)
		if e.a.Q > 0 {
			v.HitPct = float64(int(1000*float64(e.a.Cached)/float64(e.a.Q))) / 10
			v.AvgMs = float64(int(float64(e.a.LatUs)/float64(e.a.Q)/10)) / 100
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Q > out[j].Q || out[i].Q == out[j].Q && out[i].IP < out[j].IP })
	writeJSON(w, map[string]any{"devices": out, "tracked": len(rows), "cap": v282MaxDevices})
}

func (x *V282) serveNames(w http.ResponseWriter, r *http.Request) {
	auto := map[string]string{}
	if am := x.auto.Load(); am != nil {
		for n, ip := range *am {
			auto[n] = ip.String()
		}
	}
	writeJSON(w, map[string]any{"manual": x.s.settings.Get().LocalNames, "auto": auto, "router": x.s.ptrServer})
}

func (x *V282) serveStability(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"version":        Version,
		"vendor":         Vendor,
		"cache_restored": x.s.restored.Load(),
		"uptime_s":       int64(time.Since(x.started).Seconds()),
		"panics":         x.panics.Load(),
		"cache_mb":       float64(x.s.cache.Bytes()/10485) / 100,
	}
	if fi, err := os.Stat(x.s.cacheFile); err == nil {
		out["cache_saved"] = fi.ModTime().Unix()
		out["cache_file_mb"] = float64(fi.Size()/10485) / 100
	}
	if x.opsPath != "" {
		if b, err := os.ReadFile(x.opsPath); err == nil {
			var ops map[string]any
			if json.Unmarshal(b, &ops) == nil {
				out["ops"] = ops // written by the host's backup + watchdog scripts
			}
		}
	}
	writeJSON(w, out)
}
