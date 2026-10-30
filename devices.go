// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Devices (spec 04, IP-based; no router access) + quiet-device watch (item g) + IPv6
// coverage (spec 06, passive signals only).

type devStat struct {
	Queries, Hits, Stale, Failed, Blocked atomic.Int64
	A, AAAA, HTTPS                        atomic.Int64
	Last                                  atomic.Int64 // unix nano
}

type deviceMeta struct {
	Alias    string `json:"alias,omitempty"`
	Group    string `json:"group,omitempty"`
	Watched  bool   `json:"watched,omitempty"`
	QuietMin int    `json:"quiet_min,omitempty"` // default 60
	LastSeen int64  `json:"last_seen,omitempty"` // persisted for watched devices
}

type groupDef struct {
	Name  string `json:"name"`
	Color string `json:"color,omitempty"`
}

type groupsFile struct {
	Version int                    `json:"version"`
	Devices map[string]*deviceMeta `json:"devices"`
	Groups  []groupDef             `json:"groups"`
}

const maxDevices = 4096

type Devices struct {
	m        sync.Map // ip -> *devStat
	count    atomic.Int64
	mu       sync.Mutex
	g        groupsFile
	path     string
	settings *settingsStore
	alerts   *Alerts
	names    *ClientNames
	flight   *Flight
	started  time.Time
	now      func() time.Time
}

func NewDevices(path string, st *settingsStore, al *Alerts) *Devices {
	d := &Devices{path: path, settings: st, alerts: al, started: time.Now(), now: time.Now}
	d.g = groupsFile{Version: 1, Devices: map[string]*deviceMeta{}}
	if b, err := os.ReadFile(path); err == nil {
		var g groupsFile
		if json.Unmarshal(b, &g) == nil && g.Devices != nil {
			d.g = g
		}
	}
	return d
}

// Record is on the query path: O(1), atomics only once the device exists.
func (d *Devices) Record(ip string, qtype uint16, result string) {
	if d == nil || ip == "" {
		return
	}
	v, ok := d.m.Load(ip)
	if !ok {
		if d.count.Load() >= maxDevices {
			return
		}
		var loaded bool
		v, loaded = d.m.LoadOrStore(ip, &devStat{})
		if !loaded {
			d.count.Add(1)
		}
	}
	s := v.(*devStat)
	s.Queries.Add(1)
	switch result {
	case "cached":
		s.Hits.Add(1)
	case "stale":
		s.Hits.Add(1)
		s.Stale.Add(1)
	case "failed":
		s.Failed.Add(1)
	case "blocked":
		s.Blocked.Add(1)
	}
	switch qtype {
	case dns.TypeA:
		s.A.Add(1)
	case dns.TypeAAAA:
		s.AAAA.Add(1)
	case dns.TypeHTTPS:
		s.HTTPS.Add(1)
	}
	s.Last.Store(d.now().UnixNano())
}

func (d *Devices) lastSeen(ip string) time.Time {
	if v, ok := d.m.Load(ip); ok {
		if t := v.(*devStat).Last.Load(); t > 0 {
			return time.Unix(0, t)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if m := d.g.Devices[ip]; m != nil && m.LastSeen > 0 {
		return time.Unix(m.LastSeen, 0)
	}
	return time.Time{}
}

type deviceView struct {
	IP        string   `json:"ip"`
	Name      string   `json:"name"`
	PTR       string   `json:"ptr,omitempty"`
	Alias     string   `json:"alias,omitempty"`
	Group     string   `json:"group"`
	Queries   int64    `json:"queries"`
	HitPct    float64  `json:"hit_pct"`
	Stale     int64    `json:"stale"`
	Failed    int64    `json:"failed"`
	Blocked   int64    `json:"blocked"`
	LastSeen  string   `json:"last_seen,omitempty"`
	AgoSec    int64    `json:"ago_sec"`
	V6        bool     `json:"v6"`
	AAAARatio float64  `json:"aaaa_ratio"`
	Watched   bool     `json:"watched"`
	QuietMin  int      `json:"quiet_min,omitempty"`
	Quiet     bool     `json:"quiet"`
	Online    bool     `json:"online"`
	TopDomain []string `json:"top_domains,omitempty"`
	P95Ms     float64  `json:"p95_ms,omitempty"`
	Suspect   []string `json:"suspect,omitempty"`
}

func (d *Devices) name(ip string, m *deviceMeta) (string, string) {
	ptr := ""
	if d.names != nil {
		ptr = d.names.Name(ip)
	}
	if m != nil && m.Alias != "" {
		return m.Alias, ptr
	}
	if ptr != "" {
		return ptr, ptr
	}
	return ip, ptr
}

// List builds the device table. detail adds top domains and p95 from the flight recorder.
func (d *Devices) List(detail bool) []deviceView {
	if d == nil {
		return nil
	}
	now := d.now()
	d.mu.Lock()
	meta := map[string]deviceMeta{}
	for ip, m := range d.g.Devices {
		meta[ip] = *m
	}
	d.mu.Unlock()
	var top map[string]map[string]int
	var lat map[string][]int64
	if detail && d.flight != nil {
		top, lat = map[string]map[string]int{}, map[string][]int64{}
		for _, e := range d.flight.Snapshot() {
			if top[e.Client] == nil {
				top[e.Client] = map[string]int{}
			}
			top[e.Client][e.Name]++
			lat[e.Client] = append(lat[e.Client], e.LatUs)
		}
	}
	seen := map[string]bool{}
	var out []deviceView
	add := func(ip string, s *devStat) {
		seen[ip] = true
		m := meta[ip]
		v := deviceView{IP: ip, Alias: m.Alias, Group: m.Group, Watched: m.Watched, QuietMin: m.QuietMin}
		if v.Group == "" {
			v.Group = "Ungrouped"
		}
		v.Name, v.PTR = d.name(ip, &m)
		v.V6 = strings.Contains(ip, ":")
		if s != nil {
			v.Queries, v.Stale, v.Failed, v.Blocked = s.Queries.Load(), s.Stale.Load(), s.Failed.Load(), s.Blocked.Load()
			if v.Queries > 0 {
				v.HitPct = float64(int(1000*float64(s.Hits.Load())/float64(v.Queries))) / 10
			}
			if a := s.A.Load() + s.AAAA.Load(); a > 0 {
				v.AAAARatio = float64(s.AAAA.Load()) / float64(a)
			}
			if a, aaaa, h := s.A.Load(), s.AAAA.Load(), s.HTTPS.Load(); v.Queries >= 200 && a > 0 && aaaa == 0 && h == 0 {
				v.Suspect = append(v.Suspect, "asks only for IPv4 (A) records: it may look up IPv6 somewhere else, or it is an IPv4-only device")
			}
		}
		if t := d.lastSeen(ip); !t.IsZero() {
			v.LastSeen = t.Format(time.RFC3339)
			v.AgoSec = int64(now.Sub(t).Seconds())
			v.Online = now.Sub(t) < 10*time.Minute
		} else {
			v.AgoSec = -1
		}
		if m.Watched {
			v.Quiet = d.isQuiet(ip, m, now)
		}
		if top != nil {
			type kv struct {
				k string
				v int
			}
			var l []kv
			for k, c := range top[ip] {
				l = append(l, kv{k, c})
			}
			sort.Slice(l, func(i, j int) bool { return l[i].v > l[j].v || l[i].v == l[j].v && l[i].k < l[j].k })
			for i := 0; i < len(l) && i < 10; i++ {
				v.TopDomain = append(v.TopDomain, fmt.Sprintf("%s (%d)", l[i].k, l[i].v))
			}
			if ls := lat[ip]; len(ls) > 0 {
				sort.Slice(ls, func(i, j int) bool { return ls[i] < ls[j] })
				v.P95Ms = float64(ls[len(ls)*95/100]) / 1000
			}
		}
		out = append(out, v)
	}
	d.m.Range(func(k, val any) bool {
		add(k.(string), val.(*devStat))
		return true
	})
	for ip := range meta {
		if !seen[ip] {
			add(ip, nil)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Queries > out[j].Queries || out[i].Queries == out[j].Queries && out[i].IP < out[j].IP
	})
	return out
}

func quietLimit(m deviceMeta) time.Duration {
	return time.Duration(orInt(m.QuietMin, 60)) * time.Minute
}

// isQuiet: no query for the device's limit. Silence is only counted from when GoProxy
// started (while it was stopped we cannot know).
func (d *Devices) isQuiet(ip string, m deviceMeta, now time.Time) bool {
	ref := d.lastSeen(ip)
	if ref.Before(d.started) {
		ref = d.started
	}
	return now.Sub(ref) >= quietLimit(m)
}

// CheckQuiet raises/clears the quiet-device alerts (every minute from Run).
func (d *Devices) CheckQuiet() {
	st := d.settings.Get()
	now := d.now()
	d.mu.Lock()
	meta := map[string]deviceMeta{}
	for ip, m := range d.g.Devices {
		meta[ip] = *m
	}
	d.mu.Unlock()
	for ip, m := range meta {
		key := "quiet:" + ip
		if !m.Watched || !st.Feature("quiet_watch") {
			d.alerts.Clear(key, "")
			continue
		}
		name, _ := d.name(ip, &m)
		if d.isQuiet(ip, m, now) {
			ago := "since GoProxy started"
			if t := d.lastSeen(ip); !t.IsZero() {
				ago = "for " + now.Sub(t).Round(time.Minute).String()
			}
			d.alerts.Raise(Alert{Key: key, Kind: "quiet", Title: "Quiet device: " + name,
				Message: fmt.Sprintf("%s (%s) has made no DNS lookups %s (limit %d min). Check that it is powered and on Wi-Fi.", name, ip, ago, orInt(m.QuietMin, 60))})
		} else {
			d.alerts.Clear(key, fmt.Sprintf("%s (%s) is active again.", name, ip))
		}
	}
}

func (d *Devices) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.CheckQuiet()
	}
}

func (d *Devices) saveLocked() error {
	if d.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(d.g, "", "  ")
	if err := os.WriteFile(d.path+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(d.path+".tmp", d.path)
}

// Save persists aliases, groups and the last-seen time of watched devices.
func (d *Devices) Save() error {
	if d == nil {
		return nil
	}
	for ip := range d.watchedIPs() {
		if v, ok := d.m.Load(ip); ok {
			if t := v.(*devStat).Last.Load(); t > 0 {
				d.mu.Lock()
				if m := d.g.Devices[ip]; m != nil {
					m.LastSeen = t / 1e9
				}
				d.mu.Unlock()
			}
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.saveLocked()
}

func (d *Devices) watchedIPs() map[string]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string]bool{}
	for ip, m := range d.g.Devices {
		if m.Watched {
			out[ip] = true
		}
	}
	return out
}

type deviceEdit struct {
	IP       string  `json:"ip"`
	Alias    *string `json:"alias"`
	Group    *string `json:"group"`
	Watched  *bool   `json:"watched"`
	QuietMin *int    `json:"quiet_min"`
}

func (d *Devices) Edit(e deviceEdit) error {
	if net.ParseIP(e.IP) == nil {
		return fmt.Errorf("bad IP")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	m := d.g.Devices[e.IP]
	if m == nil {
		m = &deviceMeta{}
		d.g.Devices[e.IP] = m
	}
	if e.Alias != nil {
		if len(*e.Alias) > 64 {
			return fmt.Errorf("name too long")
		}
		m.Alias = strings.TrimSpace(*e.Alias)
	}
	if e.Group != nil {
		g := strings.TrimSpace(*e.Group)
		if g == "Ungrouped" {
			g = ""
		}
		if g != "" && !d.hasGroupLocked(g) {
			d.g.Groups = append(d.g.Groups, groupDef{Name: g})
		}
		m.Group = g
	}
	if e.Watched != nil {
		m.Watched = *e.Watched
	}
	if e.QuietMin != nil {
		if *e.QuietMin < 5 || *e.QuietMin > 7*24*60 {
			return fmt.Errorf("quiet time must be 5 minutes to 7 days")
		}
		m.QuietMin = *e.QuietMin
	}
	if *m == (deviceMeta{}) {
		delete(d.g.Devices, e.IP)
	}
	return d.saveLocked()
}

func (d *Devices) hasGroupLocked(g string) bool {
	for _, x := range d.g.Groups {
		if x.Name == g {
			return true
		}
	}
	return false
}

type groupEdit struct {
	Action string `json:"action"` // create | rename | delete
	Name   string `json:"name"`
	To     string `json:"to"`
	Color  string `json:"color"`
}

func (d *Devices) EditGroup(e groupEdit) error {
	e.Name, e.To = strings.TrimSpace(e.Name), strings.TrimSpace(e.To)
	if e.Name == "" || len(e.Name) > 40 || e.Name == "Ungrouped" {
		return fmt.Errorf("bad group name")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch e.Action {
	case "create":
		if !d.hasGroupLocked(e.Name) {
			d.g.Groups = append(d.g.Groups, groupDef{Name: e.Name, Color: e.Color})
		}
	case "rename":
		if e.To == "" || len(e.To) > 40 || d.hasGroupLocked(e.To) {
			return fmt.Errorf("bad new name")
		}
		for i := range d.g.Groups {
			if d.g.Groups[i].Name == e.Name {
				d.g.Groups[i].Name = e.To
			}
		}
		for _, m := range d.g.Devices {
			if m.Group == e.Name {
				m.Group = e.To
			}
		}
	case "delete":
		var keep []groupDef
		for _, g := range d.g.Groups {
			if g.Name != e.Name {
				keep = append(keep, g)
			}
		}
		d.g.Groups = keep
		for _, m := range d.g.Devices {
			if m.Group == e.Name {
				m.Group = ""
			}
		}
	default:
		return fmt.Errorf("unknown action")
	}
	return d.saveLocked()
}

type groupRoll struct {
	Name    string  `json:"name"`
	Devices int     `json:"devices"`
	Online  int     `json:"online"`
	Queries int64   `json:"queries"`
	HitPct  float64 `json:"hit_pct"`
	Failed  int64   `json:"failed"`
}

func rollup(list []deviceView, groups []groupDef) []groupRoll {
	by := map[string]*groupRoll{}
	order := []string{}
	for _, g := range groups {
		by[g.Name] = &groupRoll{Name: g.Name}
		order = append(order, g.Name)
	}
	hits := map[string]float64{}
	for _, v := range list {
		r := by[v.Group]
		if r == nil {
			r = &groupRoll{Name: v.Group}
			by[v.Group] = r
			order = append(order, v.Group)
		}
		r.Devices++
		if v.Online {
			r.Online++
		}
		r.Queries += v.Queries
		r.Failed += v.Failed
		hits[v.Group] += v.HitPct * float64(v.Queries) / 100
	}
	var out []groupRoll
	for _, n := range order {
		r := by[n]
		if r.Queries > 0 {
			r.HitPct = float64(int(1000*hits[n]/float64(r.Queries))) / 10
		}
		out = append(out, *r)
	}
	return out
}

// ---------------- IPv6 coverage (spec 06, passive) ----------------

type coverageView struct {
	Enabled   bool     `json:"enabled"`
	Score     int      `json:"score"` // -1 = not enough data
	PCHasIPv6 bool     `json:"pc_has_ipv6"`
	PCIPv6    []string `json:"pc_ipv6"`
	V6Clients int      `json:"v6_clients"`
	Reasons   []string `json:"reasons"`
	Suspects  []string `json:"suspects"`
	Hint      string   `json:"hint"`
}

func pcIPv6(ifs []ifaceAddr) []string {
	var out []string
	for _, i := range ifs {
		if !i.Up || i.Loopback || virtualAdapter(i.Name) {
			continue
		}
		for _, ip := range i.IPs {
			if ip.To4() == nil && (ip.IsGlobalUnicast() || ip.IsPrivate()) {
				out = append(out, ip.String())
			}
		}
	}
	return out
}

func coverage(list []deviceView, pcV6 []string) coverageView {
	v := coverageView{Enabled: true, PCIPv6: pcV6, PCHasIPv6: len(pcV6) > 0, Score: 100,
		Hint: "If devices skip GoProxy over IPv6: in your router, set the LAN IPv6 DNS (RDNSS / DHCPv6) to this PC's IPv6 address, or turn off IPv6 DNS there. GoProxy never changes the router."}
	var total int64
	for _, d := range list {
		total += d.Queries
		if d.V6 && d.IP != "::1" {
			v.V6Clients++
		}
		if len(d.Suspect) > 0 {
			v.Suspects = append(v.Suspects, d.Name+" ("+d.IP+"): "+d.Suspect[0])
		}
	}
	if total < 500 {
		v.Score = -1
		v.Reasons = append(v.Reasons, "not enough queries yet to judge")
		return v
	}
	if v.PCHasIPv6 && v.V6Clients == 0 {
		v.Score -= 30
		v.Reasons = append(v.Reasons, "the network has IPv6 but no device has asked GoProxy over IPv6: devices may be using an IPv6 DNS server from the router or the ISP instead of GoProxy")
	}
	v.Score -= min(10*len(v.Suspects), 50)
	v.Score = max(v.Score, 0)
	if len(v.Reasons) == 0 && len(v.Suspects) == 0 {
		v.Reasons = append(v.Reasons, "no signs of devices bypassing GoProxy")
	}
	return v
}

// ---------------- HTTP ----------------

func (d *Devices) serveList(w http.ResponseWriter, r *http.Request) {
	st := d.settings.Get()
	if !st.Feature("devices") {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	list := d.List(true)
	d.mu.Lock()
	groups := append([]groupDef(nil), d.g.Groups...)
	d.mu.Unlock()
	cv := coverageView{Score: -1}
	if st.Feature("ipv6_check") {
		cv = coverage(list, pcIPv6(systemIfaces()))
	}
	writeJSON(w, map[string]any{"enabled": true, "devices": list, "groups": groups, "rollup": rollup(list, groups), "coverage": cv,
		"note": "Devices are identified by IP address. If the router gives a device a new address, its name and group stay with the old address: a DHCP reservation in your router keeps them stable."})
}

// groupOf returns the device's group ("" = ungrouped). Only used after a filter match.
func (d *Devices) groupOf(ip string) string {
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if m := d.g.Devices[ip]; m != nil {
		return m.Group
	}
	return ""
}
