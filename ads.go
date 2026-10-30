// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Ads & Tracking filter (v2.4.2). OFF by default. A small, curated, built-in list of
// Google ad / ad-stats names and common trackers. It can NOT block the ads inside YouTube
// videos: those come from the same servers as the videos (youtube.com, googlevideo.com),
// which are pinned and never blocked.
//
// Who is filtered: per device (by IP), then per group, then the global switch. An active
// schedule entry for the device or its group overrides all of these.

// adsCore: Google ad serving and ad statistics.
var adsCore = []string{
	"doubleclick.net", "googleads.g.doubleclick.net", "ad.doubleclick.net", "static.doubleclick.net",
	"stats.g.doubleclick.net", "pagead2.googlesyndication.com", "googlesyndication.com",
	"googleadservices.com", "adservice.google.com", "partnerad.l.doubleclick.net",
	"pubads.g.doubleclick.net", "securepubads.g.doubleclick.net", "tpc.googlesyndication.com",
}

// adsTrackers: common third-party trackers (not Google Analytics; see adsAnalytics).
var adsTrackers = []string{
	"app-measurement.com", "adnxs.com", "scorecardresearch.com", "taboola.com", "outbrain.com",
	"criteo.com", "criteo.net", "moatads.com", "amazon-adsystem.com", "ads.yahoo.com",
	"adsrvr.org", "rubiconproject.com", "pubmatic.com", "openx.net", "casalemedia.com",
}

// adsAnalytics: Google Analytics / Tag Manager. Separate sub-switch because blocking them
// can break logins or checkouts on some websites.
var adsAnalytics = []string{
	"google-analytics.com", "ssl.google-analytics.com", "www.google-analytics.com",
	"analytics.google.com", "googletagmanager.com", "googletagservices.com",
}

// adsNeverBlock: names that look like ads but are needed by video players / apps. They are
// never blocked by this filter, even if added to the extra list.
var adsNeverBlock = []string{
	"imasdk.googleapis.com", // Google IMA SDK: blocking it breaks many video players (TVs, news sites)
	"youtube.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com",
	"netflix.com", "nflxvideo.net", "nflxso.net", "nflxext.com",
	// Note: parents like google.com / googleapis.com are deliberately NOT here, or
	// adservice.google.com would be protected too. Connectivity checks come from
	// connectivityNames / -never-block.
}

const (
	adsModeDefault = ""
	adsModeOn      = "on"
	adsModeOff     = "off"
)

// adsSchedule: during [From, To) local time (HH:MM, may wrap past midnight) on the given
// days, the target's filter is Mode. Target is a device IP or "group:<name>".
type adsSchedule struct {
	Target string `json:"target"`
	Mode   string `json:"mode"`
	From   string `json:"from"`
	To     string `json:"to"`
	Days   string `json:"days,omitempty"` // e.g. "mon,tue,wed"; empty = every day
}

type adsConfig struct {
	global    bool
	set       map[string]struct{}
	never     map[string]struct{}
	clients   map[string]string
	groups    map[string]string
	schedules []adsSchedule
	any       bool // global on, or any client/group/schedule could turn it on
}

type AdsFilter struct {
	cfg     atomic.Pointer[adsConfig]
	pinned  func(name string) bool // pinned / never-block check from the server
	groupOf func(ip string) string
	now     func() time.Time
	mu      sync.Mutex
	daily   map[string]int64 // YYYY-MM-DD -> blocked count
	total   atomic.Int64
}

func NewAdsFilter() *AdsFilter {
	f := &AdsFilter{now: time.Now, daily: map[string]int64{}}
	f.cfg.Store(&adsConfig{})
	return f
}

func normIP(ip string) string {
	if p := net.ParseIP(strings.TrimSpace(ip)); p != nil {
		if v4 := p.To4(); v4 != nil {
			return v4.String()
		}
		return p.String()
	}
	return strings.TrimSpace(ip)
}

// adsList returns the active list for the settings (built-in + analytics + extra).
func adsList(st Settings) []string {
	l := append(append([]string{}, adsCore...), adsTrackers...)
	if st.AdsAnalytics {
		l = append(l, adsAnalytics...)
	}
	return append(l, splitList(st.AdsExtra)...)
}

// Apply rebuilds the filter from settings (on start, Save and Revert). Never on the query path.
func (f *AdsFilter) Apply(st Settings) {
	if f == nil {
		return
	}
	c := &adsConfig{global: st.AdsFilter, set: map[string]struct{}{}, never: map[string]struct{}{}, clients: map[string]string{}, groups: map[string]string{}}
	for _, d := range adsList(st) {
		addDomain(d, c.set)
	}
	for _, d := range adsNeverBlock {
		addDomain(d, c.never)
	}
	for ip, m := range st.AdsClients {
		c.clients[normIP(ip)] = m
		c.any = c.any || m == adsModeOn
	}
	for g, m := range st.AdsGroups {
		c.groups[g] = m
		c.any = c.any || m == adsModeOn
	}
	c.schedules = append(c.schedules, st.AdsSchedules...)
	for _, s := range st.AdsSchedules {
		c.any = c.any || s.Mode == adsModeOn
	}
	c.any = c.any || c.global
	f.cfg.Store(c)
}

// Listed reports whether name (or a parent) is on the filter list and not protected.
// Protection (pinned, never-block, adsNeverBlock) always wins.
func (f *AdsFilter) Listed(name string) (bool, string) {
	c := f.cfg.Load()
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var hit string
	for d := name; d != ""; {
		if _, ok := c.never[d]; ok {
			return false, ""
		}
		if hit == "" {
			if _, ok := c.set[d]; ok {
				hit = d
			}
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	if hit == "" {
		return false, ""
	}
	if f.pinned != nil && f.pinned(name) {
		return false, ""
	}
	return true, hit
}

func hhmm(s string) (int, bool) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, false
	}
	return t.Hour()*60 + t.Minute(), true
}

func (s adsSchedule) active(now time.Time) bool {
	from, ok1 := hhmm(s.From)
	to, ok2 := hhmm(s.To)
	if !ok1 || !ok2 || from == to {
		return false
	}
	m := now.Hour()*60 + now.Minute()
	day := now
	in := false
	if from < to {
		in = m >= from && m < to
	} else { // wraps midnight: 21:00-07:00
		in = m >= from || m < to
		if m < to {
			day = now.AddDate(0, 0, -1) // the window started yesterday
		}
	}
	if !in {
		return false
	}
	if strings.TrimSpace(s.Days) == "" {
		return true
	}
	d := strings.ToLower(day.Weekday().String()[:3])
	for _, x := range splitList(strings.ToLower(s.Days)) {
		if x == d {
			return true
		}
	}
	return false
}

// Decision explains whether the filter applies to client ip and why.
func (f *AdsFilter) Decision(ip string) (bool, string) {
	c := f.cfg.Load()
	ip = normIP(ip)
	group := ""
	if f.groupOf != nil && ip != "" {
		group = f.groupOf(ip)
	}
	now := f.now()
	for _, s := range c.schedules {
		if (s.Target == ip || (group != "" && s.Target == "group:"+group)) && s.active(now) {
			return s.Mode == adsModeOn, fmt.Sprintf("schedule %s-%s for %s", s.From, s.To, s.Target)
		}
	}
	if m := c.clients[ip]; m != "" {
		return m == adsModeOn, "device setting (" + m + ")"
	}
	if group != "" {
		if m := c.groups[group]; m != "" {
			return m == adsModeOn, "group " + group + " (" + m + ")"
		}
	}
	if c.global {
		return true, "global switch (on)"
	}
	return false, "global switch (off)"
}

// Block is the query-path check: cheap when nothing can turn the filter on.
func (f *AdsFilter) Block(name, ip string) bool {
	if f == nil || !f.cfg.Load().any {
		return false
	}
	if ok, _ := f.Listed(name); !ok {
		return false
	}
	if on, _ := f.Decision(ip); !on {
		return false
	}
	f.count()
	return true
}

func (f *AdsFilter) count() {
	f.total.Add(1)
	day := f.now().Format("2006-01-02")
	f.mu.Lock()
	f.daily[day]++
	if len(f.daily) > 90 {
		cut := f.now().AddDate(0, 0, -90).Format("2006-01-02")
		for k := range f.daily {
			if k < cut {
				delete(f.daily, k)
			}
		}
	}
	f.mu.Unlock()
}

type dayCount struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

// Days returns the last n days (oldest first, zero-filled).
func (f *AdsFilter) Days(n int) []dayCount {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	out := make([]dayCount, 0, n)
	for i := n - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		out = append(out, dayCount{d, f.daily[d]})
	}
	return out
}

func (f *AdsFilter) snapshot() map[string]int64 {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	m := make(map[string]int64, len(f.daily))
	for k, v := range f.daily {
		m[k] = v
	}
	return m
}

func (f *AdsFilter) restore(m map[string]int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range m {
		f.daily[k] += v
	}
}

// ---------------- validation ----------------

func validAdsMode(m string) bool { return m == adsModeOn || m == adsModeOff }

func validateAds(st *Settings, protected func(string) bool) error {
	extra := splitList(st.AdsExtra)
	if len(extra) > 500 {
		return fmt.Errorf("at most 500 extra filter domains")
	}
	var clean []string
	for _, d := range extra {
		m := map[string]struct{}{}
		if !addDomain(d, m) {
			return fmt.Errorf("extra filter domain %q is not a domain name", d)
		}
		n := normName(d)
		if protected != nil && protected(n) {
			return fmt.Errorf("%s is pinned / protected (YouTube, Netflix, connectivity checks or video players) and can't be filtered", n)
		}
		clean = append(clean, n)
	}
	st.AdsExtra = strings.Join(clean, ",")
	for ip, m := range st.AdsClients {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("device %q is not an IP address", ip)
		}
		if !validAdsMode(m) {
			return fmt.Errorf("device %s: mode must be on or off (remove it for Default)", ip)
		}
	}
	for g, m := range st.AdsGroups {
		if g == "" || len(g) > 40 || !validAdsMode(m) {
			return fmt.Errorf("group %q: mode must be on or off", g)
		}
	}
	if len(st.AdsSchedules) > 50 {
		return fmt.Errorf("at most 50 filter schedules")
	}
	for i, s := range st.AdsSchedules {
		if !validAdsMode(s.Mode) {
			return fmt.Errorf("schedule %d: mode must be on or off", i+1)
		}
		_, ok1 := hhmm(s.From)
		_, ok2 := hhmm(s.To)
		if !ok1 || !ok2 || s.From == s.To {
			return fmt.Errorf("schedule %d: times must be HH:MM (24h) and different", i+1)
		}
		if strings.HasPrefix(s.Target, "group:") {
			if len(s.Target) <= 6 {
				return fmt.Errorf("schedule %d: group name missing", i+1)
			}
		} else if net.ParseIP(s.Target) == nil {
			return fmt.Errorf("schedule %d: target must be a device IP or group:<name>", i+1)
		}
		for _, d := range splitList(strings.ToLower(s.Days)) {
			if !strings.Contains("mon,tue,wed,thu,fri,sat,sun", d) || len(d) != 3 {
				return fmt.Errorf("schedule %d: days are mon,tue,wed,thu,fri,sat,sun", i+1)
			}
		}
	}
	return nil
}

// ---------------- server glue ----------------

// protectedName: pinned names, auto-pinned suffixes (googlevideo.com...), -never-block and
// the connectivity-check names. These always win over the Ads & Tracking filter.
func (s *DNSServer) protectedName(name string) bool {
	name = normName(name)
	for _, d := range adsNeverBlock {
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	for _, d := range append(append([]string{}, s.neverBlock...), connectivityNames...) {
		d = normName(d)
		if d != "" && (name == d || strings.HasSuffix(name, "."+d)) {
			return true
		}
	}
	if s.pinned != nil {
		for _, sfx := range s.pinned.suffixes {
			if name == sfx || strings.HasSuffix(name, "."+sfx) {
				return true
			}
		}
		s.pinned.mu.RLock()
		_, ok := s.pinned.m[name]
		s.pinned.mu.RUnlock()
		if ok {
			return true
		}
	}
	return false
}

type adsView struct {
	Enabled   bool              `json:"enabled"`
	Analytics bool              `json:"analytics"`
	Today     int64             `json:"today"`
	Total     int64             `json:"total"`
	Days      []dayCount        `json:"days"`
	Builtin   []string          `json:"builtin"`
	Analytic  []string          `json:"analytics_list"`
	Never     []string          `json:"never_blocked"`
	Clients   map[string]string `json:"clients"`
	Groups    map[string]string `json:"groups"`
	Schedules []adsSchedule     `json:"schedules"`
	Active    int               `json:"devices_filtered_now"`
}

func (s *DNSServer) adsView() adsView {
	st := s.settings.Get()
	days := s.ads.Days(14)
	v := adsView{Enabled: st.AdsFilter, Analytics: st.AdsAnalytics, Days: days, Total: s.ads.total.Load(),
		Builtin: append(append([]string{}, adsCore...), adsTrackers...), Analytic: adsAnalytics, Never: adsNeverBlock,
		Clients: st.AdsClients, Groups: st.AdsGroups, Schedules: st.AdsSchedules}
	if len(days) > 0 {
		v.Today = days[len(days)-1].Count
	}
	for _, d := range s.devices.List(false) {
		if on, _ := s.ads.Decision(d.IP); on {
			v.Active++
		}
	}
	sort.Strings(v.Builtin)
	return v
}

// adsEdit: per-device / per-group mode. Mode "default" (or "") removes the override.
type adsEdit struct {
	IP    string `json:"ip,omitempty"`
	Group string `json:"group,omitempty"`
	Mode  string `json:"mode"`
}

func (v *V24) serveAdsClient(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	var e adsEdit
	if err := readJSON(r, &e); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	if e.Mode == "default" {
		e.Mode = ""
	}
	if e.Mode != "" && !validAdsMode(e.Mode) {
		jsonErr(w, 400, "mode must be default, on or off")
		return
	}
	what := ""
	switch {
	case e.IP != "":
		if net.ParseIP(e.IP) == nil {
			jsonErr(w, 400, "bad IP")
			return
		}
		e.IP = normIP(e.IP)
		what = "Ads & Tracking filter for device " + e.IP + ": " + orStr(e.Mode, "default")
	case e.Group != "":
		e.Group = strings.TrimSpace(e.Group)
		what = "Ads & Tracking filter for group " + e.Group + ": " + orStr(e.Mode, "default")
	default:
		jsonErr(w, 400, "ip or group required")
		return
	}
	next, diff, err := v.s.settings.Update(v.by(r), what, func(s *Settings) error {
		if e.IP != "" {
			if s.AdsClients == nil {
				s.AdsClients = map[string]string{}
			}
			if e.Mode == "" {
				delete(s.AdsClients, e.IP)
			} else {
				s.AdsClients[e.IP] = e.Mode
			}
			if len(s.AdsClients) == 0 {
				s.AdsClients = nil
			}
		} else {
			if s.AdsGroups == nil {
				s.AdsGroups = map[string]string{}
			}
			if e.Mode == "" {
				delete(s.AdsGroups, e.Group)
			} else {
				s.AdsGroups[e.Group] = e.Mode
			}
			if len(s.AdsGroups) == 0 {
				s.AdsGroups = nil
			}
		}
		return validateAds(s, v.s.protectedName)
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	_ = v.applyLive(next)
	writeJSON(w, map[string]any{"ok": true, "diff": diff})
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func newServerAds() *AdsFilter { return NewAdsFilter() }

// wireAds connects the filter to the pinned list and the device groups.
func (s *DNSServer) wireAds() {
	s.ads.pinned = s.protectedName
	s.ads.groupOf = func(ip string) string { return s.devices.groupOf(ip) }
}
