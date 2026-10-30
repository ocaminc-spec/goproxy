// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Settings are dashboard choices that survive restarts (goproxy-settings.json next to
// the cache file). Unknown fields are ignored by older versions, so a roll back is safe.
type Settings struct {
	BlockingPaused bool `json:"blocking_paused"`

	// v2.4: per-feature switches (missing = the feature's default, see featureDefaults).
	Features map[string]bool `json:"features,omitempty"`

	// Alerts (spec 02). ntfy is OFF unless ntfy_on is true AND a topic is set.
	ExpectedIP   string      `json:"expected_ip,omitempty"`
	NtfyOn       bool        `json:"ntfy_on,omitempty"`
	NtfyServer   string      `json:"ntfy_server,omitempty"`
	NtfyTopic    string      `json:"ntfy_topic,omitempty"`
	NtfyToken    string      `json:"ntfy_token,omitempty"` // never sent back to the dashboard
	PeerToken    string      `json:"peer_token,omitempty"` // v2.6.0, encrypted at rest, never sent back
	Peers        []PeerEntry `json:"peers,omitempty"`
	WarmupList   string      `json:"warmup_list,omitempty"` // v2.6.0 names always preloaded at start
	KumaURL      string      `json:"kuma_url,omitempty"`    // v2.6.0 Uptime Kuma base URL (LAN), e.g. http://192.168.1.123:3001
	KumaSlug     string      `json:"kuma_slug,omitempty"`   // its status page slug (default "dns")
	NtfyIPChange bool        `json:"ntfy_ip_change,omitempty"`
	NtfyQuiet    bool        `json:"ntfy_quiet,omitempty"`
	NtfyOutage   bool        `json:"ntfy_outage,omitempty"`

	// Local names answered by GoProxy itself, e.g. "nas.home" -> "192.168.1.123".
	LocalNames map[string]string `json:"local_names,omitempty"`

	// Upstreams (applied live since v2.5.1).
	Quad9ECS      bool   `json:"quad9_ecs,omitempty"`
	ExtraUpstream string `json:"extra_upstream,omitempty"`  // optional extra DoH URL
	ExtraBoot     string `json:"extra_bootstrap,omitempty"` // its IPs, comma separated
	UpstreamSet   string `json:"upstream_set,omitempty"`    // replaces the default DoH list (presets); empty = default
	Preset        string `json:"preset,omitempty"`          // last applied upstream preset (informational)
	// v2.5.1 DNS Servers: ordered (index = priority), applied live. Empty = the defaults
	// derived from the fields above plus UltraDNS Public at the bottom.
	DNSServers []UpstreamEntry `json:"dns_servers,omitempty"`

	// Engine tuning overrides (nil = the command-line flag / built-in default).
	// Applied at the next start. A flag given explicitly on the command line wins.
	Tune TuneOverrides `json:"tune,omitempty"`

	// Retention.
	FlightMinutes int `json:"flight_minutes,omitempty"` // flight recorder window (default 10)
	AuditDays     int `json:"audit_days,omitempty"`     // audit log retention (default 90)
	OutageMonths  int `json:"outage_months,omitempty"`  // outage log retention (default 24)
	CanaryMinutes int `json:"canary_minutes,omitempty"` // self-test interval (default 5)

	// v2.4.2 Ads & Tracking filter. OFF by default (global). Per device (IP) and per group
	// overrides: "on" / "off" (absent = Default, follows the group, then the global switch).
	AdsFilter    bool              `json:"ads_filter,omitempty"`
	AdsAnalytics bool              `json:"ads_analytics,omitempty"` // also Google Analytics / Tag Manager
	AdsExtra     string            `json:"ads_extra,omitempty"`     // extra domains, comma separated
	AdsClients   map[string]string `json:"ads_clients,omitempty"`
	AdsGroups    map[string]string `json:"ads_groups,omitempty"`
	AdsSchedules []adsSchedule     `json:"ads_schedules,omitempty"`

	// v2.4.2 auto-rollback after a dashboard update (off by default).
	AutoRollback bool `json:"auto_rollback,omitempty"`
	// v2.4.2 reject updates without a valid release signature (off by default; a WRONG
	// signature is always rejected).
	RequireSigned bool `json:"require_signed,omitempty"`

	// v2.7.0 (blocking, alerts, webhook, peer sync, backups, per-device rules)
	V27 V27Config `json:"v27,omitempty"`
	// v2.8.0 smart server (smart upstreams, prefetch, habits, self-healing, threat feeds, detection, DNSSEC, adaptive TTL, TSDB)
	V28 V28Config `json:"v28,omitempty"`
}

type TuneOverrides struct {
	CacheGB        *int64   `json:"cache_gb,omitempty"`
	MinTTLSec      *int64   `json:"min_ttl_sec,omitempty"`
	MaxTTLSec      *int64   `json:"max_ttl_sec,omitempty"`
	StaleSec       *int64   `json:"stale_sec,omitempty"`
	StaleTimeoutMs *int64   `json:"stale_timeout_ms,omitempty"`
	PrefetchHits   *int64   `json:"prefetch_hits,omitempty"`
	PrefetchAt     *float64 `json:"prefetch_at,omitempty"`
	Siblings       *bool    `json:"siblings,omitempty"`
	KeepHot        *int64   `json:"keep_hot,omitempty"`
	Warmup         *int64   `json:"warmup,omitempty"`
	RaceFirst      *int64   `json:"race_first,omitempty"`
	CacheMB        *int64   `json:"cache_mb,omitempty"`
	PlainFallback  *bool    `json:"plain_fallback,omitempty"`
	WarmupRate     *float64 `json:"warmup_rate,omitempty"`
	ParallelAll    *bool    `json:"parallel_all,omitempty"`
}

// Feature names and defaults. Everything new in v2.4 can be switched off on its own.
var featureDefaults = map[string]bool{
	"watchdog":      true,
	"ip_watch":      true,
	"canary":        true,
	"devices":       true,
	"ipv6_check":    true,
	"outage_log":    true,
	"quiet_watch":   true,
	"flight_rec":    true,
	"drift_alert":   true,
	"local_names":   true,
	"kiosk":         false,
	"device_volume": false, // v2.6.0 per-device query volume (opt-in)
}

func (s Settings) Feature(name string) bool {
	if v, ok := s.Features[name]; ok {
		return v
	}
	return featureDefaults[name]
}

func (s Settings) ntfyReady() bool { return s.NtfyOn && strings.TrimSpace(s.NtfyTopic) != "" }

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// clone deep-copies the maps so a stored snapshot can never be changed through an alias.
func (s Settings) clone() Settings {
	b, _ := json.Marshal(s)
	var c Settings
	_ = json.Unmarshal(b, &c)
	return c
}

// settingsChange is one entry of the config history.
type settingsChange struct {
	ID     int64    `json:"id"`
	At     string   `json:"at"`
	By     string   `json:"by"`
	What   string   `json:"what"`
	Diff   []string `json:"diff"`
	Before Settings `json:"before"`
}

type settingsStore struct {
	mu    sync.Mutex
	path  string
	cur   atomic.Pointer[Settings]
	audit func(ip, action, detail string)
}

func (st *settingsStore) Load() (Settings, error) {
	var s Settings
	if st == nil || st.path == "" {
		return s, nil
	}
	b, err := os.ReadFile(st.path)
	if err != nil {
		st.cur.Store(&s)
		return s, err
	}
	err = json.Unmarshal(b, &s)
	st.openSettings(&s)
	st.cur.Store(&s)
	return s, err
}

// Get returns the current settings (cheap; safe on the query path).
func (st *settingsStore) Get() Settings {
	if st == nil {
		return Settings{}
	}
	if p := st.cur.Load(); p != nil {
		return *p
	}
	return Settings{}
}

// Save writes atomically (tmp + rename) so a crash never leaves a half-written file.
func (st *settingsStore) Save(s Settings) error {
	if st == nil {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.saveLocked(s)
}

func (st *settingsStore) saveLocked(s Settings) error {
	cp := s.clone()
	st.cur.Store(&cp)
	if st.path == "" {
		return nil
	}
	disk := s.clone()
	if err := st.sealSettings(&disk); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(disk, "", "  ")
	if err := os.WriteFile(st.path+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(st.path+".tmp", st.path)
}

// Update applies fn to a copy of the settings, saves it, records the change in the config
// history (with a diff) and the audit log. It never holds the lock while fn talks to the
// network or disk beyond the settings file itself.
func (st *settingsStore) Update(by, what string, fn func(*Settings) error) (Settings, []string, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	before := st.Get().clone()
	next := before.clone()
	if err := fn(&next); err != nil {
		return before, nil, err
	}
	diff := diffSettings(before, next)
	if len(diff) == 0 {
		return next, nil, nil
	}
	if err := st.saveLocked(next); err != nil {
		return before, nil, err
	}
	st.appendHistory(settingsChange{At: time.Now().Format(time.RFC3339), By: by, What: what, Diff: diff, Before: before})
	if st.audit != nil {
		st.audit(by, "settings: "+what, strings.Join(diff, "; "))
	}
	return next, diff, nil
}

func (st *settingsStore) historyPath() string {
	if st.path == "" {
		return ""
	}
	return strings.TrimSuffix(st.path, ".json") + "-history.json"
}

const maxHistory = 50

func (st *settingsStore) History() []settingsChange {
	p := st.historyPath()
	if p == "" {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var h []settingsChange
	_ = json.Unmarshal(b, &h)
	for i := range h {
		st.openSettings(&h[i].Before)
	}
	return h
}

func (st *settingsStore) appendHistory(c settingsChange) {
	p := st.historyPath()
	if p == "" {
		return
	}
	h := st.History()
	c.ID = time.Now().UnixNano()
	if n := len(h); n > 0 && h[n-1].ID >= c.ID {
		c.ID = h[n-1].ID + 1
	}
	if st.sealSettings(&c.Before) != nil {
		c.Before.NtfyToken, c.Before.PeerToken = "", "" // never write a secret in plain text
	}
	for i := range h {
		_ = st.sealSettings(&h[i].Before)
	}
	h = append(h, c)
	if len(h) > maxHistory {
		h = h[len(h)-maxHistory:]
	}
	b, _ := json.Marshal(h)
	if os.WriteFile(p+".tmp", b, 0o600) == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

// Revert restores the settings as they were before history entry id. The revert itself is
// recorded too, so it can be undone.
func (st *settingsStore) Revert(id int64, by string) ([]string, error) {
	var target *Settings
	for _, c := range st.History() {
		if c.ID == id {
			b := c.Before
			target = &b
		}
	}
	if target == nil {
		return nil, fmt.Errorf("no history entry %d", id)
	}
	_, diff, err := st.Update(by, fmt.Sprintf("revert to before #%d", id), func(s *Settings) error {
		*s = target.clone()
		return nil
	})
	return diff, err
}

// diffSettings lists changed fields as "name: old -> new" (secrets masked).
func diffSettings(a, b Settings) []string {
	fa, fb := flatten(a), flatten(b)
	keys := map[string]bool{}
	for k := range fa {
		keys[k] = true
	}
	for k := range fb {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		if fa[k] == fb[k] {
			continue
		}
		va, vb := fa[k], fb[k]
		if strings.Contains(k, "token") {
			va, vb = mask(va), mask(vb)
		}
		out = append(out, fmt.Sprintf("%s: %s -> %s", k, orDash(va), orDash(vb)))
	}
	sort.Strings(out)
	return out
}

func mask(s string) string {
	if s == "" {
		return ""
	}
	return "••••"
}

func orDash(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

// flatten turns settings into dotted keys -> string values.
func flatten(s Settings) map[string]string {
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, vv)
			}
		case []any:
			if len(x) > 0 {
				b, _ := json.Marshal(x)
				out[prefix] = string(b)
			}
		default:
			if v == nil || (reflect.ValueOf(v).IsZero() && !strings.HasPrefix(prefix, "features.")) {
				return
			}
			out[prefix] = fmt.Sprint(v)
		}
	}
	walk("", m)
	return out
}
