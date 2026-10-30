// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.7.0: dashboard-managed ad blocking, alerts engine with a generic webhook, settings and
// blocklist sync between peers, peer failover watch, nightly backups, per-device rules.
//
// Defaults (all conservative):
//   - ad blocking OFF (nothing is downloaded until switched on),
//   - webhook OFF and no endpoint set,
//   - peer sync automatic but only acts once a synced setting changes (newest wins),
//   - peer watch on when peers + token are set (dashboard alert only unless a push is on),
//   - nightly backup on (local data dir, 7 copies),
//   - per-device rules OFF behind the "device_volume" approval switch.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var defaultBlocklists = []string{
	"https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
	"https://small.oisd.nl/domainswild",
}

// V27Config lives in Settings.V27.
type V27Config struct {
	// Blocking (synced between peers)
	BlockOn    bool     `json:"block_on,omitempty"`
	BlockLists []string `json:"block_lists,omitempty"` // empty = defaultBlocklists
	BlockAllow []string `json:"block_allow,omitempty"`
	BlockDeny  []string `json:"block_deny,omitempty"`

	// Alerts engine
	AlertSlowMs  int    `json:"alert_slow_ms,omitempty"`  // p95 over 5 min; default 300
	AlertFailPct int    `json:"alert_fail_pct,omitempty"` // failed answers over 5 min; default 20
	AlertsOff    bool   `json:"alerts_off,omitempty"`
	WebhookOn    bool   `json:"webhook_on,omitempty"`
	WebhookKind  string `json:"webhook_kind,omitempty"`  // ntfy | pushover | json
	WebhookURL   string `json:"webhook_url,omitempty"`   // secret (sealed, masked)
	WebhookToken string `json:"webhook_token,omitempty"` // secret: ntfy bearer / Pushover app token
	WebhookUser  string `json:"webhook_user,omitempty"`  // Pushover user key

	// Peer sync / watch
	SyncOff   bool   `json:"sync_off,omitempty"`
	SyncStamp int64  `json:"sync_stamp,omitempty"` // unix ms of the newest synced change
	SyncHash  string `json:"sync_hash,omitempty"`
	SyncFrom  string `json:"sync_from,omitempty"`
	WatchOff  bool   `json:"watch_off,omitempty"`

	// Backups
	BackupOff bool `json:"backup_off,omitempty"`

	// Per-device rules (enforced only with the device_volume feature on)
	DeviceRules []DeviceRule `json:"device_rules,omitempty"`
}

type DeviceRule struct {
	IP      string        `json:"ip"`
	Name    string        `json:"name,omitempty"`
	Block   bool          `json:"block,omitempty"` // no internet at all (every lookup blocked)
	Bedtime []adsSchedule `json:"bedtime,omitempty"`
}

func (c V27Config) slowMs() int  { return orInt(c.AlertSlowMs, 300) }
func (c V27Config) failPct() int { return orInt(c.AlertFailPct, 20) }
func (c V27Config) lists() []string {
	if len(c.BlockLists) == 0 {
		return defaultBlocklists
	}
	return c.BlockLists
}

func validateV27(c *V27Config) error {
	for _, u := range c.BlockLists {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return fmt.Errorf("blocklist %q: must be an http(s) URL", u)
		}
	}
	if len(c.BlockLists) > 20 {
		return errors.New("at most 20 blocklists")
	}
	if len(c.BlockAllow)+len(c.BlockDeny) > 5000 {
		return errors.New("allow + block lists: at most 5000 names")
	}
	if c.AlertSlowMs < 0 || c.AlertSlowMs > 10000 || c.AlertFailPct < 0 || c.AlertFailPct > 100 {
		return errors.New("alert thresholds out of range")
	}
	switch c.WebhookKind {
	case "", "ntfy", "pushover", "json":
	default:
		return errors.New("webhook kind: ntfy, pushover or json")
	}
	if c.WebhookURL != "" && !strings.HasPrefix(c.WebhookURL, secretPrefix) && c.WebhookURL != mask("x") {
		p, err := url.Parse(c.WebhookURL)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return errors.New("webhook URL must be an http(s) URL")
		}
	}
	if c.WebhookOn && c.WebhookURL == "" {
		return errors.New("webhook: set the URL first")
	}
	if c.WebhookKind == "pushover" && c.WebhookOn && (c.WebhookToken == "" || c.WebhookUser == "") {
		return errors.New("pushover: app token and user key are required")
	}
	for i, r := range c.DeviceRules {
		if net.ParseIP(r.IP) == nil {
			return fmt.Errorf("device rule %d: %q is not an IP address", i+1, r.IP)
		}
		for _, b := range r.Bedtime {
			if _, ok := hhmm(b.From); !ok {
				return fmt.Errorf("device %s: bedtime from %q (use HH:MM)", r.IP, b.From)
			}
			if _, ok := hhmm(b.To); !ok {
				return fmt.Errorf("device %s: bedtime to %q (use HH:MM)", r.IP, b.To)
			}
		}
	}
	for _, l := range [][]string{c.BlockAllow, c.BlockDeny} {
		for _, d := range l {
			if validHostname(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), "*.")) != nil {
				return fmt.Errorf("%q is not a domain name", d)
			}
		}
	}
	return nil
}

// ---- per-device rules (hot path) ----

type devRules struct {
	by map[string]DeviceRule
}

// deviceBlocked: true when a rule blocks client now. Cheap when no rules: one atomic load.
func (s *DNSServer) deviceBlocked(client string, now time.Time) bool {
	p := s.devRules.Load()
	if p == nil || len(p.by) == 0 || client == "" {
		return false
	}
	r, ok := p.by[normIP(client)]
	if !ok {
		return false
	}
	if r.Block {
		return true
	}
	for _, b := range r.Bedtime {
		if b.active(now) {
			return true
		}
	}
	return false
}

func (s *DNSServer) applyV27(st Settings) {
	c := st.V27
	s.bl.SetSources(c.BlockOn, c.lists(), c.BlockAllow, c.BlockDeny)
	if st.Feature("device_volume") && len(c.DeviceRules) > 0 {
		m := &devRules{by: map[string]DeviceRule{}}
		for _, r := range c.DeviceRules {
			m.by[normIP(r.IP)] = r
		}
		s.devRules.Store(m)
	} else {
		s.devRules.Store(nil)
	}
}

// ---- webhook ----

type Webhook struct {
	mu     sync.Mutex
	last   map[string]time.Time
	client *http.Client
	every  time.Duration
	now    func() time.Time
}

func NewWebhook() *Webhook {
	return &Webhook{last: map[string]time.Time{}, client: &http.Client{Timeout: 8 * time.Second}, every: 30 * time.Minute, now: time.Now}
}

func webhookReady(c V27Config) bool { return c.WebhookOn && strings.TrimSpace(c.WebhookURL) != "" }

// Send posts one alert. The URL and tokens are never logged.
func (h *Webhook) Send(c V27Config, key, title, msg string, force bool) error {
	if h == nil || !webhookReady(c) {
		return errors.New("webhook is off")
	}
	h.mu.Lock()
	if t, ok := h.last[key]; ok && !force && h.now().Sub(t) < h.every {
		h.mu.Unlock()
		return nil
	}
	h.last[key] = h.now()
	h.mu.Unlock()
	var req *http.Request
	var err error
	switch c.WebhookKind {
	case "pushover":
		f := url.Values{"token": {c.WebhookToken}, "user": {c.WebhookUser}, "title": {title}, "message": {msg}}
		req, err = http.NewRequest(http.MethodPost, c.WebhookURL, strings.NewReader(f.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	case "json":
		b, _ := json.Marshal(map[string]string{"title": title, "message": msg, "key": key, "source": "goproxy"})
		req, err = http.NewRequest(http.MethodPost, c.WebhookURL, bytes.NewReader(b))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	default: // ntfy: body = message, Title header
		req, err = http.NewRequest(http.MethodPost, c.WebhookURL, strings.NewReader(msg))
		if err == nil {
			req.Header.Set("Title", title)
			req.Header.Set("Tags", "warning")
			if c.WebhookToken != "" {
				req.Header.Set("Authorization", "Bearer "+c.WebhookToken)
			}
		}
	}
	if err != nil {
		return errors.New("bad webhook URL")
	}
	resp, err := h.client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		log.Printf("webhook: send failed: %v", err)
		return errors.New("send failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("webhook: HTTP %d", resp.StatusCode)
		return fmt.Errorf("webhook answered HTTP %d", resp.StatusCode)
	}
	return nil
}

// ---- alerts engine: slow / failing server ----

// checkServer looks at the last 5 minutes and raises or clears "slow" and "failing".
func (s *DNSServer) checkServer() {
	c := s.settings.Get().V27
	if c.AlertsOff || s.health == nil {
		s.alerts.Clear("v27:slow", "")
		s.alerts.Clear("v27:fail", "")
		return
	}
	var sum HealthBucket
	for _, b := range s.health.WindowView(15*time.Second, 20) {
		sum.add(b.HealthBucket)
	}
	p95 := histP95(sum.Hist)
	if sum.Timed >= 50 && p95 > float64(c.slowMs()) {
		s.alerts.Raise(Alert{Key: "v27:slow", Kind: "slow", Title: "DNS is slow", Message: fmt.Sprintf("95%% of answers took up to %.0f ms over the last 5 minutes (limit %d ms).", p95, c.slowMs())})
	} else if sum.Timed >= 20 {
		s.alerts.Clear("v27:slow", "DNS speed is back to normal")
	}
	if sum.Queries >= 30 && 100*sum.Failures > int64(c.failPct())*sum.Queries {
		s.alerts.Raise(Alert{Key: "v27:fail", Kind: "dns", Title: "DNS lookups failing", Message: fmt.Sprintf("%d of %d lookups failed in the last 5 minutes.", sum.Failures, sum.Queries)})
	} else if sum.Queries >= 10 {
		s.alerts.Clear("v27:fail", "DNS lookups are working again")
	}
}

func histP95(h [11]int64) float64 {
	var n int64
	for _, v := range h {
		n += v
	}
	if n == 0 {
		return 0
	}
	need, acc := (n*95+99)/100, int64(0)
	for i, v := range h {
		if acc += v; acc >= need {
			return histHi(i)
		}
	}
	return histHi(len(h) - 1)
}

// ---- peer sync (newest wins) and failover watch ----

// SyncData is what peers share. No secrets, no per-device rules.
type SyncData struct {
	BlockOn      bool              `json:"block_on"`
	BlockLists   []string          `json:"block_lists"`
	BlockAllow   []string          `json:"block_allow"`
	BlockDeny    []string          `json:"block_deny"`
	LocalNames   map[string]string `json:"local_names"`
	AdsFilter    bool              `json:"ads_filter"`
	AdsAnalytics bool              `json:"ads_analytics"`
	AdsExtra     string            `json:"ads_extra"`
	AlertSlowMs  int               `json:"alert_slow_ms"`
	AlertFailPct int               `json:"alert_fail_pct"`
}

type syncState struct {
	Stamp int64    `json:"stamp"`
	Data  SyncData `json:"data"`
	Name  string   `json:"name"`
}

func syncOf(st Settings) SyncData {
	return SyncData{st.V27.BlockOn, st.V27.BlockLists, st.V27.BlockAllow, st.V27.BlockDeny, st.LocalNames,
		st.AdsFilter, st.AdsAnalytics, st.AdsExtra, st.V27.AlertSlowMs, st.V27.AlertFailPct}
}

func (d SyncData) hash() string {
	b, _ := json.Marshal(d) // maps marshal sorted: stable
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func (d SyncData) applyTo(st *Settings) {
	st.V27.BlockOn, st.V27.BlockLists, st.V27.BlockAllow, st.V27.BlockDeny = d.BlockOn, d.BlockLists, d.BlockAllow, d.BlockDeny
	st.LocalNames, st.AdsFilter, st.AdsAnalytics, st.AdsExtra = d.LocalNames, d.AdsFilter, d.AdsAnalytics, d.AdsExtra
	st.V27.AlertSlowMs, st.V27.AlertFailPct = d.AlertSlowMs, d.AlertFailPct
}

type V27 struct {
	v       *V24
	hook    *Webhook
	mu      sync.Mutex
	fails   map[string]int
	lastRun atomic.Int64
	syncLog []syncEvent
	now     func() time.Time
	backups string // backup dir
	call    func(ctx context.Context, p PeerEntry, tok, method, path string, out any) error
}

type syncEvent struct {
	At   string `json:"at"`
	Peer string `json:"peer"`
	What string `json:"what"`
}

func NewV27(v *V24) *V27 {
	return &V27{v: v, hook: NewWebhook(), fails: map[string]int{}, now: time.Now, call: peerCall,
		backups: filepath.Join(filepath.Dir(v.s.settings.path), "backups")}
}

func (x *V27) logSync(peer, what string) {
	x.mu.Lock()
	x.syncLog = append(x.syncLog, syncEvent{x.now().Format(time.RFC3339), peer, what})
	if len(x.syncLog) > 30 {
		x.syncLog = x.syncLog[len(x.syncLog)-30:]
	}
	x.mu.Unlock()
}

// stampLocal: a synced setting changed here since the last sync -> it is the newest now.
func (x *V27) stampLocal() syncState {
	st := x.v.s.settings.Get()
	h := syncOf(st).hash()
	if h != st.V27.SyncHash {
		ms := x.now().UnixMilli()
		if st.V27.SyncHash == "" {
			ms = 0 // first run after the upgrade: age unknown, never overrides a peer
		}
		next, _, err := x.v.s.settings.Update("sync", "synced settings changed here", func(s *Settings) error {
			s.V27.SyncHash, s.V27.SyncStamp, s.V27.SyncFrom = h, ms, ""
			return nil
		})
		if err == nil {
			st = next
		}
	}
	return syncState{Stamp: st.V27.SyncStamp, Data: syncOf(st), Name: hostName()}
}

func hostName() string {
	h, _ := os.Hostname()
	return h
}

// adopt applies a newer peer state locally.
func (x *V27) adopt(peer string, rs syncState) error {
	tmp := x.v.s.settings.Get().clone()
	rs.Data.applyTo(&tmp)
	if err := validateSettings(&tmp); err != nil {
		return err
	}
	if err := validateV27(&tmp.V27); err != nil {
		return err
	}
	if err := validateAds(&tmp, x.v.s.protectedName); err != nil {
		return err
	}
	next, _, err := x.v.s.settings.Update("peer "+peer, "synced from "+peer, func(s *Settings) error {
		rs.Data.applyTo(s)
		s.V27.SyncStamp, s.V27.SyncHash, s.V27.SyncFrom = rs.Stamp, rs.Data.hash(), peer
		return nil
	})
	if err != nil {
		return err
	}
	_ = x.v.applyLive(next)
	x.logSync(peer, "took newer settings from "+peer)
	return nil
}

// RunOnce: sync (pull newer state from peers) and watch peers. force = "Sync now".
func (x *V27) RunOnce(ctx context.Context, force bool) []string {
	st := x.v.s.settings.Get()
	var notes []string
	local := x.stampLocal()
	if st.PeerToken == "" || len(st.Peers) == 0 {
		return []string{"no peers set up"}
	}
	for _, p := range st.Peers {
		var rs syncState
		err := x.call(ctx, p, st.PeerToken, http.MethodGet, "/api/peer/sync", &rs)
		x.watch(p, err)
		if err != nil {
			notes = append(notes, p.Name+": "+err.Error())
			continue
		}
		if st.V27.SyncOff && !force {
			continue
		}
		switch {
		case rs.Stamp > local.Stamp && rs.Data.hash() != local.Data.hash():
			if err := x.adopt(p.Name, rs); err != nil {
				notes = append(notes, p.Name+": not applied: "+err.Error())
				x.logSync(p.Name, "rejected: "+err.Error())
			} else {
				notes = append(notes, p.Name+": took its newer settings")
				local = syncState{Stamp: rs.Stamp, Data: rs.Data}
			}
		case rs.Stamp < local.Stamp && rs.Data.hash() != local.Data.hash():
			notes = append(notes, p.Name+": has older settings (it will take ours)")
		case rs.Data.hash() == local.Data.hash():
			notes = append(notes, p.Name+": in sync")
		case force:
			ms := max(x.now().UnixMilli(), rs.Stamp+1)
			if _, _, err := x.v.s.settings.Update("sync", "Sync now: this server's settings made the newest", func(s *Settings) error {
				s.V27.SyncStamp, s.V27.SyncFrom = ms, ""
				return nil
			}); err == nil {
				local.Stamp = ms
				notes = append(notes, p.Name+": different; this server's settings are now the newest, "+p.Name+" takes them within 30 s")
				x.logSync(p.Name, "Sync now: ours made newest")
			}
		default:
			notes = append(notes, p.Name+": different, but neither side has a newer change (press Sync now on the server whose settings are right)")
		}
	}
	x.lastRun.Store(x.now().Unix())
	return notes
}

// watch: 3 failed checks in a row (about 90 s) raise a peer-down alert; one success clears it.
func (x *V27) watch(p PeerEntry, err error) {
	if x.v.s.settings.Get().V27.WatchOff {
		x.v.s.alerts.Clear("v27:peer:"+p.Name, "")
		return
	}
	x.mu.Lock()
	if err != nil {
		x.fails[p.Name]++
	} else {
		x.fails[p.Name] = 0
	}
	n := x.fails[p.Name]
	x.mu.Unlock()
	if n >= 3 {
		x.v.s.alerts.Raise(Alert{Key: "v27:peer:" + p.Name, Kind: "peer", Title: "Peer DNS server down: " + p.Name,
			Message: fmt.Sprintf("%s has not answered %d checks in a row (%v). This server keeps answering.", p.Name, n, err)})
	} else if n == 0 {
		x.v.s.alerts.Clear("v27:peer:"+p.Name, p.Name+" is answering again")
	}
}

// ---- nightly backup ----

const backupKeep = 7

// backupFiles: settings (secrets stay sealed), their key, history, auth (password hash,
// sessions), kiosk, devices. Contents are copied, never logged.
func (x *V27) backupFiles() []string {
	d := filepath.Dir(x.v.s.settings.path)
	var out []string
	for _, f := range []string{"goproxy-settings.json", "goproxy-settings-history.json", "goproxy-secret.key", "goproxy-auth.json", "goproxy-kiosk.json", "goproxy-groups.json", "goproxy-habits.json", "goproxy-versions.json"} {
		p := filepath.Join(d, f)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (x *V27) BackupNow() (string, int, error) {
	name := x.now().Format("2006-01-02_150405")
	dir := filepath.Join(x.backups, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", 0, err
	}
	n := 0
	for _, src := range x.backupFiles() {
		b, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, filepath.Base(src)), b, 0o600); err != nil {
			return name, n, err
		}
		n++
	}
	x.rotate()
	log.Printf("backup: %s, %d files", name, n) // names only, never contents
	return name, n, nil
}

func (x *V27) rotate() {
	es, _ := os.ReadDir(x.backups)
	var ds []string
	for _, e := range es {
		if e.IsDir() {
			ds = append(ds, e.Name())
		}
	}
	sort.Strings(ds)
	for len(ds) > backupKeep {
		_ = os.RemoveAll(filepath.Join(x.backups, ds[0]))
		ds = ds[1:]
	}
}

type backupView struct {
	Name  string   `json:"name"`
	Files []string `json:"files"`
	Bytes int64    `json:"bytes"`
}

func (x *V27) Backups() []backupView {
	es, _ := os.ReadDir(x.backups)
	var out []backupView
	for i := len(es) - 1; i >= 0; i-- {
		if !es[i].IsDir() {
			continue
		}
		v := backupView{Name: es[i].Name()}
		fs, _ := os.ReadDir(filepath.Join(x.backups, es[i].Name()))
		for _, f := range fs {
			v.Files = append(v.Files, f.Name())
			if inf, err := f.Info(); err == nil {
				v.Bytes += inf.Size()
			}
		}
		out = append(out, v)
	}
	return out
}

// due: one backup per night after 03:00 local time (or at start if none today).
func (x *V27) backupDue() bool {
	now := x.now()
	if now.Hour() < 3 {
		return false
	}
	today := now.Format("2006-01-02")
	for _, b := range x.Backups() {
		if strings.HasPrefix(b.Name, today) {
			return false
		}
	}
	return true
}

func (x *V27) Run(ctx context.Context) {
	x.v.s.applyV27(x.v.s.settings.Get())
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	n := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n++
			x.v.s.checkServer()
			x.RunOnce(ctx, false)
			if n%20 == 1 && !x.v.s.settings.Get().V27.BackupOff && x.backupDue() {
				if _, _, err := x.BackupNow(); err != nil {
					log.Printf("backup: failed: %v", err)
				}
			}
		}
	}
}

// pushWebhook is called by Alerts.Raise (only when the webhook is on).
func (x *V27) pushWebhook(al Alert) {
	c := x.v.s.settings.Get().V27
	if webhookReady(c) {
		go x.hook.Send(c, al.Key, al.Title, al.Message, false)
	}
}

// ---- API ----

func maskV27(c V27Config) V27Config {
	c.WebhookURL, c.WebhookToken = mask(c.WebhookURL), mask(c.WebhookToken)
	return c
}

func (x *V27) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/v27/config", x.serveConfig)
	mux.HandleFunc("/api/v27/sync", x.serveSync)
	mux.HandleFunc("/api/v27/backup", x.serveBackup)
	mux.HandleFunc("/api/v27/webhook/test", x.serveWebhookTest)
	mux.HandleFunc("/api/v27/devices/live", x.serveDevicesLive)
}

func (x *V27) serveConfig(w http.ResponseWriter, r *http.Request) {
	s := x.v.s
	if r.Method == http.MethodGet {
		st := s.settings.Get()
		writeJSON(w, map[string]any{"config": maskV27(st.V27), "default_lists": defaultBlocklists,
			"block_size": s.bl.Size(), "block_updated": s.bl.Updated.Load(), "block_updating": s.bl.Updating.Load(),
			"blocked": s.stats.Blocked.Load(), "flag_blocking": s.bl.Enabled, "device_feature": st.Feature("device_volume")})
		return
	}
	if !postOnly(w, r) {
		return
	}
	var in V27Config
	if err := readJSON(r, &in); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	next, diff, err := s.settings.Update(x.v.by(r), "v2.7 settings saved", func(st *Settings) error {
		old := st.V27
		if in.WebhookURL == mask(old.WebhookURL) {
			in.WebhookURL = old.WebhookURL
		}
		if in.WebhookToken == mask(old.WebhookToken) {
			in.WebhookToken = old.WebhookToken
		}
		in.SyncStamp, in.SyncHash, in.SyncFrom = old.SyncStamp, old.SyncHash, old.SyncFrom
		if !st.Feature("device_volume") {
			in.DeviceRules = old.DeviceRules // approval switch off: rules can't be edited
		}
		if err := validateV27(&in); err != nil {
			return err
		}
		st.V27 = in
		return nil
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	_ = x.v.applyLive(next)
	writeJSON(w, map[string]any{"ok": true, "diff": diff, "config": maskV27(next.V27)})
}

func (x *V27) serveSync(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		notes := x.RunOnce(r.Context(), true)
		writeJSON(w, map[string]any{"ok": true, "notes": notes})
		return
	}
	st := x.v.s.settings.Get()
	x.mu.Lock()
	lg := append([]syncEvent(nil), x.syncLog...)
	x.mu.Unlock()
	writeJSON(w, map[string]any{"stamp": st.V27.SyncStamp, "from": st.V27.SyncFrom, "auto": !st.V27.SyncOff,
		"last_run": x.lastRun.Load(), "log": lg, "peers": len(st.Peers)})
}

func (x *V27) serveBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		name, n, err := x.BackupNow()
		if err != nil {
			jsonErr(w, 500, "backup failed")
			return
		}
		writeJSON(w, map[string]any{"ok": true, "name": name, "files": n})
		return
	}
	writeJSON(w, map[string]any{"backups": x.Backups(), "keep": backupKeep, "dir": x.backups})
}

func (x *V27) serveWebhookTest(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	if err := x.hook.Send(x.v.s.settings.Get().V27, "test", "GoProxy test", "Test alert from GoProxy "+Version, true); err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (x *V27) serveDevicesLive(w http.ResponseWriter, r *http.Request) {
	s := x.v.s
	if !s.settings.Get().Feature("device_volume") || s.devvol == nil {
		writeJSON(w, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, map[string]any{"enabled": true, "devices": s.deviceVolume(), "at": time.Now().Unix()})
}

// peer side: GET /api/peer/sync (LAN + peer token, checked by servePeerAPI).
func (s *DNSServer) peerSyncState() syncState {
	if s.v27 != nil {
		return s.v27.stampLocal()
	}
	st := s.settings.Get()
	return syncState{Stamp: st.V27.SyncStamp, Data: syncOf(st), Name: hostName()}
}
