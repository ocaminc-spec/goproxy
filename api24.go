// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// V24 bundles the v2.4 features for the HTTP API.
type V24 struct {
	app      *App
	s        *DNSServer
	ipw      *IPWatch
	out      *Outages
	wd       *Watchdog
	audit    *Audit
	ntfy     *Ntfy
	kiosk    *Kiosk
	auth     *Auth
	explicit map[string]bool // flags given on the command line
	started  Settings        // settings the engine was built with (restart detection)
	upFlag   string          // the -upstreams value (default list unless given)

	// v2.5.1 DNS Servers (live upstream list)
	manageUpstreams bool // main sets it: settings changes rebuild the resolver's list
	upMu            sync.Mutex
	upSig, upWarn   string
}

func (v *V24) by(r *http.Request) string {
	ip := remoteIP(r)
	if v.auth != nil {
		if u := v.auth.Session(r); u != "" {
			return ip + " (" + u + ")"
		}
	}
	return ip
}

func readJSON(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(v)
}

func postOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "POST only")
		return false
	}
	return true
}

func (v *V24) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/settings", v.serveSettings)
	mux.HandleFunc("/api/settings/history", func(w http.ResponseWriter, r *http.Request) {
		h := v.s.settings.History()
		for i := range h { // never expose the token, even in old snapshots
			h[i].Before.NtfyToken = mask(h[i].Before.NtfyToken)
			h[i].Before.PeerToken = mask(h[i].Before.PeerToken)
			h[i].Before.V27 = maskV27(h[i].Before.V27)
		}
		writeJSON(w, h)
	})
	mux.HandleFunc("/api/settings/revert", v.serveRevert)
	mux.HandleFunc("/api/audit", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, v.audit.Last(300)) })
	mux.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"active": v.s.alerts.Active(), "history": v.s.alerts.History()})
	})
	mux.HandleFunc("/api/alerts/dismiss", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var b struct{ Key string }
		if readJSON(r, &b) != nil || b.Key == "" {
			jsonErr(w, 400, "key required")
			return
		}
		v.s.alerts.Clear(b.Key, "")
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/ipwatch", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, v.ipw.View()) })
	mux.HandleFunc("/api/ipwatch/accept", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		ip, err := v.ipw.Accept(v.by(r))
		if err != nil {
			jsonErr(w, 409, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true, "expected_ip": ip})
	})
	mux.HandleFunc("/api/ntfy/test", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		st := v.s.settings.Get()
		if !st.ntfyReady() {
			jsonErr(w, 409, "ntfy is off: switch it on and set a topic first")
			return
		}
		auditf(v.by(r), "ntfy test", "")
		ok := v.ntfy.send(st, "test", "GoProxy test alert", "This is a test from GoProxy DNS v"+Version+". Alerts work.", false, true)
		writeJSON(w, map[string]any{"ok": ok})
	})
	mux.HandleFunc("/api/devices", v.s.devices.serveList)
	mux.HandleFunc("/api/ads", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, v.s.adsView()) })
	mux.HandleFunc("/api/ads/client", v.serveAdsClient)
	mux.HandleFunc("/api/why", v.s.serveWhy)
	mux.HandleFunc("/api/settings/export", v.serveExport)
	mux.HandleFunc("/api/settings/import", v.serveImport)
	mux.HandleFunc("/api/dns-servers", v.serveDNSServers)
	mux.HandleFunc("/api/dns-servers/reset", v.serveDNSServersReset)
	mux.HandleFunc("/api/dns-servers/test", v.serveDNSServerTest)
	mux.HandleFunc("/api/devices/edit", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var e deviceEdit
		if err := readJSON(r, &e); err != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		if err := v.s.devices.Edit(e); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		b, _ := json.Marshal(e)
		auditf(v.by(r), "device edited", string(b))
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/groups", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var e groupEdit
		if err := readJSON(r, &e); err != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		if err := v.s.devices.EditGroup(e); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		auditf(v.by(r), "group "+e.Action, e.Name+" "+e.To)
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/outages", v.out.serveJSON)
	mux.HandleFunc("/api/outages.csv", v.out.serveCSV)
	mux.HandleFunc("/api/canary", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			v.s.canary.RunOnce()
		}
		writeJSON(w, v.s.canary.View())
	})
	mux.HandleFunc("/api/flight", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			name := v.s.flight.Dump("saved from the dashboard by "+v.by(r), true)
			writeJSON(w, map[string]any{"ok": name != "", "file": filepath.Base(name)})
			return
		}
		writeJSON(w, map[string]any{"enabled": v.s.settings.Get().Feature("flight_rec"), "files": v.s.flight.Files(), "folder": v.s.flight.dir})
	})
	mux.HandleFunc("/api/watchdog", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, v.wd.View()) })
	mux.HandleFunc("/api/restart", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		if !trustedClient(r) {
			jsonErr(w, 403, "restart is only allowed from the home network")
			return
		}
		if err := v.app.upd.Restart(v.by(r)); err != nil {
			jsonErr(w, 409, err.Error())
			return
		}
		writeJSON(w, map[string]any{"ok": true})
	})
	// loopback-only status for the tray process (no login: it carries no private data)
	mux.HandleFunc("/api/tray/status", func(w http.ResponseWriter, r *http.Request) {
		if !isLoopback(r) {
			jsonErr(w, 403, "this PC only")
			return
		}
		writeJSON(w, map[string]any{"version": Version, "service": serviceMode, "dns_ok": v.wd.View().Fails == 0 && v.s.canary.View().OK, "alerts": v.s.alerts.Active()})
	})
	v.kiosk.Register(mux)
}

// ---------------- settings ----------------

func maskedSettings(st Settings) Settings {
	st.NtfyToken = mask(st.NtfyToken)
	st.PeerToken = mask(st.PeerToken)
	st.V27 = maskV27(st.V27)
	return st
}

var topicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func validateSettings(st *Settings) error {
	if err := validateKuma(strings.TrimSpace(st.KumaURL), strings.TrimSpace(st.KumaSlug)); err != nil {
		return err
	}
	if len(splitList(st.WarmupList)) > 500 {
		return fmt.Errorf("preload names: at most 500")
	}
	for k := range st.Features {
		if _, ok := featureDefaults[k]; !ok {
			return fmt.Errorf("unknown feature %q", k)
		}
	}
	if st.ExpectedIP != "" {
		ip := net.ParseIP(st.ExpectedIP)
		if ip == nil || ip.To4() == nil || !ip.IsPrivate() {
			return fmt.Errorf("expected IP must be a home-network IPv4 address like 192.168.1.127")
		}
	}
	if st.NtfyServer != "" {
		u, err := url.Parse(st.NtfyServer)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("ntfy server must be a URL like https://ntfy.sh")
		}
	}
	if st.NtfyTopic != "" && !topicRE.MatchString(st.NtfyTopic) {
		return fmt.Errorf("ntfy topic: letters, digits, - and _ only (up to 64)")
	}
	if st.NtfyOn && st.NtfyTopic == "" {
		return fmt.Errorf("set an ntfy topic before switching ntfy on")
	}
	if _, err := parseLocalNames(st.LocalNames); err != nil {
		return err
	}
	if set := splitList(st.UpstreamSet); len(set) > 0 {
		if len(set) > 6 {
			return fmt.Errorf("at most 6 upstreams")
		}
		for _, e := range set {
			u, err := url.Parse(e)
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("upstream %q must be a DoH URL like https://1.1.1.1/dns-query", e)
			}
			if net.ParseIP(u.Hostname()) == nil && !hasBootstrap(u.Hostname()) {
				return fmt.Errorf("upstream %q: use an IP-address URL (GoProxy must never need DNS to reach its upstreams)", e)
			}
		}
	}
	if e := strings.TrimSpace(st.ExtraUpstream); e != "" {
		u, err := url.Parse(e)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("extra upstream must be a DoH URL like https://dns.example/dns-query")
		}
		if net.ParseIP(u.Hostname()) == nil {
			ips := splitList(st.ExtraBoot)
			if len(ips) == 0 {
				return fmt.Errorf("extra upstream %s needs its IP address(es) (bootstrap), so GoProxy never has to look itself up", u.Hostname())
			}
			for _, ip := range ips {
				if net.ParseIP(ip) == nil {
					return fmt.Errorf("bootstrap %q is not an IP address", ip)
				}
			}
		}
	}
	if len(st.DNSServers) > 0 {
		if _, err := normalizeDNSServers(st.DNSServers); err != nil {
			return fmt.Errorf("DNS servers: %w", err)
		}
	}
	if err := validateTune(&st.Tune); err != nil {
		return err
	}
	for _, c := range []struct {
		v, lo, hi int
		n         string
	}{{st.FlightMinutes, 1, 60, "flight recorder minutes"}, {st.AuditDays, 7, 3650, "audit log days"}, {st.OutageMonths, 1, 120, "outage log months"}, {st.CanaryMinutes, 1, 60, "self-test minutes"}} {
		if c.v != 0 && (c.v < c.lo || c.v > c.hi) {
			return fmt.Errorf("%s must be between %d and %d", c.n, c.lo, c.hi)
		}
	}
	return nil
}

// restartKeys: changes to these only take effect after a restart. Since v2.5.1 the upstream
// settings (DNS Servers, presets, Quad9 ECS, extra upstream) are applied live.
func restartNeeded(a, b Settings) bool {
	ja, _ := json.Marshal([]any{a.Tune})
	jb, _ := json.Marshal([]any{b.Tune})
	return string(ja) != string(jb)
}

type effectiveTune struct {
	Key      string `json:"key"`
	Flag     string `json:"flag"`
	Running  string `json:"running"`
	Default  string `json:"default"`
	Saved    string `json:"saved,omitempty"`
	Explicit bool   `json:"set_on_command_line"`
}

func (v *V24) effective() []effectiveTune {
	cur := v.s.settings.Get()
	var out []effectiveTune
	for _, tf := range tuneFlags {
		f := flag.Lookup(tf.Flag)
		if f == nil {
			continue
		}
		saved, _, _ := tf.value(&cur.Tune)
		out = append(out, effectiveTune{Key: tf.Key, Flag: tf.Flag, Running: f.Value.String(), Default: f.DefValue, Saved: saved, Explicit: v.explicit[tf.Flag]})
	}
	return out
}

func (v *V24) serveSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cur := v.s.settings.Get()
		var upNames []string
		for _, u := range v.s.res.Ups() {
			upNames = append(upNames, u.URL)
		}
		writeJSON(w, map[string]any{"settings": maskedSettings(cur), "features": featureDefaults, "tune": v.effective(),
			"restart_needed": restartNeeded(v.started, cur), "upstreams_running": upNames, "upstreams_flag_set": v.explicit["upstreams"],
			"quad9_ecs_url": quad9ECS, "data_dir": dataDir, "service": serviceMode})
		return
	}
	if !postOnly(w, r) {
		return
	}
	var patch map[string]json.RawMessage
	if err := readJSON(r, &patch); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	delete(patch, "blocking_paused")
	var applyErr error
	next, diff, err := v.s.settings.Update(v.by(r), "saved in the dashboard", func(s *Settings) error {
		var m map[string]json.RawMessage
		b, _ := json.Marshal(s)
		_ = json.Unmarshal(b, &m)
		oldToken := s.NtfyToken
		for k, raw := range patch {
			if string(raw) == "null" {
				delete(m, k)
			} else {
				m[k] = raw
			}
		}
		b, _ = json.Marshal(m)
		var n Settings
		if err := json.Unmarshal(b, &n); err != nil {
			return errors.New("bad value: " + err.Error())
		}
		if n.NtfyToken == mask(oldToken) && oldToken != "" {
			n.NtfyToken = oldToken
		}
		n.BlockingPaused = s.BlockingPaused
		n.PeerToken, n.Peers = s.PeerToken, s.Peers // own API: /api/peers/config
		n.V27 = s.V27                               // own API: /api/v27/config
		if err := validateSettings(&n); err != nil {
			return err
		}
		if err := validateAds(&n, v.s.protectedName); err != nil {
			return err
		}
		*s = n
		return nil
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	applyErr = v.applyLive(next)
	resp := map[string]any{"ok": true, "diff": diff, "restart_needed": restartNeeded(v.started, next), "settings": maskedSettings(next)}
	if applyErr != nil {
		resp["warning"] = applyErr.Error()
	}
	writeJSON(w, resp)
}

// applyLive pushes settings that take effect immediately.
func (v *V24) applyLive(st Settings) error {
	v.applyUpstreams(st)
	v.s.ads.Apply(st)
	v.s.flight.SetWindow(time.Duration(orInt(st.FlightMinutes, 10)) * time.Minute)
	v.s.flight.rec.Store(st.Feature("flight_rec"))
	if v.s.devvol != nil {
		v.s.devvol.On.Store(st.Feature("device_volume"))
	}
	go v.s.devices.CheckQuiet()
	if !st.Feature("canary") {
		v.s.alerts.Clear("canary", "")
	}
	v.s.applyV27(st)
	v.s.applyV28(st)
	return v.s.applyLocalNames(st)
}

func (v *V24) serveRevert(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	var b struct {
		ID int64 `json:"id"`
	}
	if err := readJSON(r, &b); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	diff, err := v.s.settings.Revert(b.ID, v.by(r))
	if err != nil {
		jsonErr(w, 404, err.Error())
		return
	}
	cur := v.s.settings.Get()
	_ = v.applyLive(cur)
	writeJSON(w, map[string]any{"ok": true, "diff": diff, "restart_needed": restartNeeded(v.started, cur)})
}

func randomTopic() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "goproxy-" + hex.EncodeToString(b)
}

var _ = os.Getpid
