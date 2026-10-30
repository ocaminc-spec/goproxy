// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.5.1 DNS Servers: a user-managed, ordered list of upstreams (DoH, DoT or plain UDP) with
// add / remove / enable / disable / reorder from the dashboard. Saved in goproxy-settings.json
// ("dns_servers"), part of the settings backup, recorded in Config history, applied live.
// Priority drives the race: the top N enabled servers (N = "Upstreams raced first", default 2)
// are asked at once; encrypted servers below them join after the hedge delay; unencrypted ones
// below them are only fallbacks (see Resolver.split).

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/miekg/dns"
)

// UpstreamEntry is one entry of the DNS Servers list. Its position in the list is its priority.
type UpstreamEntry struct {
	Name      string `json:"name"`
	Addr      string `json:"addr"`  // DoH: https URL · DoT: tls://host:port · UDP: ip:port
	Proto     string `json:"proto"` // doh | dot | udp
	Enabled   bool   `json:"enabled"`
	Bootstrap string `json:"bootstrap,omitempty"` // IPs for a host name (DoH/DoT), comma separated
	Preset    string `json:"preset,omitempty"`    // id of the preset it came from (informational)
}

const maxDNSServers = 16

// dnsPreset is a known server offered in the "Add" menu.
type dnsPreset struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Proto     string `json:"proto"`
	Addr      string `json:"addr"`
	Encrypted bool   `json:"encrypted"`
	Note      string `json:"note,omitempty"`
}

// UltraDNS Public (formerly Verisign Public DNS; Neustar → Vercara → DigiCert) has no
// DNS-over-HTTPS or DNS-over-TLS service: port 853 is closed, there is no TLS on 443 and
// dns.ultradns.com has no address (checked 2026-10-18). So it is plain UDP/TCP only and is
// labelled unencrypted.
const ultraNote = "Unencrypted: UltraDNS Public offers no DoH or DoT, so your ISP can see and change these lookups. Kept at the bottom it is only a fallback."

var dnsPresets = []dnsPreset{
	{ID: "cloudflare-1", Name: "Cloudflare", Proto: "doh", Addr: cfA, Encrypted: true},
	{ID: "cloudflare-2", Name: "Cloudflare (2)", Proto: "doh", Addr: cfB, Encrypted: true},
	{ID: "quad9-1", Name: "Quad9", Proto: "doh", Addr: q9A, Encrypted: true},
	{ID: "quad9-2", Name: "Quad9 (2)", Proto: "doh", Addr: q9B, Encrypted: true},
	{ID: "quad9-ecs", Name: "Quad9 with ECS", Proto: "doh", Addr: quad9ECS, Encrypted: true, Note: "Sends part of your public IP subnet to websites' DNS (better CDN choice, a little less private)."},
	{ID: "google", Name: "Google", Proto: "doh", Addr: googleA, Encrypted: true},
	{ID: "adguard", Name: "AdGuard (unfiltered)", Proto: "doh", Addr: "https://unfiltered.adguard-dns.com/dns-query", Encrypted: true},
	{ID: "cloudflare-dot", Name: "Cloudflare DoT", Proto: "dot", Addr: "tls://cloudflare-dns.com:853", Encrypted: true},
	{ID: "quad9-dot", Name: "Quad9 DoT", Proto: "dot", Addr: "tls://dns.quad9.net:853", Encrypted: true},
	{ID: "google-dot", Name: "Google DoT", Proto: "dot", Addr: "tls://dns.google:853", Encrypted: true},
	{ID: "google-doh-name", Name: "Google (dns.google)", Proto: "doh", Addr: "https://dns.google/dns-query", Encrypted: true},
	{ID: "cloudflare-dot-ip", Name: "Cloudflare DoT (1.1.1.1)", Proto: "dot", Addr: "tls://1.1.1.1:853", Encrypted: true},
	{ID: "google-dot-ip", Name: "Google DoT (8.8.8.8)", Proto: "dot", Addr: "tls://8.8.8.8:853", Encrypted: true},
	{ID: "ultradns-1", Name: "UltraDNS Public", Proto: "udp", Addr: "64.6.64.6:53", Note: ultraNote},
	{ID: "ultradns-2", Name: "UltraDNS Public (2)", Proto: "udp", Addr: "64.6.65.6:53", Note: ultraNote},
}

func presetByID(id string) (dnsPreset, bool) {
	for _, p := range dnsPresets {
		if p.ID == id {
			return p, true
		}
	}
	return dnsPreset{}, false
}

// selfDNSPort is GoProxy's own DNS port: a UDP server on this machine with that port would
// send GoProxy's lookups back to itself.
var selfDNSPort = "53"

// normalizeDNSServer validates one entry and returns it in canonical form.
func normalizeDNSServer(d UpstreamEntry) (UpstreamEntry, error) {
	d.Name = strings.TrimSpace(d.Name)
	d.Addr = strings.TrimSpace(d.Addr)
	d.Proto = strings.ToLower(strings.TrimSpace(d.Proto))
	d.Bootstrap = strings.Join(splitList(d.Bootstrap), ",")
	if d.Addr == "" {
		return d, errors.New("address is empty")
	}
	if d.Proto == "" { // infer from the address
		switch {
		case strings.HasPrefix(strings.ToLower(d.Addr), "https://"):
			d.Proto = "doh"
		case strings.HasPrefix(strings.ToLower(d.Addr), "tls://"):
			d.Proto = "dot"
		default:
			d.Proto = "udp"
		}
	}
	for _, ip := range splitList(d.Bootstrap) {
		if net.ParseIP(ip) == nil {
			return d, fmt.Errorf("%s: bootstrap %q is not an IP address", d.Addr, ip)
		}
	}
	if len(splitList(d.Bootstrap)) > 4 {
		return d, fmt.Errorf("%s: at most 4 bootstrap IPs", d.Addr)
	}
	needBoot := func(host string) error {
		if net.ParseIP(host) == nil && d.Bootstrap == "" && !hasBootstrap(host) {
			return fmt.Errorf("%s uses a name: give its IP address(es) as bootstrap, so GoProxy never needs DNS to reach its own servers", host)
		}
		return nil
	}
	switch d.Proto {
	case "doh":
		u, err := url.Parse(d.Addr)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
			return d, fmt.Errorf("%q: a DoH address must be a URL like https://1.1.1.1/dns-query", d.Addr)
		}
		if p := u.Port(); p != "" {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return d, fmt.Errorf("%q: bad port", d.Addr)
			}
		}
		if u.Path == "" {
			u.Path = "/dns-query"
		}
		if err := needBoot(u.Hostname()); err != nil {
			return d, err
		}
		d.Addr = u.String()
	case "dot":
		a := d.Addr
		if i := strings.Index(a, "://"); i >= 0 {
			if !strings.EqualFold(a[:i], "tls") {
				return d, fmt.Errorf("%q: a DoT address looks like tls://dns.quad9.net:853 or 9.9.9.9", d.Addr)
			}
			a = a[i+3:]
		}
		host, port, err := splitHostPortDefault(a, "853")
		if err != nil || !validHost(host) {
			return d, fmt.Errorf("%q: a DoT address looks like tls://dns.quad9.net:853 or 9.9.9.9", d.Addr)
		}
		if err := needBoot(host); err != nil {
			return d, err
		}
		d.Addr = "tls://" + net.JoinHostPort(strings.ToLower(host), port)
	case "udp":
		host, port, err := splitHostPortDefault(strings.TrimPrefix(d.Addr, "udp://"), "53")
		ip := net.ParseIP(host)
		if err != nil || ip == nil {
			return d, fmt.Errorf("%q: a plain DNS (UDP) address must be an IP address like 64.6.64.6 or 64.6.64.6:53", d.Addr)
		}
		if ip.IsUnspecified() || ip.IsMulticast() {
			return d, fmt.Errorf("%q is not a usable DNS server address", d.Addr)
		}
		if ip.IsLoopback() && port == selfDNSPort {
			return d, fmt.Errorf("%q is GoProxy itself: it would ask itself in a loop", d.Addr)
		}
		d.Addr = net.JoinHostPort(ip.String(), port)
		d.Bootstrap = ""
	default:
		return d, fmt.Errorf("protocol %q: use DoH, DoT or UDP", d.Proto)
	}
	if d.Name == "" {
		d.Name = defaultServerName(d)
	}
	if len([]rune(d.Name)) > 48 {
		return d, fmt.Errorf("name %q is too long (48 characters at most)", d.Name)
	}
	for _, r := range d.Name {
		if !unicode.IsPrint(r) {
			return d, fmt.Errorf("name %q contains a control character", d.Name)
		}
	}
	if d.Preset != "" {
		if _, ok := presetByID(d.Preset); !ok {
			d.Preset = ""
		}
	}
	return d, nil
}

func splitHostPortDefault(a, def string) (string, string, error) {
	if a == "" {
		return "", "", errors.New("empty")
	}
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		// bare host or bare IPv6 ("2620:74:1b::1:1" / "[2620:74:1b::1:1]")
		host, port = strings.TrimSuffix(strings.TrimPrefix(a, "["), "]"), def
		if strings.ContainsAny(host, "/[]") {
			return "", "", err
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", "", errors.New("bad port")
	}
	return host, port, nil
}

func validHost(h string) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if h == "" || len(h) > 253 {
		return false
	}
	_, ok := dns.IsDomainName(h)
	return ok && !strings.ContainsAny(h, " /\\@")
}

func defaultServerName(d UpstreamEntry) string {
	for _, p := range dnsPresets {
		if p.Addr == d.Addr && p.Proto == d.Proto {
			return p.Name
		}
	}
	if pr := providerOf(d.Addr); pr != "Other" {
		return pr
	}
	if u, err := url.Parse(d.Addr); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return d.Addr
}

// normalizeDNSServers validates the whole list: 1–16 entries, no duplicates, at least one enabled.
func normalizeDNSServers(in []UpstreamEntry) ([]UpstreamEntry, error) {
	if len(in) == 0 {
		return nil, errors.New("the list is empty: add at least one DNS server")
	}
	if len(in) > maxDNSServers {
		return nil, fmt.Errorf("at most %d DNS servers", maxDNSServers)
	}
	out := make([]UpstreamEntry, 0, len(in))
	seen := map[string]bool{}
	enabled := 0
	for i, d := range in {
		n, err := normalizeDNSServer(d)
		if err != nil {
			return nil, fmt.Errorf("server %d: %w", i+1, err)
		}
		k := n.Proto + " " + strings.ToLower(n.Addr)
		if seen[k] {
			return nil, fmt.Errorf("server %d: %s is listed twice", i+1, n.Addr)
		}
		seen[k] = true
		if n.Enabled {
			enabled++
		}
		out = append(out, n)
	}
	if enabled == 0 {
		return nil, errors.New("keep at least one DNS server enabled")
	}
	return out, nil
}

// interleaveProviders reorders so neighbours come from different providers where possible
// (the top 2 that are raced first should not both be Cloudflare).
func interleaveProviders(list []string) []string {
	var order []string
	byProv := map[string][]string{}
	for _, u := range list {
		p := providerOf(u)
		if p == "Other" {
			p = "other:" + u
		}
		if _, ok := byProv[p]; !ok {
			order = append(order, p)
		}
		byProv[p] = append(byProv[p], u)
	}
	var out []string
	for len(out) < len(list) {
		for _, p := range order {
			if l := byProv[p]; len(l) > 0 {
				out = append(out, l[0])
				byProv[p] = l[1:]
			}
		}
	}
	return out
}

func serverFromString(u string) UpstreamEntry {
	d := UpstreamEntry{Addr: u, Enabled: true}
	switch {
	case strings.HasPrefix(u, "https://"):
		d.Proto = "doh"
	case strings.HasPrefix(u, "tls://"):
		d.Proto = "dot"
	default:
		d.Proto = "udp"
	}
	if n, err := normalizeDNSServer(d); err == nil {
		return n
	}
	d.Name = u
	return d
}

// defaultDNSServers: the upstreams the older settings describe (default Cloudflare + Quad9,
// a preset, Quad9 ECS, the extra upstream), interleaved by provider, then UltraDNS Public
// (both addresses) enabled at the lowest priority.
func defaultDNSServers(flagVal string, st Settings) []UpstreamEntry {
	if strings.TrimSpace(flagVal) == "" {
		flagVal = defaultDoH
	}
	var out []UpstreamEntry
	seen := map[string]bool{}
	for _, u := range interleaveProviders(upstreamList(flagVal, st, false)) {
		d := serverFromString(u)
		if e := strings.TrimSpace(st.ExtraUpstream); e != "" && u == e {
			d.Bootstrap = strings.Join(splitList(st.ExtraBoot), ",")
		}
		if !seen[d.Addr] {
			seen[d.Addr] = true
			out = append(out, d)
		}
	}
	// v2.6.0 defaults: Cloudflare + Google over DoH and DoT, all raced in parallel; plain UDP
	// only through -fallback (8.8.8.8 / 1.1.1.1) when encryption fails and Fall back is on.
	defaults := flagVal == defaultDoH && strings.TrimSpace(st.UpstreamSet) == "" && !st.Quad9ECS && strings.TrimSpace(st.ExtraUpstream) == ""
	extra := []string{"ultradns-1", "ultradns-2"}
	if defaults {
		extra = []string{"cloudflare-dot-ip", "google-dot-ip"}
	}
	for _, id := range extra {
		p, _ := presetByID(id)
		if !seen[p.Addr] {
			out = append(out, UpstreamEntry{Name: p.Name, Addr: p.Addr, Proto: p.Proto, Enabled: true, Preset: p.ID})
		}
	}
	return out
}

// effectiveServers returns the list GoProxy should run with, where it comes from
// ("flag" = -upstreams on the command line, "custom" = the saved DNS Servers list,
// "default") and a warning when a saved list was unusable.
func effectiveServers(flagVal string, st Settings, explicit bool) ([]UpstreamEntry, string, string) {
	if explicit {
		var out []UpstreamEntry
		for _, u := range splitList(flagVal) {
			out = append(out, serverFromString(u))
		}
		return out, "flag", ""
	}
	if len(st.DNSServers) > 0 {
		l, err := normalizeDNSServers(st.DNSServers)
		if err == nil {
			return l, "custom", ""
		}
		return defaultDNSServers(flagVal, st), "default", "the saved DNS Servers list is not usable (" + err.Error() + "); using the defaults"
	}
	return defaultDNSServers(flagVal, st), "default", ""
}

func serverKey(proto, addr string) string { return strings.ToLower(proto + " " + addr) }

// newUpstreamFor builds the Upstream for one entry. DoH entries share tr.
func newUpstreamFor(d UpstreamEntry, tr *http.Transport) *Upstream {
	switch d.Proto {
	case "doh":
		if ips := splitList(d.Bootstrap); len(ips) > 0 {
			if u, err := url.Parse(d.Addr); err == nil {
				setBootstrap(u.Hostname(), ips)
			}
		}
		up := NewUpstream(d.Addr, tr)
		up.SetLabel(d.Name)
		return up
	case "dot":
		hp := strings.TrimPrefix(d.Addr, "tls://")
		host, _, _ := net.SplitHostPort(hp)
		if ips := splitList(d.Bootstrap); len(ips) > 0 {
			setBootstrap(host, ips)
		}
		up := &Upstream{Name: d.Addr, URL: d.Addr, dot: newDoTClient(hp, host)}
		up.SetLabel(d.Name)
		return up
	}
	up := NewUpstream(d.Addr, nil)
	up.SetLabel(d.Name)
	return up
}

// buildUpstreams creates the live list for the enabled entries, reusing existing Upstream
// objects (and their stats and connections) for servers that stay.
func buildUpstreams(list []UpstreamEntry, tr *http.Transport, old []*Upstream) (ups, removed []*Upstream) {
	have := map[string]*Upstream{}
	for _, u := range old {
		have[serverKey(u.Proto(), u.URL)] = u
	}
	used := map[*Upstream]bool{}
	for _, d := range list {
		if !d.Enabled {
			continue
		}
		proto := map[string]string{"doh": "DoH", "dot": "DoT", "udp": "UDP"}[d.Proto]
		addr := d.Addr
		if d.Proto == "udp" {
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr = net.JoinHostPort(addr, "53")
			}
		}
		if u, ok := have[serverKey(proto, addr)]; ok && !used[u] {
			u.SetLabel(d.Name)
			used[u] = true
			ups = append(ups, u)
			continue
		}
		u := newUpstreamFor(d, tr)
		used[u] = true
		ups = append(ups, u)
	}
	for _, u := range old {
		if !used[u] {
			removed = append(removed, u)
		}
	}
	return ups, removed
}

func serversSig(list []UpstreamEntry, src string) string {
	var b strings.Builder
	b.WriteString(src)
	for _, d := range list {
		fmt.Fprintf(&b, "|%s %s %v %s %s", d.Proto, d.Addr, d.Enabled, d.Bootstrap, d.Name)
	}
	return b.String()
}

// ---------------- DoT client ----------------

// dotClient keeps a few TLS connections open and reuses them (one query at a time each).
type dotClient struct {
	addr, host string
	cfg        *tls.Config
	dial       func(ctx context.Context, network, addr string) (net.Conn, error)
	mu         sync.Mutex
	idle       []dotConn
}

type dotConn struct {
	c    *dns.Conn
	used time.Time
}

const dotIdle = 20 * time.Second

func newDoTClient(addr, host string) *dotClient {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, ClientSessionCache: tls.NewLRUClientSessionCache(8)}
	td := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}, Config: cfg}
	return &dotClient{addr: addr, host: host, cfg: cfg, dial: bootstrapDial(td.DialContext)}
}

func (d *dotClient) get(ctx context.Context) (*dns.Conn, bool, error) {
	d.mu.Lock()
	for len(d.idle) > 0 {
		x := d.idle[len(d.idle)-1]
		d.idle = d.idle[:len(d.idle)-1]
		if time.Since(x.used) < dotIdle {
			d.mu.Unlock()
			return x.c, true, nil
		}
		_ = x.c.Close()
	}
	d.mu.Unlock()
	c, err := d.dial(ctx, "tcp", d.addr)
	if err != nil {
		return nil, false, err
	}
	return &dns.Conn{Conn: c}, false, nil
}

func (d *dotClient) put(c *dns.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.idle) >= 4 {
		_ = c.Close()
		return
	}
	d.idle = append(d.idle, dotConn{c, time.Now()})
}

func (d *dotClient) closeIdle() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, x := range d.idle {
		_ = x.c.Close()
	}
	d.idle = nil
}

func (d *dotClient) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	for attempt := 0; attempt < 2; attempt++ {
		c, reused, err := d.get(ctx)
		if err != nil {
			return nil, err
		}
		dl, ok := ctx.Deadline()
		if !ok {
			dl = time.Now().Add(4 * time.Second)
		}
		_ = c.SetDeadline(dl)
		stop := context.AfterFunc(ctx, func() { _ = c.Close() })
		var r *dns.Msg
		err = c.WriteMsg(q)
		if err == nil {
			r, err = c.ReadMsg()
		}
		if !stop() { // the race was decided or timed out: the conn is closed
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if err == nil && r != nil && r.Id == q.Id {
			_ = c.SetDeadline(time.Time{})
			d.put(c)
			return r, nil
		}
		_ = c.Close()
		if err == nil {
			err = errors.New("dns: mismatched reply id")
		}
		if !reused || ctx.Err() != nil { // a pooled conn may have been closed by the server: retry once
			return nil, err
		}
	}
	return nil, errors.New("dot: no connection")
}

// ---------------- live apply ----------------

// applyUpstreams rebuilds the resolver's list from the settings when it changed.
func (v *V24) applyUpstreams(st Settings) {
	if v.s == nil || v.s.res == nil || !v.manageUpstreams {
		return
	}
	list, src, warn := effectiveServers(v.upFlag, st, v.explicit["upstreams"])
	v.upMu.Lock()
	defer v.upMu.Unlock()
	v.upWarn = warn
	sig := serversSig(list, src)
	if sig == v.upSig {
		return
	}
	res := v.s.res
	ups, removed := buildUpstreams(list, res.Tr, res.Ups())
	if len(ups) == 0 { // cannot happen after validation; never leave DNS without upstreams
		list, src = defaultDNSServers(v.upFlag, st), "default"
		ups, removed = buildUpstreams(list, res.Tr, res.Ups())
	}
	res.Priority.Store(src != "flag")
	res.SetUpstreams(ups)
	v.upSig = sig
	for _, u := range removed {
		u.closeIdle()
	}
	var names []string
	for _, u := range ups {
		names = append(names, u.Label()+" "+u.Proto()+" "+u.URL)
	}
	if warn != "" {
		log.Printf("dns servers: %s", warn)
	}
	log.Printf("dns servers (%s, priority order): %s", src, strings.Join(names, " · "))
}

// ---------------- HTTP ----------------

type dnsServerView struct {
	UpstreamEntry
	Order     int     `json:"order"`
	Encrypted bool    `json:"encrypted"`
	Running   bool    `json:"running"`
	Role      string  `json:"role"` // raced first | hedge | fallback | disabled
	Health    string  `json:"health,omitempty"`
	P95Ms     float64 `json:"p95_ms,omitempty"`
	Queries   int64   `json:"queries,omitempty"`
	Wins      int64   `json:"wins,omitempty"`
}

func (v *V24) raceFirst() int {
	if v.s != nil && v.s.res != nil && v.s.res.First > 0 {
		return v.s.res.First
	}
	return 2
}

func (v *V24) dnsServersView() map[string]any {
	st := v.s.settings.Get()
	list, src, warn := effectiveServers(v.upFlag, st, v.explicit["upstreams"])
	run := map[string]*Upstream{}
	if v.s.res != nil {
		for _, u := range v.s.res.Ups() {
			run[serverKey(u.Proto(), u.URL)] = u
		}
	}
	first := v.raceFirst()
	views := make([]dnsServerView, 0, len(list))
	n := 0
	for i, d := range list {
		x := dnsServerView{UpstreamEntry: d, Order: i + 1, Encrypted: d.Proto != "udp", Role: "disabled"}
		if d.Enabled {
			switch {
			case n < first:
				x.Role = "raced first"
			case x.Encrypted:
				x.Role = "joins if slow"
			default:
				x.Role = "fallback only"
			}
			if src == "flag" {
				x.Role = "command line"
			}
			n++
		}
		proto := map[string]string{"doh": "DoH", "dot": "DoT", "udp": "UDP"}[d.Proto]
		if u, ok := run[serverKey(proto, d.Addr)]; ok {
			x.Running, x.Health, x.P95Ms, x.Queries, x.Wins = true, u.health(), float64(u.P95())/1e6, u.Queries.Load(), u.Wins.Load()
		}
		views = append(views, x)
	}
	v.upMu.Lock()
	if warn == "" {
		warn = v.upWarn
	}
	v.upMu.Unlock()
	return map[string]any{"servers": views, "source": src, "custom": len(st.DNSServers) > 0, "warning": warn, "presets": dnsPresets,
		"race_first": first, "flag_set": v.explicit["upstreams"], "max": maxDNSServers, "defaults": defaultDNSServers(v.upFlag, st)}
}

func (v *V24) serveDNSServers(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, v.dnsServersView())
		return
	}
	if !postOnly(w, r) {
		return
	}
	var body struct {
		Servers []UpstreamEntry `json:"servers"`
	}
	if err := readJSON(r, &body); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	norm, err := normalizeDNSServers(body.Servers)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	next, diff, err := v.s.settings.Update(v.by(r), "DNS servers", func(s *Settings) error {
		s.DNSServers = norm
		return validateSettings(s)
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	_ = v.applyLive(next)
	resp := v.dnsServersView()
	resp["ok"], resp["diff"] = true, diff
	writeJSON(w, resp)
}

func (v *V24) serveDNSServersReset(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	next, diff, err := v.s.settings.Update(v.by(r), "DNS servers reset to defaults", func(s *Settings) error {
		s.DNSServers = nil
		return nil
	})
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	_ = v.applyLive(next)
	resp := v.dnsServersView()
	resp["ok"], resp["diff"] = true, diff
	writeJSON(w, resp)
}

// serveDNSServerTest asks one server (saved or not) for example.com on its own connection.
func (v *V24) serveDNSServerTest(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	var d UpstreamEntry
	if err := readJSON(r, &d); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	n, err := normalizeDNSServer(d)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	var tr *http.Transport
	if n.Proto == "doh" {
		tr = newDoHTransport()
	}
	up := newUpstreamFor(n, tr)
	defer up.closeIdle()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(1232, false)
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()
	t0 := time.Now()
	resp, err := up.Exchange(ctx, q)
	ms := float64(time.Since(t0).Microseconds()) / 1000
	out := map[string]any{"server": n, "ms": ms, "ok": err == nil && resp != nil}
	if err != nil {
		out["error"] = shortErr(err)
	} else if resp != nil {
		var ans []string
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				ans = append(ans, a.A.String())
			}
		}
		out["rcode"], out["answers"] = dns.RcodeToString[resp.Rcode], ans
	}
	writeJSON(w, out)
}
