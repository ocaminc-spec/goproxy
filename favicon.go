// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- host validation (SSRF guard) ----------

// normalizeHost returns a lowercase hostname (port stripped) or an error when the
// value is not a plain DNS hostname. IP literals are rejected outright.
func normalizeHost(h string) (string, error) {
	h = strings.ToLower(strings.TrimSpace(h))
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return "", errors.New("bad host")
	}
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return "", errors.New("ip literals not allowed")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", errors.New("hostname must be fully qualified")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", errors.New("bad label")
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", errors.New("bad character")
			}
		}
	}
	if tld := labels[len(labels)-1]; tld == "local" || tld == "localhost" || tld == "internal" || tld == "lan" || tld == "home" || tld == "arpa" {
		return "", errors.New("internal tld")
	}
	return h, nil
}

// iconAllow lists prefixes exempted from the guard (e.g. a fake-IP DNS sandbox),
// set via GOPROXY_ICON_ALLOW_CIDR="198.18.0.0/15". Empty by default.
var iconAllow []netip.Prefix

func init() {
	for _, c := range strings.Split(os.Getenv("GOPROXY_ICON_ALLOW_CIDR"), ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(c)); err == nil {
			iconAllow = append(iconAllow, p)
		}
	}
}

func blockedIP(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range iconAllow {
		if p.Contains(a) && !a.IsLoopback() {
			return false
		}
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var blockedPrefixes = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "2001:db8::/32"} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// safeDialControl runs after DNS resolution, so it also defeats DNS rebinding.
func safeDialControl(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	if blockedIP(ap.Addr()) {
		return fmt.Errorf("blocked address %s", ap.Addr())
	}
	return nil
}

// rootDomain: "a.b.example.com" -> "example.com" (handles common 2-level suffixes like co.uk).
func rootDomain(h string) string {
	l := strings.Split(h, ".")
	n := 2
	if len(l) >= 3 && len(l[len(l)-1]) == 2 && map[string]bool{"co": true, "com": true, "net": true, "org": true, "ac": true, "gov": true, "edu": true}[l[len(l)-2]] {
		n = 3
	}
	if len(l) <= n {
		return h
	}
	return strings.Join(l[len(l)-n:], ".")
}

// ---------- icon cache ----------

type icon struct {
	data  []byte
	ctype string
	exp   time.Time
	used  time.Time
}

type IconCache struct {
	mu       sync.Mutex
	m        map[string]*icon
	inflight map[string]chan struct{}
	max      int
	ttl      time.Duration
	client   *http.Client
	fetch    func(ctx context.Context, host string) ([]byte, string, error) // overridable in tests
	sem      chan struct{}
}

const maxIconBytes = 256 << 10

func NewIconCache(max int, ttl, timeout time.Duration) *IconCache {
	d := &net.Dialer{Timeout: timeout, Control: safeDialControl}
	tr := &http.Transport{DialContext: d.DialContext, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, MaxIdleConns: 32, IdleConnTimeout: 30 * time.Second}
	ic := &IconCache{m: map[string]*icon{}, inflight: map[string]chan struct{}{}, max: max, ttl: ttl, sem: make(chan struct{}, 8),
		client: &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return errors.New("non-https redirect")
			}
			if _, err := normalizeHost(req.URL.Hostname()); err != nil {
				return err
			}
			return nil
		}}}
	ic.fetch = ic.fetchRemote
	return ic
}

func (ic *IconCache) fetchRemote(ctx context.Context, host string) ([]byte, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+host+"/favicon.ico", nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 GoProxy-favicon")
	resp, err := ic.client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxIconBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxIconBytes {
		return nil, "", errors.New("bad body")
	}
	ct := http.DetectContentType(b)
	if len(b) >= 4 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0 {
		ct = "image/x-icon"
	}
	if !strings.HasPrefix(ct, "image/") {
		if bytesLooksSVG(b) {
			ct = "image/svg+xml"
		} else {
			return nil, "", errors.New("not an image: " + ct)
		}
	}
	return b, ct, nil
}

func bytesLooksSVG(b []byte) bool {
	s := strings.ToLower(string(b[:min(len(b), 512)]))
	return strings.Contains(s, "<svg")
}

// Get returns a cached icon, or resolves one (deduplicated, bounded concurrency).
// It always returns something: on failure a generated letter icon is cached too.
func (ic *IconCache) Get(ctx context.Context, host string) ([]byte, string) {
	for {
		ic.mu.Lock()
		if it, ok := ic.m[host]; ok && time.Now().Before(it.exp) {
			it.used = time.Now()
			ic.mu.Unlock()
			return it.data, it.ctype
		}
		if ch, ok := ic.inflight[host]; ok {
			ic.mu.Unlock()
			select {
			case <-ch:
				continue
			case <-ctx.Done():
				b, ct := letterIcon(host)
				return b, ct
			}
		}
		ch := make(chan struct{})
		ic.inflight[host] = ch
		ic.mu.Unlock()

		// Resolve detached from the caller so a closed browser tab still populates the cache.
		data, ct := ic.resolve(host)
		ic.mu.Lock()
		ic.put(host, data, ct)
		delete(ic.inflight, host)
		close(ch)
		ic.mu.Unlock()
		return data, ct
	}
}

func (ic *IconCache) resolve(host string) ([]byte, string) {
	ic.sem <- struct{}{}
	defer func() { <-ic.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*ic.client.Timeout+time.Second)
	defer cancel()
	cands := []string{host}
	if r := rootDomain(host); r != host {
		cands = append(cands, r)
	}
	for _, h := range cands {
		if b, ct, err := ic.fetch(ctx, h); err == nil {
			return b, ct
		}
	}
	return letterIcon(host)
}

// put must be called with mu held; evicts least-recently-used when full.
func (ic *IconCache) put(host string, data []byte, ct string) {
	now := time.Now()
	if _, ok := ic.m[host]; !ok && len(ic.m) >= ic.max {
		type kv struct {
			k string
			t time.Time
		}
		var all []kv
		for k, v := range ic.m {
			if now.After(v.exp) {
				delete(ic.m, k)
				continue
			}
			all = append(all, kv{k, v.used})
		}
		if len(ic.m) >= ic.max {
			sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
			for _, x := range all[:len(ic.m)-ic.max+1] {
				delete(ic.m, x.k)
			}
		}
	}
	ic.m[host] = &icon{data: data, ctype: ct, exp: now.Add(ic.ttl), used: now}
}

func (ic *IconCache) Len() int { ic.mu.Lock(); defer ic.mu.Unlock(); return len(ic.m) }

var letterColors = []string{"#0071e3", "#34c759", "#ff9500", "#af52de", "#ff2d55", "#5ac8fa", "#5856d6", "#ff3b30", "#30b0c7", "#a2845e"}

func letterIcon(host string) ([]byte, string) {
	r := rootDomain(host)
	ch := "?"
	if r != "" {
		ch = strings.ToUpper(r[:1])
	}
	f := fnv.New32a()
	f.Write([]byte(r))
	c := letterColors[f.Sum32()%uint32(len(letterColors))]
	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="%s"/><text x="32" y="43" font-family="-apple-system,Helvetica,Arial,sans-serif" font-size="32" font-weight="600" fill="#fff" text-anchor="middle">%s</text></svg>`, c, ch)
	return []byte(svg), "image/svg+xml"
}

// ServeHTTP implements GET /favicon?host=<host>.
func (ic *IconCache) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, err := normalizeHost(r.URL.Query().Get("host"))
	if err != nil {
		http.Error(w, "invalid host: "+err.Error(), http.StatusBadRequest)
		return
	}
	b, ct := ic.Get(r.Context(), h)
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	_, _ = w.Write(b)
}

// ---------- per-host stats ----------

type hostStat struct {
	Host     string `json:"host"`
	Requests int64  `json:"requests"`
	Bytes    int64  `json:"bytes"`
	last     time.Time
}

type HostStats struct {
	mu  sync.Mutex
	m   map[string]*hostStat
	max int
}

func NewHostStats(max int) *HostStats { return &HostStats{m: map[string]*hostStat{}, max: max} }

func (hs *HostStats) get(h string) *hostStat {
	s, ok := hs.m[h]
	if !ok {
		if len(hs.m) >= hs.max { // drop the least-recently-seen host
			var old string
			var t time.Time
			for k, v := range hs.m {
				if old == "" || v.last.Before(t) {
					old, t = k, v.last
				}
			}
			delete(hs.m, old)
		}
		s = &hostStat{Host: h}
		hs.m[h] = s
	}
	s.last = time.Now()
	return s
}

func (hs *HostStats) Record(host string, reqs, bytes int64) {
	if host == "" {
		return
	}
	hs.mu.Lock()
	s := hs.get(host)
	s.Requests += reqs
	s.Bytes += bytes
	hs.mu.Unlock()
}

func (hs *HostStats) Top(n int) []hostStat {
	hs.mu.Lock()
	out := make([]hostStat, 0, len(hs.m))
	for _, v := range hs.m {
		out = append(out, *v)
	}
	hs.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Host < out[j].Host
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// Restore seeds counters (used when loading persisted history).
func (hs *HostStats) Restore(list []hostStat) {
	hs.mu.Lock()
	for _, v := range list {
		if len(hs.m) >= hs.max {
			break
		}
		s := hs.get(v.Host)
		s.Requests += v.Requests
		s.Bytes += v.Bytes
	}
	hs.mu.Unlock()
}

// hostOf extracts a hostname from a log URL ("http://x/y" or "x:443").
func hostOf(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndex(u, "@"); i >= 0 {
		u = u[i+1:]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		u = h
	}
	return strings.ToLower(strings.Trim(u, "[]"))
}
