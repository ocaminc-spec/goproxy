// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.0 DNS tunneling + DGA detection (lightweight heuristics, no ML model):
//   - DGA: the registrable label is long, high-entropy, consonant-heavy or digit-mixed.
//   - Tunneling: one base domain gets many distinct long subdomains in 5 minutes, or very
//     long labels, or a burst of TXT/NULL lookups.
// Alert-only by default; block mode (opt-in) answers flagged names with 0.0.0.0 / NODATA.
// Known CDN / cloud suffixes and reverse lookups are never flagged.

import (
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

var detectSafe = []string{"in-addr.arpa", "ip6.arpa", "local", "lan", "home.arpa", "googlevideo.com", "gvt1.com", "gvt2.com", "1e100.net", "googleapis.com", "googleusercontent.com", "gstatic.com",
	"cloudfront.net", "akamaiedge.net", "akamai.net", "akamaihd.net", "akadns.net", "edgekey.net", "edgesuite.net", "azureedge.net", "azure.com", "windows.net", "trafficmanager.net", "msedge.net",
	"amazonaws.com", "fastly.net", "fastly-edge.com", "cdn77.org", "nflxvideo.net", "nflxso.net", "aaplimg.com", "apple-dns.net", "icloud.com", "cloudflare.net", "cloudflare-dns.com",
	"spotify.com", "scdn.co", "tiktokcdn.com", "fbcdn.net", "whatsapp.net", "steamcontent.com", "xboxlive.com", "playstation.net", "doubleclick.net", "sophosxl.net", "mcafee.com", "spamhaus.org",
	"dnsbl", "senderbase.org", "e5.sk", "tailscale.net", "ts.net", "plex.direct", "quickconnect.to", "synology.me", "duckdns.org", "local.goproxy"}

func safeDomain(name string) bool {
	for _, s := range detectSafe {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// baseDomain: the last two labels (three for 2-letter-SLD ccTLDs like co.uk / com.au).
func baseDomain(name string) string {
	l := strings.Split(name, ".")
	if len(l) <= 2 {
		return name
	}
	n := 2
	if sld := l[len(l)-2]; len(l[len(l)-1]) == 2 && (len(sld) <= 3) {
		n = 3
	}
	if n > len(l) {
		n = len(l)
	}
	return strings.Join(l[len(l)-n:], ".")
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var f [256]int
	for i := 0; i < len(s); i++ {
		f[s[i]]++
	}
	var h float64
	for _, c := range f {
		if c > 0 {
			p := float64(c) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// dgaScore in [0,1]: >= 0.75 is suspicious.
func dgaScore(name string) float64 {
	b := baseDomain(name)
	lbl := strings.SplitN(b, ".", 2)[0]
	if len(lbl) < 10 || safeDomain(name) || strings.HasPrefix(lbl, "xn--") {
		return 0
	}
	var digits, vowels, run, maxRun, hyph, flips int
	for i := 0; i < len(lbl); i++ {
		c := lbl[i]
		if i > 0 && (c >= '0' && c <= '9') != (lbl[i-1] >= '0' && lbl[i-1] <= '9') {
			flips++
		}
		switch {
		case c >= '0' && c <= '9':
			digits++
			run = 0
		case strings.IndexByte("aeiouy", c) >= 0:
			vowels++
			run = 0
		case c == '-':
			hyph++
			run = 0
		default:
			run++
			maxRun = max(maxRun, run)
		}
	}
	n := float64(len(lbl))
	sc := 0.0
	if e := entropy(lbl); e > 3.0 {
		sc += min((e-3.0)/0.8, 1) * 0.35
	}
	if float64(flips)/n > 0.3 {
		sc += 0.2 // letters and digits interleaved
	}
	if len(lbl) >= 16 {
		sc += min((n-16)/16, 1) * 0.15
	}
	if vr := float64(vowels) / n; vr < 0.3 {
		sc += min((0.3-vr)/0.2, 1) * 0.25
	}
	if maxRun >= 5 {
		sc += min(float64(maxRun-4)/4, 1) * 0.15
	}
	if dr := float64(digits) / n; dr > 0.1 && dr < 0.9 {
		sc += min(dr/0.4, 1) * 0.15
	}
	if hyph > 0 {
		sc *= 0.7 // real brands use words-with-hyphens; DGAs rarely do
	}
	return min(sc, 1)
}

type detBase struct {
	subs    map[string]struct{}
	lenSum  int
	txt     int
	longLbl bool
}

type DetectEvent struct {
	T      int64   `json:"t"`
	Kind   string  `json:"kind"` // dga | tunnel
	Domain string  `json:"domain"`
	Score  float64 `json:"score"`
	Reason string  `json:"reason"`
	Count  int     `json:"count"`
}

type Detector struct {
	mu      sync.Mutex
	win     map[string]*detBase
	events  []DetectEvent
	flagged atomic.Pointer[map[string]int64] // base -> unix until (block mode)
	seen    map[string]int64                 // base -> last event (dedupe 1 h)
	On      atomic.Bool
	Block   atomic.Bool
	DGA     atomic.Int64
	Tunnel  atomic.Int64
	Blocked atomic.Int64
	now     func() time.Time
	raise   func(DetectEvent)
}

func NewDetector() *Detector {
	d := &Detector{win: map[string]*detBase{}, seen: map[string]int64{}, now: time.Now}
	m := map[string]int64{}
	d.flagged.Store(&m)
	return d
}

// Observe a lookup that went upstream (cache hits are not re-checked).
func (d *Detector) Observe(name string, qtype uint16) {
	if d == nil || !d.On.Load() || name == "" || safeDomain(name) || !strings.Contains(name, ".") {
		return
	}
	base := baseDomain(name)
	if sc := dgaScore(name); sc >= 0.75 {
		d.event(DetectEvent{Kind: "dga", Domain: base, Score: sc, Reason: "random-looking domain name", Count: 1})
	}
	sub := strings.TrimSuffix(strings.TrimSuffix(name, base), ".")
	d.mu.Lock()
	b := d.win[base]
	if b == nil {
		if len(d.win) >= 5000 {
			d.mu.Unlock()
			return
		}
		b = &detBase{subs: map[string]struct{}{}}
		d.win[base] = b
	}
	if sub != "" && len(b.subs) < 1000 {
		if _, ok := b.subs[sub]; !ok {
			b.subs[sub] = struct{}{}
			b.lenSum += len(sub)
		}
	}
	if qtype == dns.TypeTXT || qtype == dns.TypeNULL {
		b.txt++
	}
	for _, l := range strings.Split(sub, ".") {
		if len(l) >= 50 {
			b.longLbl = true
		}
	}
	n, avg, txt, long := len(b.subs), 0, b.txt, b.longLbl
	if n > 0 {
		avg = b.lenSum / n
	}
	d.mu.Unlock()
	switch {
	case n >= 60 && avg >= 20:
		d.event(DetectEvent{Kind: "tunnel", Domain: base, Score: 0.9, Reason: "many long unique subdomains", Count: n})
	case long && n >= 10:
		d.event(DetectEvent{Kind: "tunnel", Domain: base, Score: 0.85, Reason: "very long labels", Count: n})
	case txt >= 40 && n >= 20:
		d.event(DetectEvent{Kind: "tunnel", Domain: base, Score: 0.8, Reason: "burst of TXT lookups", Count: txt})
	}
}

func (d *Detector) event(e DetectEvent) {
	now := d.now().Unix()
	d.mu.Lock()
	if t, ok := d.seen[e.Domain]; ok && now-t < 3600 {
		d.mu.Unlock()
		return
	}
	d.seen[e.Domain] = now
	if len(d.seen) > 20000 {
		d.seen = map[string]int64{}
	}
	e.T = now
	d.events = append(d.events, e)
	if len(d.events) > 200 {
		d.events = d.events[len(d.events)-200:]
	}
	old := *d.flagged.Load()
	m := make(map[string]int64, len(old)+1)
	for k, v := range old {
		if v > now {
			m[k] = v
		}
	}
	m[e.Domain] = now + 24*3600
	d.flagged.Store(&m)
	d.mu.Unlock()
	if e.Kind == "dga" {
		d.DGA.Add(1)
	} else {
		d.Tunnel.Add(1)
	}
	if d.raise != nil {
		d.raise(e)
	}
}

// ShouldBlock (block mode only): flagged base domain, or a fresh name scoring very high.
func (d *Detector) ShouldBlock(name string) bool {
	if d == nil || !d.On.Load() || !d.Block.Load() {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if safeDomain(name) {
		return false
	}
	if until, ok := (*d.flagged.Load())[baseDomain(name)]; ok && until > d.now().Unix() {
		d.Blocked.Add(1)
		return true
	}
	if dgaScore(name) >= 0.85 {
		d.Blocked.Add(1)
		return true
	}
	return false
}

// Reset starts a new 5-minute tunneling window.
func (d *Detector) Reset() {
	d.mu.Lock()
	d.win = map[string]*detBase{}
	d.mu.Unlock()
}

func (d *Detector) Events() []DetectEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]DetectEvent, len(d.events))
	for i, e := range d.events {
		out[len(d.events)-1-i] = e
	}
	return out
}
