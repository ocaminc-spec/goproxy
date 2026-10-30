// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.1 upstream speed: warm connection pools, HTTP/3 DoH (opt-in, falls back to HTTP/2),
// nearest-anycast address per provider, and serve-stale at once (RFC 8767).
// Already in place before 2.8.1 and kept: HTTP/2 multiplexing with keep-alive and pings,
// TLS session resumption (DoH and DoT), coalesced misses, per-profile UDP buffers and
// one listener goroutine per core.

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	warmEvery     = 15 * time.Second // below DoT's 20 s idle and far below DoH's 90 s
	staleMaxAge   = 24 * time.Hour   // RFC 8767 suggests 1-3 days
	h3RetryAfter  = 10 * time.Minute
	h3Handshake   = 400 * time.Millisecond
	anycastEvery  = 10 * time.Minute
	anycastGainPc = 0.8                  // a sibling must be at least 20 % faster...
	anycastGainMs = 2 * time.Millisecond // ...and 2 ms faster
)

// Provider anycast siblings: different addresses of the same service with the same certificate.
var anycastSiblings = [][]string{
	{"1.1.1.1", "1.0.0.1"}, {"2606:4700:4700::1111", "2606:4700:4700::1001"},
	{"8.8.8.8", "8.8.4.4"}, {"2001:4860:4860::8888", "2001:4860:4860::8844"},
	{"9.9.9.9", "149.112.112.112"}, {"2620:fe::fe", "2620:fe::9"},
	{"9.9.9.11", "149.112.112.11"}, {"94.140.14.140", "94.140.14.141"},
}

var (
	anycastOn  atomic.Bool
	anycastMu  sync.RWMutex
	anycastMap = map[string]string{} // "ip:port" -> faster "ip:port"
)

func anycastAlt(addr string) string {
	if !anycastOn.Load() {
		return ""
	}
	anycastMu.RLock()
	defer anycastMu.RUnlock()
	return anycastMap[addr]
}

type AnycastPick struct {
	From   string  `json:"from"`
	To     string  `json:"to"`
	FromMs float64 `json:"from_ms"`
	ToMs   float64 `json:"to_ms"`
}

type Speed struct {
	s       *DNSServer
	warmOn  atomic.Bool
	h3On    atomic.Bool
	staleOn atomic.Bool
	mu      sync.Mutex
	picks   []AnycastPick
	checked time.Time
}

func NewSpeed(s *DNSServer) *Speed {
	sp := &Speed{s: s}
	sp.warmOn.Store(true)
	sp.staleOn.Store(true)
	anycastOn.Store(true)
	return sp
}

func (sp *Speed) apply(c V28Config) {
	if sp == nil {
		return
	}
	sp.warmOn.Store(!c.WarmOff)
	sp.h3On.Store(c.H3On)
	h3Global.Store(c.H3On)
	anycastOn.Store(!c.AnycastOff)
	sp.staleOn.Store(!c.ServeStaleOff)
	if sp.s != nil && sp.s.cache != nil {
		if c.ServeStaleOff {
			sp.s.cache.staleMax.Store(0)
		} else {
			sp.s.cache.staleMax.Store(int64(staleMaxAge))
		}
	}
}

func (x *V28) staleNow() bool { return x != nil && x.sp != nil && x.sp.staleOn.Load() }

// Warm sends one tiny query over every encrypted upstream that has been idle for warmEvery,
// so the pooled TLS/HTTP-2 connection never goes cold between real lookups.
func (sp *Speed) Warm(ctx context.Context) {
	if sp == nil || !sp.warmOn.Load() || sp.s == nil || sp.s.res == nil {
		return
	}
	cut := time.Now().Add(-warmEvery + time.Second).UnixNano()
	var wg sync.WaitGroup
	for _, u := range sp.s.res.Ups() {
		if !u.Encrypted() || u.open() || u.lastUse.Load() > cut {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			q := new(dns.Msg)
			q.SetQuestion(".", dns.TypeNS)
			q.RecursionDesired = true
			c, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			u.lastUse.Store(time.Now().UnixNano())
			// not recorded in the upstream's stats: it is upkeep, not a lookup
			var err error
			if u.doh {
				_, err = u.doDoH(c, q)
			} else if u.dot != nil {
				_, err = u.dot.exchange(c, q)
			}
			if err == nil {
				u.Warms.Add(1)
			}
		}()
	}
	wg.Wait()
}

// ---- nearest anycast ----

func connectMs(ctx context.Context, addr string) time.Duration {
	var xs []time.Duration
	for range 5 {
		t0 := time.Now()
		c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return 0
		}
		xs = append(xs, time.Since(t0))
		_ = c.Close()
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	return xs[2]
}

// tlsOK checks that the sibling presents a certificate valid for the original server name.
func tlsOK(ctx context.Context, addr, serverName string) bool {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 2 * time.Second}, Config: &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// targets returns (dial addr, TLS server name) for every encrypted upstream.
func (sp *Speed) targets() (out [][2]string) {
	for _, u := range sp.s.res.Ups() {
		switch {
		case u.doh:
			h, p := u.Name, "443"
			if hh, pp, err := net.SplitHostPort(u.Name); err == nil {
				h, p = hh, pp
			}
			h = trimBrackets(h)
			if net.ParseIP(h) != nil {
				out = append(out, [2]string{net.JoinHostPort(h, p), h})
			} else {
				bootstrapMu.RLock()
				for _, ip := range bootstrapIPs[h] {
					out = append(out, [2]string{net.JoinHostPort(ip, p), h})
				}
				bootstrapMu.RUnlock()
			}
		case u.dot != nil:
			out = append(out, [2]string{u.dot.addr, u.dot.host})
		}
	}
	return
}

func trimBrackets(h string) string {
	if len(h) > 1 && h[0] == '[' && h[len(h)-1] == ']' {
		return h[1 : len(h)-1]
	}
	return h
}

// PickAnycast measures each provider sibling and redirects a configured address to its
// sibling only when the sibling is clearly faster, has a valid certificate for the same
// name, and is not itself one of your configured upstreams (so diversity is kept).
func (sp *Speed) PickAnycast(ctx context.Context) {
	if sp == nil || sp.s == nil || sp.s.res == nil || !anycastOn.Load() {
		return
	}
	tg := sp.targets()
	configured := map[string]bool{}
	for _, t := range tg {
		configured[t[0]] = true
	}
	next := map[string]string{}
	var picks []AnycastPick
	for _, t := range tg {
		h, p, _ := net.SplitHostPort(t[0])
		var sibs []string
		for _, g := range anycastSiblings {
			for _, ip := range g {
				if ip == h {
					sibs = g
				}
			}
		}
		if sibs == nil {
			continue
		}
		base := connectMs(ctx, t[0])
		if base == 0 {
			continue
		}
		best, bestD := "", base
		for _, ip := range sibs {
			a := net.JoinHostPort(ip, p)
			if ip == h || configured[a] {
				continue
			}
			if d := connectMs(ctx, a); d > 0 && float64(d) < float64(bestD)*anycastGainPc && base-d >= anycastGainMs {
				best, bestD = a, d
			}
		}
		if best != "" && tlsOK(ctx, best, t[1]) {
			next[t[0]] = best
			picks = append(picks, AnycastPick{t[0], best, ms(base), ms(bestD)})
		}
	}
	anycastMu.Lock()
	anycastMap = next
	anycastMu.Unlock()
	sp.mu.Lock()
	sp.picks, sp.checked = picks, time.Now()
	sp.mu.Unlock()
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// ---- HTTP/3 ----

var h3Global atomic.Bool

type h3Client struct{ c *http.Client }

func (u *Upstream) h3client() *h3Client {
	if c := u.h3.Load(); c != nil {
		return c
	}
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ClientSessionCache: tls.NewLRUClientSessionCache(16)},
		QUICConfig:      &quic.Config{HandshakeIdleTimeout: h3Handshake, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 20 * time.Second},
		Dial: func(ctx context.Context, addr string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			targets := []string{addr}
			bootstrapMu.RLock()
			if ips := bootstrapIPs[host]; len(ips) > 0 {
				targets = nil
				for _, ip := range ips {
					targets = append(targets, net.JoinHostPort(ip, port))
				}
			}
			bootstrapMu.RUnlock()
			var last error
			for _, t := range targets {
				if alt := anycastAlt(t); alt != "" {
					t = alt
				}
				c, err := quic.DialAddrEarly(ctx, t, tc, qc)
				if err == nil {
					return c, nil
				}
				last = err
			}
			return nil, last
		},
	}
	c := &h3Client{c: &http.Client{Transport: tr, Timeout: 4 * time.Second}}
	if u.h3.CompareAndSwap(nil, c) {
		return c
	}
	return u.h3.Load()
}

// tryH3 returns ok=false whenever HTTP/2 should be used (off, recently broken, or failed now).
func (u *Upstream) tryH3(ctx context.Context, wire []byte, q *dns.Msg) (*dns.Msg, bool) {
	if !h3Global.Load() || time.Now().UnixNano() < u.h3Broken.Load() {
		return nil, false
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", u.URL, bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := u.h3client().c.Do(req)
	if err != nil {
		if ctx.Err() == nil || !errors.Is(ctx.Err(), context.Canceled) {
			u.H3Fail.Add(1)
			u.h3Broken.Store(time.Now().Add(h3RetryAfter).UnixNano())
		}
		return nil, false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil || resp.StatusCode != 200 {
		u.H3Fail.Add(1)
		u.h3Broken.Store(time.Now().Add(h3RetryAfter).UnixNano())
		return nil, false
	}
	r := new(dns.Msg)
	if r.Unpack(body) != nil {
		return nil, false
	}
	r.Id = q.Id
	u.H3OK.Add(1)
	return r, true
}

func (sp *Speed) Status() map[string]any {
	if sp == nil {
		return nil
	}
	sp.mu.Lock()
	picks, checked := sp.picks, sp.checked
	sp.mu.Unlock()
	type us struct {
		Name   string `json:"name"`
		Warms  int64  `json:"warms"`
		H3OK   int64  `json:"h3_ok"`
		H3Fail int64  `json:"h3_fail"`
		H3     string `json:"h3"`
	}
	var ups []us
	now := time.Now().UnixNano()
	for _, u := range sp.s.res.Ups() {
		if !u.Encrypted() {
			continue
		}
		st := "off"
		if h3Global.Load() && u.doh {
			st = "trying"
			if now < u.h3Broken.Load() {
				st = "not supported (HTTP/2)"
			} else if u.H3OK.Load() > 0 {
				st = "in use"
			}
		}
		if !u.doh {
			st = "n/a (DoT)"
		}
		ups = append(ups, us{u.Label(), u.Warms.Load(), u.H3OK.Load(), u.H3Fail.Load(), st})
	}
	var ck int64
	if !checked.IsZero() {
		ck = checked.Unix()
	}
	return map[string]any{"warm": sp.warmOn.Load(), "h3": sp.h3On.Load(), "anycast": anycastOn.Load(), "serve_stale": sp.staleOn.Load(),
		"stale_max_hours": staleMaxAge.Hours(), "stale_ttl_sec": 30, "anycast_picks": picks, "anycast_checked": ck, "upstreams": ups,
		"stale_served": sp.s.stats.StaleHits.Load()}
}
