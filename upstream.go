// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// Outcome of one upstream exchange. Only the "real" error kinds count as Errors.
type outcome int

const (
	outOK        outcome = iota
	outCancelled         // a race loser cancelled because another upstream already answered (NOT an error)
	outTimeout           // deadline hit / i/o timeout
	outHTTP              // DoH answered with a non-200 status (429 = rate limited)
	outConn              // connection-level failure: reset, GOAWAY, TLS, EOF, refused
	outServfail          // rcode SERVFAIL (often a DNSSEC validation failure or the authoritative server timing out)
	outRefused           // rcode REFUSED
	outBad               // malformed / unexpected reply
)

// Upstream is one resolver (DoH, DoT or plain UDP) with live win/latency/error stats.
type Upstream struct {
	Name   string
	URL    string                 // https://... for DoH, tls://host:port for DoT, or host:port for UDP
	label  atomic.Pointer[string] // v2.5.1: display name from the DNS Servers list ("UltraDNS Public")
	doh    bool
	client *http.Client
	tr     *http.Transport
	udp    *dns.Client
	dot    *dotClient // v2.5.1: DNS-over-TLS (RFC 7858)

	Queries   atomic.Int64
	Wins      atomic.Int64
	Errors    atomic.Int64 // real failures: timeout + http + conn + bad (not cancelled, not SERVFAIL/REFUSED)
	Timeouts  atomic.Int64
	HTTPErrs  atomic.Int64
	ConnErrs  atomic.Int64
	Servfails atomic.Int64
	Refused   atomic.Int64
	BadResp   atomic.Int64
	Cancelled atomic.Int64
	Retries   atomic.Int64 // DoH requests retried on a fresh connection after a connection error
	lastHTTP  atomic.Int64 // last non-200 status code

	latSum  atomic.Int64 // ns, successful answers
	latN    atomic.Int64
	ewma    atomic.Int64 // ns
	lastOK  atomic.Int64 // unix nano
	lastErr atomic.Int64
	consec  atomic.Int64 // consecutive transport-level failures (drives the circuit breaker)
	errPPM  atomic.Int64 // EWMA of the failure rate, parts per million

	brkUntil atomic.Int64 // circuit breaker open until (unix nano)
	brkTrips atomic.Int64 // consecutive trips: backoff doubles each time
	brkTotal atomic.Int64

	latMu  sync.Mutex
	latBuf [128]int64 // ring of recent successful latencies (ns) for p95
	latPos int
	latCnt int

	// v2.8.0 smart upstreams
	demoteUntil atomic.Int64 // unix nano: kept out of the top N until then
	lastProbe   atomic.Int64
	probeEWMA   atomic.Int64 // ns, from the periodic probes only (fair: every upstream asked the same way)

	// v2.8.1 speed
	lastUse  atomic.Int64 // unix nano of the last real or warm exchange
	h3       atomic.Pointer[h3Client]
	h3Broken atomic.Int64 // unix nano: HTTP/3 not tried again before this
	H3OK     atomic.Int64
	H3Fail   atomic.Int64
	Warms    atomic.Int64

	now func() time.Time
}

const (
	breakerAfter   = 3                // consecutive failures that open the breaker
	breakerBase    = 2 * time.Second  // first backoff
	breakerMax     = 60 * time.Second // backoff cap
	defaultHedge   = 50 * time.Millisecond
	minHedge       = 20 * time.Millisecond
	maxHedge       = 200 * time.Millisecond
	dohIdleTimeout = 90 * time.Second
)

// Quad9 with ECS (EDNS Client Subnet): optional, off by default (Settings · Upstreams).
// It sends part of the house's public IP subnet to the authoritative servers so CDNs
// (YouTube, Netflix) can pick a nearby server; the trade-off is less privacy.
const quad9ECS = "https://dns11.quad9.net/dns-query"

// bootstrapIPs maps DoH host names to fixed IPs so GoProxy never needs DNS to reach its
// own upstreams (the default upstreams are IP-literal URLs for the same reason). TLS still
// verifies the certificate for the host name.
var (
	bootstrapMu  sync.RWMutex
	bootstrapIPs = map[string][]string{
		"dns11.quad9.net":            {"9.9.9.11", "149.112.112.11"},
		"unfiltered.adguard-dns.com": {"94.140.14.140", "94.140.14.141"},
		"dns.nextdns.io":             {"45.90.28.0", "45.90.30.0"},
		"dns.google":                 {"8.8.8.8", "8.8.4.4"},
		"cloudflare-dns.com":         {"1.1.1.1", "1.0.0.1"},
		"dns.quad9.net":              {"9.9.9.9", "149.112.112.112"},
	}
)

func hasBootstrap(host string) bool {
	bootstrapMu.RLock()
	defer bootstrapMu.RUnlock()
	return len(bootstrapIPs[strings.ToLower(host)]) > 0
}

func setBootstrap(host string, ips []string) {
	bootstrapMu.Lock()
	bootstrapIPs[strings.ToLower(host)] = ips
	bootstrapMu.Unlock()
}

func bootstrapDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dial(ctx, network, addr)
		}
		bootstrapMu.RLock()
		ips := bootstrapIPs[strings.ToLower(host)]
		bootstrapMu.RUnlock()
		if len(ips) == 0 {
			if alt := anycastAlt(addr); alt != "" { // v2.8.1: nearest sibling of the same provider
				if c, err := dial(ctx, network, alt); err == nil {
					return c, nil
				}
			}
			return dial(ctx, network, addr)
		}
		var last error
		for _, ip := range ips {
			a := net.JoinHostPort(ip, port)
			if alt := anycastAlt(a); alt != "" {
				if c, err := dial(ctx, network, alt); err == nil {
					return c, nil
				}
			}
			c, err := dial(ctx, network, a)
			if err == nil {
				return c, nil
			}
			last = err
		}
		return nil, last
	}
}

func newDoHTransport() *http.Transport {
	return &http.Transport{
		ForceAttemptHTTP2:   true, // HTTP/2 multiplexed, kept alive
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 4,
		// Close idle connections before the server does (servers silently drop idle HTTP/2
		// connections after ~1-2 min; reusing one of those costs a reset + redial on the next query).
		IdleConnTimeout:       dohIdleTimeout,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, ClientSessionCache: tls.NewLRUClientSessionCache(64)},
		DialContext:           bootstrapDial((&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext),
		Proxy:                 nil,
		// Detect dead HTTP/2 connections quickly (Wi-Fi drop, sleep, network change).
		HTTP2: &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 3 * time.Second},
	}
}

func NewUpstream(raw string, tr *http.Transport) *Upstream {
	u := &Upstream{URL: raw}
	if pu, err := url.Parse(raw); err == nil && pu.Scheme == "https" {
		if tr == nil {
			tr = newDoHTransport()
		}
		u.doh, u.Name, u.tr = true, pu.Host, tr
		u.client = &http.Client{Transport: tr, Timeout: 4 * time.Second}
	} else {
		if _, _, err := net.SplitHostPort(raw); err != nil {
			raw = net.JoinHostPort(raw, "53")
		}
		u.URL, u.Name = raw, "udp://"+raw
		u.udp = &dns.Client{Net: "udp", Timeout: 2 * time.Second, UDPSize: 4096}
	}
	return u
}

func (u *Upstream) clock() time.Time {
	if u.now != nil {
		return u.now()
	}
	return time.Now()
}

type httpStatusErr struct {
	name string
	code int
}

func (e *httpStatusErr) Error() string { return fmt.Sprintf("doh %s: http %d", e.name, e.code) }

// classify maps a transport error to an outcome. raceCtx is the context the request ran under.
func classify(raceCtx context.Context, err error) outcome {
	var he *httpStatusErr
	switch {
	case err == nil:
		return outOK
	case errors.As(err, &he):
		return outHTTP
	case errors.Is(raceCtx.Err(), context.Canceled):
		return outCancelled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(raceCtx.Err(), context.DeadlineExceeded):
		return outTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return outTimeout
	}
	var de *dns.Error
	if errors.As(err, &de) {
		return outBad
	}
	if strings.Contains(err.Error(), "dns: ") {
		return outBad
	}
	return outConn
}

// isConnReset reports errors where the request never got a usable connection (GOAWAY, reset,
// closed idle conn), i.e. it is safe and useful to retry once on a fresh connection.
func isConnReset(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, k := range []string{"GOAWAY", "connection reset", "broken pipe", "use of closed network connection", "EOF", "http2: client connection lost", "stream error", "REFUSED_STREAM", "server closed idle connection"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// Exchange queries this upstream and records the outcome. It never declares a winner.
func (u *Upstream) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	r, _, err := u.exchange(ctx, q)
	return r, err
}

func (u *Upstream) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, outcome, error) {
	u.Queries.Add(1)
	u.lastUse.Store(time.Now().UnixNano())
	t0 := time.Now()
	var r *dns.Msg
	var err error
	if u.doh {
		r, err = u.doDoH(ctx, q)
		if err != nil && ctx.Err() == nil && isConnReset(err) {
			// The pooled HTTP/2 connection went away under us (GOAWAY / reset): drop idle
			// connections and retry once on a fresh one while there is still time.
			u.Retries.Add(1)
			u.tr.CloseIdleConnections()
			r, err = u.doDoH(ctx, q)
		}
	} else if u.dot != nil {
		r, err = u.dot.exchange(ctx, q)
	} else {
		r, _, err = u.udp.ExchangeContext(ctx, q, u.URL)
		if err == nil && r.Truncated {
			tc := *u.udp
			tc.Net = "tcp"
			r, _, err = tc.ExchangeContext(ctx, q, u.URL)
		}
	}
	o := classify(ctx, err)
	if err == nil {
		switch {
		case r == nil || !r.Response || r.Id != q.Id:
			o, err = outBad, fmt.Errorf("%s: malformed reply", u.Name)
		case r.Rcode == dns.RcodeServerFailure:
			o, err = outServfail, fmt.Errorf("%s: rcode SERVFAIL", u.Name)
		case r.Rcode == dns.RcodeRefused:
			o, err = outRefused, fmt.Errorf("%s: rcode REFUSED", u.Name)
		case !validAnswer(r):
			o, err = outBad, fmt.Errorf("%s: rcode %s", u.Name, dns.RcodeToString[r.Rcode])
		}
	}
	u.record(o, time.Since(t0))
	if o == outServfail || o == outRefused || (o == outBad && r != nil && r.Response) {
		return r, o, err // still returned: usable as a last resort, never as a winner
	}
	if err != nil {
		return nil, o, err
	}
	return r, o, nil
}

func (u *Upstream) record(o outcome, d time.Duration) {
	now := u.clock().UnixNano()
	fail := int64(0)
	switch o {
	case outCancelled:
		u.Cancelled.Add(1)
		return // says nothing about the upstream
	case outOK:
		ns := d.Nanoseconds()
		u.lastOK.Store(now)
		u.consec.Store(0)
		u.brkTrips.Store(0)
		u.latSum.Add(ns)
		u.latN.Add(1)
		if old := u.ewma.Load(); old == 0 {
			u.ewma.Store(ns)
		} else {
			u.ewma.Store(old + (ns-old)/8)
		}
		u.latMu.Lock()
		u.latBuf[u.latPos] = ns
		u.latPos = (u.latPos + 1) % len(u.latBuf)
		u.latCnt = min(u.latCnt+1, len(u.latBuf))
		u.latMu.Unlock()
	case outServfail:
		// The upstream did answer: a per-name problem (DNSSEC bogus, dead authoritative server),
		// not an upstream outage. Counted separately; nudges the score but not the breaker.
		u.Servfails.Add(1)
		u.consec.Store(0)
		u.lastOK.Store(now)
		fail = 250_000
	case outRefused:
		u.Refused.Add(1)
		fail = 1_000_000
	default:
		u.Errors.Add(1)
		u.lastErr.Store(now)
		fail = 1_000_000
		switch o {
		case outTimeout:
			u.Timeouts.Add(1)
		case outHTTP:
			u.HTTPErrs.Add(1)
		case outConn:
			u.ConnErrs.Add(1)
		case outBad:
			u.BadResp.Add(1)
		}
	}
	old := u.errPPM.Load()
	u.errPPM.Store(old + (fail-old)/16)
	if o == outOK || o == outServfail {
		return
	}
	if u.consec.Add(1) >= breakerAfter {
		trips := u.brkTrips.Add(1)
		back := breakerBase << min(trips-1, 5)
		if back > breakerMax {
			back = breakerMax
		}
		u.brkUntil.Store(now + int64(back))
		u.brkTotal.Add(1)
		u.consec.Store(0)
	}
}

// open reports whether the circuit breaker is currently skipping this upstream.
func (u *Upstream) open() bool { return u.clock().UnixNano() < u.brkUntil.Load() }

// P95 of recent successful answers (0 = no data).
func (u *Upstream) P95() time.Duration {
	u.latMu.Lock()
	n := u.latCnt
	s := make([]int64, n)
	copy(s, u.latBuf[:n])
	u.latMu.Unlock()
	if n == 0 {
		return 0
	}
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return time.Duration(s[int(math.Ceil(0.95*float64(n)))-1])
}

// score: lower is better. p95 latency inflated by the recent failure rate. Upstreams
// without data score 0 so they get measured.
func (u *Upstream) score() float64 {
	p := float64(u.P95()) / 1e6
	if p == 0 {
		return 0
	}
	return p * (1 + 10*float64(u.errPPM.Load())/1e6)
}

func (u *Upstream) doDoH(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := q.Copy()
	m.Id = 0 // RFC 8484: cache-friendly
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", u.URL, bytes.NewReader(wire))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	if r, ok := u.tryH3(ctx, wire, q); ok { // v2.8.1: HTTP/3 when switched on and working
		return r, nil
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		u.lastHTTP.Store(int64(resp.StatusCode))
		return nil, &httpStatusErr{u.Name, resp.StatusCode}
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, fmt.Errorf("dns: unpack: %w", err)
	}
	r.Id = q.Id
	return r, nil
}

// Resolver races the best-scored DoH upstreams first, hedges to the rest after a short delay,
// and falls back to plain UDP if every DoH upstream fails.
type Resolver struct {
	DoH      []*Upstream // initial list (tests / start); the live list is Ups()
	Fallback []*Upstream
	// v2.5.1 DNS Servers: the list can be replaced while running (SetUpstreams), and in
	// priority mode the configured order decides who is raced first instead of the score.
	live     atomic.Pointer[[]*Upstream]
	Priority atomic.Bool
	Parallel int           // max DoH upstreams used per lookup (0 = all)
	First    int           // raced immediately (0 = 2)
	Hedge    time.Duration // delay before the others join (0 = adaptive, ~p95 of the best)
	Tr       *http.Transport
	Hedged   atomic.Int64 // lookups where the hedge fired
	// v2.6.0 parallel upstream ("parallel syncing"): every cache miss goes to ALL upstreams
	// at once (raced + fallback); the first valid answer wins, the rest are cancelled.
	ParallelAll atomic.Bool
	// v2.6.0: plain (unencrypted) upstreams are only asked when every encrypted one failed,
	// and only while PlainFallback is on (default on so sites never break).
	NoPlainFallback atomic.Bool            // zero value = fallback on
	DNSSECPass      bool                   // read by the server: SERVFAIL -> one CD=1 retry
	lastWin         atomic.Pointer[string] // label/URL of the upstream that won the last lookup
	lastFail        atomic.Int64
	lastOK          atomic.Int64
	// v2.8.0 smart upstreams: race only the best SmartN (default 3) by score, plus an
	// explorer every exploreEvery lookups; the rest are a fallback. widenUntil (self-healing)
	// temporarily races everybody again.
	Smart      atomic.Bool
	SmartN     atomic.Int32
	widenUntil atomic.Int64
	exploreCtr atomic.Uint64
	now        func() time.Time
}

// offlineFor is how long after a total upstream failure (with no success since) stale
// answers are served immediately (RFC 8767 "failure recheck timer", 30 s).
const offlineFor = 30 * time.Second

// Offline reports that the internet looks down right now.
func (rs *Resolver) Offline() bool {
	if rs == nil {
		return false
	}
	f := rs.lastFail.Load()
	if f == 0 || f < rs.lastOK.Load() {
		return false
	}
	return rs.clock().Sub(time.Unix(0, f)) < offlineFor
}

func (rs *Resolver) clock() time.Time {
	if rs.now != nil {
		return rs.now()
	}
	return time.Now()
}

type UpstreamStat struct {
	Name       string  `json:"name"`
	Label      string  `json:"label,omitempty"`
	Kind       string  `json:"kind"`
	Encrypted  bool    `json:"encrypted"`
	Priority   int     `json:"priority,omitempty"` // 1 = top of the DNS Servers list (0 = -fallback list)
	Queries    int64   `json:"queries"`
	Wins       int64   `json:"wins"`
	Errors     int64   `json:"errors"` // timeout + http + conn + bad
	Timeouts   int64   `json:"timeouts"`
	HTTPErrs   int64   `json:"http_errors"`
	ConnErrs   int64   `json:"conn_errors"`
	BadResp    int64   `json:"bad_replies"`
	Servfails  int64   `json:"servfail"`
	Refused    int64   `json:"refused"`
	Cancelled  int64   `json:"cancelled"`
	Retries    int64   `json:"retries"`
	LastHTTP   int64   `json:"last_http_status"`
	WinRate    float64 `json:"win_rate"`
	AvgMs      float64 `json:"avg_ms"`
	EwmaMs     float64 `json:"ewma_ms"`
	P95Ms      float64 `json:"p95_ms"`
	ErrRate    float64 `json:"err_rate"`
	Score      float64 `json:"score"`
	BreakerSec float64 `json:"breaker_sec"` // >0: skipped for this many more seconds
	Trips      int64   `json:"breaker_trips"`
	Health     string  `json:"health"` // up | slow | down | idle
	LastOKSec  float64 `json:"last_ok_sec"`
}

func (u *Upstream) health() string {
	switch {
	case u.open() || u.consec.Load() >= breakerAfter:
		return "down"
	case u.lastOK.Load() == 0 && u.lastErr.Load() == 0:
		return "idle"
	case u.lastErr.Load() > u.lastOK.Load() || u.ewma.Load() > int64(250*time.Millisecond):
		return "slow"
	}
	return "up"
}

func validAnswer(r *dns.Msg) bool {
	return r != nil && r.Response && (r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError)
}

// order returns the DoH upstreams to use, best score first, breaker-open ones last (or
// dropped while healthy alternatives exist).
func (rs *Resolver) order() []*Upstream {
	type sc struct {
		u *Upstream
		s float64
	}
	var ok, opened []sc
	all := rs.Ups()
	for _, u := range all {
		if u.open() {
			opened = append(opened, sc{u, u.score()})
		} else {
			ok = append(ok, sc{u, u.score()})
		}
	}
	if !rs.Priority.Load() { // priority mode keeps the configured order
		sort.SliceStable(ok, func(i, j int) bool { return ok[i].s < ok[j].s })
	}
	sort.SliceStable(opened, func(i, j int) bool { return opened[i].u.brkUntil.Load() < opened[j].u.brkUntil.Load() })
	out := make([]*Upstream, 0, len(all))
	for _, x := range ok {
		out = append(out, x.u)
	}
	if len(out) == 0 { // everything is backing off: try them anyway, soonest-to-reopen first
		for _, x := range opened {
			out = append(out, x.u)
		}
	}
	if k := rs.Parallel; k > 0 && k < len(out) {
		out = out[:k]
	}
	return out
}

func (rs *Resolver) hedgeDelay(best *Upstream) time.Duration {
	if rs.Hedge > 0 {
		return rs.Hedge
	}
	p := best.P95()
	if p == 0 {
		return defaultHedge
	}
	return min(max(p, minHedge), maxHedge)
}

// race queries all ups at once (used for the UDP fallback and by tests).
func race(ctx context.Context, ups []*Upstream, q *dns.Msg) (*dns.Msg, *Upstream, error) {
	return hedgedRace(ctx, ups, len(ups), 0, q, nil)
}

// hedgedRace starts the first `first` upstreams, then the rest after `hedge` (or as soon as
// every in-flight one has failed). The first valid NOERROR/NXDOMAIN wins; SERVFAIL/REFUSED never
// win and are only returned as a last resort. Losers are cancelled and counted as cancelled.
func hedgedRace(ctx context.Context, ups []*Upstream, first int, hedge time.Duration, q *dns.Msg, hedged *atomic.Int64) (*dns.Msg, *Upstream, error) {
	if len(ups) == 0 {
		return nil, nil, errors.New("no upstreams")
	}
	if first <= 0 || first > len(ups) {
		first = len(ups)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // cancels the losers
	type res struct {
		r   *dns.Msg
		u   *Upstream
		err error
	}
	ch := make(chan res, len(ups))
	launched, pending := 0, 0
	launch := func(n int) {
		for ; n > 0 && launched < len(ups); n-- {
			u := ups[launched]
			launched++
			pending++
			go func() {
				r, _, err := u.exchange(ctx, q.Copy()) // Pack mutates the OPT RR: never share q
				ch <- res{r, u, err}
			}()
		}
	}
	launch(first)
	var timer <-chan time.Time
	if launched < len(ups) {
		t := time.NewTimer(hedge)
		defer t.Stop()
		timer = t.C
	}
	var lastErr error
	var bad *res
	for pending > 0 || launched < len(ups) {
		select {
		case x := <-ch:
			pending--
			if x.err == nil && validAnswer(x.r) {
				x.u.Wins.Add(1)
				return x.r, x.u, nil
			}
			lastErr = x.err
			if bad == nil && x.r != nil && x.r.Response {
				bad = &x
			}
			if pending == 0 && launched < len(ups) { // everyone in flight failed: don't wait
				if hedged != nil {
					hedged.Add(1)
				}
				launch(len(ups))
				timer = nil
			}
		case <-timer:
			timer = nil
			if hedged != nil {
				hedged.Add(1)
			}
			launch(len(ups))
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			if bad != nil {
				return bad.r, bad.u, nil
			}
			return nil, nil, lastErr
		}
	}
	if bad != nil {
		return bad.r, bad.u, nil
	}
	return nil, nil, lastErr
}

func (rs *Resolver) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, *Upstream, error) {
	r, u, err := rs.resolve(ctx, q)
	switch {
	case err == nil && validAnswer(r):
		rs.lastOK.Store(rs.clock().UnixNano())
	case err == nil && r != nil: // an upstream answered (SERVFAIL etc.): internet is up
		rs.lastOK.Store(rs.clock().UnixNano())
	case ctx.Err() == nil:
		rs.lastFail.Store(rs.clock().UnixNano())
		if rs.Tr != nil {
			rs.Tr.CloseIdleConnections() // the network may have changed: redial next time
		}
	}
	return r, u, err
}

func (rs *Resolver) resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, *Upstream, error) {
	ups := rs.order()
	first := rs.First
	if first <= 0 {
		first = 2
	}
	var r *dns.Msg
	var u *Upstream
	var err error
	raced, fallback := rs.split(ups, first)
	if rs.smartOn() {
		raced, fallback = rs.smartSplit()
	}
	if rs.NoPlainFallback.Load() {
		fallback = encryptedOnly(fallback)
	}
	if len(raced) > 0 && rs.ParallelAll.Load() {
		// v2.6.0 parallel upstream: every raced server at once, first valid answer wins
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		r, u, err = race(c, raced, q)
		cancel()
		if err == nil && validAnswer(r) {
			rs.noteWin(u)
			return r, u, nil
		}
	} else if len(raced) > 0 {
		c, cancel := context.WithTimeout(ctx, 4*time.Second)
		r, u, err = hedgedRace(c, raced, first, rs.hedgeDelay(raced[0]), q, &rs.Hedged)
		cancel()
		if err == nil && validAnswer(r) {
			rs.noteWin(u)
			return r, u, nil
		}
	}
	if len(fallback) > 0 {
		c2, cancel2 := context.WithTimeout(ctx, 3*time.Second)
		defer cancel2()
		if r2, u2, err2 := race(c2, fallback, q); err2 == nil && validAnswer(r2) {
			rs.noteWin(u2)
			return r2, u2, nil
		} else if r == nil && r2 != nil {
			r, u = r2, u2
		} else if err == nil && r == nil {
			err = err2
		}
	}
	if r != nil {
		return r, u, nil
	}
	if err == nil {
		err = errors.New("no upstreams")
	}
	return nil, nil, err
}

// Ups returns the live upstream list (priority order in priority mode).
func (rs *Resolver) Ups() []*Upstream {
	if p := rs.live.Load(); p != nil {
		return *p
	}
	return rs.DoH
}

// SetUpstreams swaps the live list. In-flight lookups keep the list they started with.
func (rs *Resolver) SetUpstreams(ups []*Upstream) {
	cp := append([]*Upstream(nil), ups...)
	rs.live.Store(&cp)
}

// split decides who is raced and who is only a fallback. Score mode (legacy -upstreams flag):
// every listed upstream is raced/hedged, the -fallback list is the last resort. Priority
// mode (DNS Servers): the top `first` entries are raced immediately whatever their protocol;
// encrypted entries below them join after the hedge delay; unencrypted (plain UDP) entries
// below them are never hedged in: they are fallbacks, asked only after every raced upstream
// failed, before the -fallback list. So an unencrypted server at the bottom of the list sees
// a lookup only when encrypted DNS is down, and moving it to the top makes it a primary.
func (rs *Resolver) split(ups []*Upstream, first int) (raced, fallback []*Upstream) {
	if !rs.Priority.Load() {
		return ups, rs.Fallback
	}
	for i, u := range ups {
		if i < first || u.Encrypted() {
			raced = append(raced, u)
		} else {
			fallback = append(fallback, u)
		}
	}
	seen := map[string]bool{}
	for _, u := range fallback {
		seen[u.URL] = true
	}
	for _, u := range raced {
		seen[u.URL] = true
	}
	for _, u := range rs.Fallback {
		if !seen[u.URL] {
			fallback = append(fallback, u)
		}
	}
	return raced, fallback
}

// Label is the display name from the DNS Servers list (may change while running).
func (u *Upstream) Label() string {
	if p := u.label.Load(); p != nil {
		return *p
	}
	return ""
}

func (u *Upstream) SetLabel(s string) { u.label.Store(&s) }

// Encrypted reports DoH or DoT.
func (u *Upstream) Encrypted() bool { return u.doh || u.dot != nil }

// Proto is "DoH", "DoT" or "UDP".
func (u *Upstream) Proto() string {
	switch {
	case u.doh:
		return "DoH"
	case u.dot != nil:
		return "DoT"
	}
	return "UDP"
}

// closeIdle drops pooled connections (removed from the list, or after a benchmark).
func (u *Upstream) closeIdle() {
	if u.tr != nil {
		u.tr.CloseIdleConnections()
	}
	if u.dot != nil {
		u.dot.closeIdle()
	}
}

func (rs *Resolver) Stats() []UpstreamStat {
	var out []UpstreamStat
	var total int64
	prim := rs.Ups()
	all := append(append([]*Upstream{}, prim...), rs.Fallback...)
	for _, u := range all {
		total += u.Wins.Load()
	}
	for i, u := range all {
		s := UpstreamStat{Name: u.Name, Label: u.Label(), Kind: u.Proto(), Encrypted: u.Encrypted(), Queries: u.Queries.Load(), Wins: u.Wins.Load(), Errors: u.Errors.Load(),
			Timeouts: u.Timeouts.Load(), HTTPErrs: u.HTTPErrs.Load(), ConnErrs: u.ConnErrs.Load(), BadResp: u.BadResp.Load(),
			Servfails: u.Servfails.Load(), Refused: u.Refused.Load(), Cancelled: u.Cancelled.Load(), Retries: u.Retries.Load(),
			LastHTTP: u.lastHTTP.Load(), EwmaMs: float64(u.ewma.Load()) / 1e6, P95Ms: float64(u.P95()) / 1e6,
			ErrRate: float64(u.errPPM.Load()) / 1e6, Score: u.score(), Trips: u.brkTotal.Load(), Health: u.health()}
		if d := time.Until(time.Unix(0, u.brkUntil.Load())); d > 0 {
			s.BreakerSec = d.Seconds()
		}
		if t := u.lastOK.Load(); t > 0 {
			s.LastOKSec = time.Since(time.Unix(0, t)).Seconds()
		}
		if i >= len(prim) {
			s.Kind = "UDP fallback"
		} else {
			s.Priority = i + 1
			if s.Kind == "UDP" {
				s.Kind = "UDP (unencrypted)"
			}
		}
		if n := u.latN.Load(); n > 0 {
			s.AvgMs = float64(u.latSum.Load()) / float64(n) / 1e6
		}
		if total > 0 {
			s.WinRate = float64(s.Wins) / float64(total)
		}
		out = append(out, s)
	}
	return out
}

func (rs *Resolver) noteWin(u *Upstream) {
	if u == nil {
		return
	}
	n := u.Label()
	if n == "" {
		n = u.URL
	}
	n += " (" + u.Proto() + ")"
	rs.lastWin.Store(&n)
}

// LastWinner is the upstream that answered the most recent lookup ("" before the first).
func (rs *Resolver) LastWinner() string {
	if p := rs.lastWin.Load(); p != nil {
		return *p
	}
	return ""
}

func encryptedOnly(ups []*Upstream) []*Upstream {
	var out []*Upstream
	for _, u := range ups {
		if u.Encrypted() {
			out = append(out, u)
		}
	}
	return out
}
