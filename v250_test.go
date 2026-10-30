// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---------- GP-01: honour upstream TTLs, pinned floor, RFC 2308 negative caching ----------

func negReply(name string, rcode int, soa string) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m := new(dns.Msg)
	m.SetRcode(q, rcode)
	if soa != "" {
		m.Ns = []dns.RR{rr(soa)}
	}
	return m
}

func TestV250HonoursUpstreamTTL(t *testing.T) {
	c := NewDNSCache(1<<20, 1000, 4) // defaults = production defaults (min-ttl 0)
	if c.minTTL != 0 || c.pinnedFloor != 300*time.Second || c.negMinTTL != 5*time.Second || c.negMaxTTL != 300*time.Second {
		t.Fatalf("defaults: min=%v pinned=%v neg=[%v,%v]", c.minTTL, c.pinnedFloor, c.negMinTTL, c.negMaxTTL)
	}
	for _, tc := range []struct {
		ttl  uint32
		want uint32
	}{{10, 10}, {30, 30}, {0, 5}, {3, 5}, {3600, 3600}, {200000, 86400}} {
		e := c.Set(cacheKey("low.example.", dns.TypeA, dns.ClassINET), aReply("low.example.", tc.ttl, "1.2.3.4"))
		if e.OrigTTL != tc.want {
			t.Errorf("upstream TTL %d cached for %d, want %d", tc.ttl, e.OrigTTL, tc.want)
		}
	}
	// the answer handed to clients carries the real remaining TTL, not 300
	ck := &clock{time.Unix(2e9, 0)}
	c.now = ck.now
	e := c.Set("k", aReply("failover.example.", 20, "1.2.3.4"))
	ck.t = ck.t.Add(7 * time.Second)
	if got := e.Reply(q("failover.example."), ck.now(), false).Answer[0].Header().Ttl; got != 13 {
		t.Fatalf("remaining TTL %d, want 13", got)
	}
	// -min-ttl can still be raised by hand
	c.minTTL = 120 * time.Second
	if e := c.Set("k2", aReply("raised.example.", 10, "1.2.3.4")); e.OrigTTL != 120 {
		t.Fatalf("explicit -min-ttl ignored: %d", e.OrigTTL)
	}
}

func TestV250PinnedFloorOnly(t *testing.T) {
	c := NewDNSCache(1<<20, 1000, 4)
	p := NewPinned([]string{"www.youtube.com"}, []string{"googlevideo.com"})
	c.isPinned = p.Has
	c.minTTLExempt = []string{"googlevideo.com"}
	p.Observe("r1---sn-abc.googlevideo.com")
	if e := c.Set("a", aReply("www.youtube.com.", 20, "1.2.3.4")); e.OrigTTL != 300 {
		t.Fatalf("pinned name: %d, want 300", e.OrigTTL)
	}
	if e := c.Set("b", aReply("WWW.YouTube.com.", 900, "1.2.3.4")); e.OrigTTL != 900 {
		t.Fatalf("pinned name with a long TTL must keep it: %d", e.OrigTTL)
	}
	if e := c.Set("c", aReply("other.example.", 20, "1.2.3.4")); e.OrigTTL != 20 {
		t.Fatalf("unpinned name: %d, want 20", e.OrigTTL)
	}
	// auto-pinned CDN host is also min-TTL-exempt: the exemption wins (CDN failover)
	if e := c.Set("d", aReply("r1---sn-abc.googlevideo.com.", 10, "1.2.3.4")); e.OrigTTL != 10 {
		t.Fatalf("exempt CDN host: %d, want 10", e.OrigTTL)
	}
	c.pinnedFloor = 0
	if e := c.Set("e", aReply("www.youtube.com.", 20, "1.2.3.4")); e.OrigTTL != 20 {
		t.Fatalf("-pinned-min-ttl 0: %d", e.OrigTTL)
	}
}

func TestV250NegativeCachingRFC2308(t *testing.T) {
	c := NewDNSCache(1<<20, 1000, 4)
	for _, tc := range []struct {
		name  string
		rcode int
		soa   string
		want  uint32
	}{
		{"min of TTL and MINIMUM", dns.RcodeNameError, "example. 60 IN SOA ns. host. 1 7200 900 1209600 45", 45},
		{"SOA TTL lower", dns.RcodeNameError, "example. 20 IN SOA ns. host. 1 7200 900 1209600 3600", 20},
		{"clamped to 300", dns.RcodeNameError, "example. 3600 IN SOA ns. host. 1 7200 900 1209600 86400", 300},
		{"clamped to 5", dns.RcodeNameError, "example. 1 IN SOA ns. host. 1 7200 900 1209600 0", 5},
		{"NODATA uses SOA too", dns.RcodeSuccess, "example. 900 IN SOA ns. host. 1 7200 900 1209600 120", 120},
		{"no SOA", dns.RcodeNameError, "", 30},
	} {
		e := c.Set("n|"+tc.name, negReply("nx.example.", tc.rcode, tc.soa))
		if e == nil || !e.Negative || e.OrigTTL != tc.want {
			t.Errorf("%s: got %+v, want negative TTL %d", tc.name, e, tc.want)
		}
	}
	// the negative TTL is not raised by -min-ttl (only by -neg-min-ttl)
	c.minTTL = 300 * time.Second
	if e := c.Set("n2", negReply("nx.example.", dns.RcodeNameError, "example. 60 IN SOA ns. host. 1 7200 900 1209600 45")); e.OrigTTL != 45 {
		t.Fatalf("neg with -min-ttl 300: %d", e.OrigTTL)
	}
}

// Repeated NXDOMAIN lookups are answered from the cache: one upstream query.
func TestV250RepeatedNXDomainCached(t *testing.T) {
	var calls atomic.Int64
	up := NewUpstream(handlerUp(t, func(r *dns.Msg) *dns.Msg {
		calls.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeNameError)
		m.Ns = []dns.RR{rr("example. 60 IN SOA ns. host. 1 7200 900 1209600 40")}
		return m
	}), nil)
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 1000, 4), &Resolver{DoH: []*Upstream{up}}, NewBlocklist(nil, nil, nil))
	for i := 0; i < 5; i++ {
		r, _, _ := s.Handle(q("nope.example."))
		if r.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode %d", r.Rcode)
		}
		if i > 0 && (len(r.Ns) == 0 || r.Ns[0].Header().Ttl > 40) {
			t.Fatalf("cached NXDOMAIN TTL: %v", r.Ns)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("%d upstream queries for 5 identical NXDOMAIN lookups", calls.Load())
	}
}

// ---------- GP-02: singleflight + fast SERVFAIL does not end the race ----------

func TestV250ConcurrentMissesOneUpstreamQuery(t *testing.T) {
	var calls atomic.Int64
	up := NewUpstream(fakeUp(t, 150*time.Millisecond, "9.9.9.9", &calls, nil), nil)
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 1000, 4), &Resolver{DoH: []*Upstream{up}}, NewBlocklist(nil, nil, nil))
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, _, _ := s.Handle(q("burst.example.")); r.Rcode != 0 || len(r.Answer) != 1 {
				t.Errorf("bad answer %v", r)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d upstream queries for 25 concurrent misses", calls.Load())
	}
}

func TestV250FastServfailWaitsForHedgedUpstream(t *testing.T) {
	bad := NewUpstream(handlerUp(t, func(r *dns.Msg) *dns.Msg { m := new(dns.Msg); m.SetRcode(r, dns.RcodeServerFailure); return m }), nil)
	var c atomic.Int64
	good := NewUpstream(fakeUp(t, 60*time.Millisecond, "6.6.6.6", &c, nil), nil)
	// only the SERVFAIL upstream is raced first; the good one would normally join after 2 s
	rs := &Resolver{DoH: []*Upstream{bad, good}, First: 1, Hedge: 2 * time.Second}
	t0 := time.Now()
	r, u, err := rs.Resolve(context.Background(), upstreamQuery(q("sf.example.")))
	if err != nil || u != good || r.Rcode != dns.RcodeSuccess {
		t.Fatalf("u=%v err=%v r=%v", u, err, r)
	}
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("waited for the hedge timer after a SERVFAIL: %v", d)
	}
}

// ---------- GP-03: self-updater off in containers ----------

func TestV250DetectContainer(t *testing.T) {
	none := func(string) bool { return false }
	docker := func(p string) bool { return p == "/.dockerenv" }
	for _, tc := range []struct {
		env    string
		exists func(string) bool
		want   bool
	}{{"", none, false}, {"true", none, true}, {"1", none, true}, {"TRUE", none, true}, {"", docker, true}, {"false", docker, false}, {"no", none, false}} {
		if got := detectContainer(tc.env, tc.exists); got != tc.want {
			t.Errorf("env=%q: %v, want %v", tc.env, got, tc.want)
		}
	}
}

func TestV250ContainerBlocksUpdates(t *testing.T) {
	containerHook = func() bool { return true }
	defer func() { containerHook = nil }()
	u := NewUpdater(&App{}, t.TempDir(), "https://example.invalid/manifest.json", "www.google.com")
	if u.dir != "" || u.url != "" || !u.Status().Container {
		t.Fatalf("container: dir=%q url=%q status=%+v", u.dir, u.url, u.Status())
	}
	mux := http.NewServeMux()
	u.Register(mux)
	for _, p := range []string{"/api/update/upload", "/api/update/rollback", "/api/update/install", "/api/update/check"} {
		r := httptest.NewRequest("POST", p, nil)
		r.RemoteAddr = "192.168.1.50:4000"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var j map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &j)
		if w.Code != http.StatusConflict || j["container"] != true || !strings.Contains(j["error"].(string), "docker compose up -d") {
			t.Fatalf("%s: %d %s", p, w.Code, w.Body.String())
		}
	}
	if err := u.Restart("test"); err == nil || !strings.Contains(err.Error(), "container") {
		t.Fatalf("restart in container: %v", err)
	}
	u.start([]byte("not an exe"), "auto-rollback") // must be a no-op
	if u.busy.Load() || u.Status().State != "idle" {
		t.Fatal("start ran inside a container")
	}
}

// ---------- GP-05: blocked HTTPS / SVCB answer NOERROR NODATA ----------

func TestV250BlockedHTTPSAndSVCBAreNoData(t *testing.T) {
	var calls atomic.Int64
	s := newTestServer(t, "1.1.1.1", &calls, nil)
	s.bl.Enabled = true
	for _, typ := range []uint16{dns.TypeHTTPS, dns.TypeSVCB} {
		m := new(dns.Msg)
		m.SetQuestion("ads.example.", typ)
		m.SetEdns0(1232, false)
		r, res, _ := s.Handle(m)
		if res != "blocked" || r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
			t.Fatalf("type %d: res=%s rcode=%d answers=%d", typ, res, r.Rcode, len(r.Answer))
		}
	}
	if calls.Load() != 0 {
		t.Fatal("blocked query went upstream")
	}
}

// ---------- GP-06: CSRF token on state-changing dashboard requests ----------

func TestV250CSRF(t *testing.T) {
	a, srv, _ := authSrv(t)
	_ = a.Setup("admin", "correct horse")
	lr := post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, "")
	ck := sessionCookie(lr)
	var csrfCk *http.Cookie
	for _, c := range lr.Cookies() {
		switch c.Name {
		case csrfCookie:
			csrfCk = c
		case authCookie:
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				t.Fatal("session cookie must be HttpOnly + SameSite=Strict")
			}
		}
	}
	if csrfCk == nil || csrfCk.HttpOnly || csrfCk.SameSite != http.SameSiteStrictMode || csrfCk.Value != csrfHeaderFor(ck) {
		t.Fatalf("csrf cookie: %+v", csrfCk)
	}
	send := func(tok, origin, sfs string) int {
		req, _ := http.NewRequest("POST", srv.URL+"/api/update/upload", nil)
		req.Header.Set("Cookie", ck)
		if tok != "" {
			req.Header.Set(csrfHeader, tok)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if sfs != "" {
			req.Header.Set("Sec-Fetch-Site", sfs)
		}
		r, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	good := csrfCk.Value
	if c := send("", "", ""); c != 403 {
		t.Fatalf("no token: %d", c)
	}
	if c := send(strings.Repeat("0", len(good)), "", ""); c != 403 {
		t.Fatalf("wrong token: %d", c)
	}
	if c := send(good, "", ""); c != 200 {
		t.Fatalf("right token: %d", c)
	}
	if c := send(good, srv.URL, "same-origin"); c != 200 {
		t.Fatalf("same origin + token: %d", c)
	}
	if c := send(good, "http://evil.example", ""); c != 403 {
		t.Fatalf("cross origin with token: %d", c)
	}
	if c := send(good, "", "cross-site"); c != 403 {
		t.Fatalf("Sec-Fetch-Site cross-site without Origin: %d", c)
	}
	// GETs need no token, and a session from before v2.5.0 (no csrf cookie) gets one
	g := get(t, srv, "/api/stats", ck)
	found := false
	for _, c := range g.Cookies() {
		found = found || (c.Name == csrfCookie && c.Value == good)
	}
	if g.StatusCode != 200 || !found {
		t.Fatalf("GET %d, csrf cookie re-issued=%v", g.StatusCode, found)
	}
	// /api/auth/status exposes the same token to the logged-in page
	st := get(t, srv, "/api/auth/status", ck)
	var j map[string]any
	_ = json.NewDecoder(st.Body).Decode(&j)
	if j["csrf"] != good {
		t.Fatalf("status csrf=%v", j["csrf"])
	}
	// a new login gives a new token; the old token does not work with the new session
	ck2 := sessionCookie(post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, ""))
	if ck2 == ck {
		time.Sleep(1100 * time.Millisecond) // same-second login gives the same expiry
		ck2 = sessionCookie(post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, ""))
	}
	ck = ck2
	if c := send(good, "", ""); c != 403 {
		t.Fatalf("old token accepted for a new session: %d", c)
	}
	// login / logout (public) keep working without a token
	if r := post(t, srv, "/api/auth/logout", "", ""); r.StatusCode != 200 {
		t.Fatalf("logout: %d", r.StatusCode)
	}
}

// The dashboard page wraps fetch so every same-origin POST carries the token.
func TestV250DashboardSendsCSRFHeader(t *testing.T) {
	if !strings.Contains(string(indexHTMLForTest()), `h.set("X-GoProxy-CSRF",tok())`) {
		t.Fatal("index.html no longer adds the CSRF header")
	}
}

func indexHTMLForTest() []byte { b, _ := staticFS.ReadFile("static/index.html"); return b }
