// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// ---------- validation ----------

func TestV251NormalizeServer(t *testing.T) {
	ok := []struct{ in, proto, want string }{
		{"64.6.64.6", "udp", "64.6.64.6:53"},
		{"64.6.65.6:5353", "udp", "64.6.65.6:5353"},
		{"udp://64.6.64.6", "", "64.6.64.6:53"},
		{"2620:74:1b::1:1", "udp", "[2620:74:1b::1:1]:53"},
		{"https://1.1.1.1/dns-query", "doh", "https://1.1.1.1/dns-query"},
		{"https://9.9.9.9", "doh", "https://9.9.9.9/dns-query"},
		{"https://dns.google/dns-query", "", "https://dns.google/dns-query"}, // known bootstrap
		{"tls://dns.quad9.net", "dot", "tls://dns.quad9.net:853"},
		{"9.9.9.9", "dot", "tls://9.9.9.9:853"},
		{"tls://1.1.1.1:8853", "", "tls://1.1.1.1:8853"},
	}
	for _, c := range ok {
		n, err := normalizeDNSServer(UpstreamEntry{Addr: c.in, Proto: c.proto, Enabled: true})
		if err != nil || n.Addr != c.want || n.Name == "" {
			t.Fatalf("%s/%s: %+v %v", c.in, c.proto, n, err)
		}
	}
	if n, _ := normalizeDNSServer(UpstreamEntry{Addr: "64.6.64.6", Proto: "udp"}); n.Name != "UltraDNS Public" {
		t.Fatalf("preset name not filled in: %q", n.Name)
	}
	bad := []UpstreamEntry{
		{Addr: "", Proto: "udp"},
		{Addr: "dns.example.com", Proto: "udp"},                             // UDP needs an IP
		{Addr: "http://1.1.1.1/dns-query", Proto: "doh"},                    // not https
		{Addr: "https://doh.example.net/dns-query", Proto: "doh"},           // name without bootstrap
		{Addr: "https://x.example/dns-query", Proto: "doh", Bootstrap: "a"}, // bad bootstrap
		{Addr: "https://user:pw@1.1.1.1/dns-query", Proto: "doh"},
		{Addr: "tls://dot.example.org", Proto: "dot"},
		{Addr: "https://1.1.1.1/dns-query", Proto: "dot"},
		{Addr: "1.1.1.1", Proto: "ftp"},
		{Addr: "0.0.0.0", Proto: "udp"},
		{Addr: "127.0.0.1:53", Proto: "udp"}, // GoProxy itself
		{Addr: "1.1.1.1:99999", Proto: "udp"},
		{Addr: "1.1.1.1", Proto: "udp", Name: strings.Repeat("x", 60)},
		{Addr: "1.1.1.1", Proto: "udp", Name: "bad\x07name"},
	}
	for _, d := range bad {
		if _, err := normalizeDNSServer(d); err == nil {
			t.Fatalf("accepted %+v", d)
		}
	}
	// a name with bootstrap IPs is fine
	if _, err := normalizeDNSServer(UpstreamEntry{Addr: "https://doh.example.net/dns-query", Proto: "doh", Bootstrap: "192.0.2.1, 192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
}

func TestV251NormalizeList(t *testing.T) {
	if _, err := normalizeDNSServers(nil); err == nil {
		t.Fatal("empty list accepted")
	}
	if _, err := normalizeDNSServers([]UpstreamEntry{{Addr: "1.1.1.1", Proto: "udp"}}); err == nil {
		t.Fatal("list with nothing enabled accepted")
	}
	if _, err := normalizeDNSServers([]UpstreamEntry{{Addr: "64.6.64.6", Proto: "udp", Enabled: true}, {Addr: "64.6.64.6:53", Proto: "udp"}}); err == nil {
		t.Fatal("duplicate accepted")
	}
	var many []UpstreamEntry
	for i := 0; i < maxDNSServers+1; i++ {
		many = append(many, UpstreamEntry{Addr: net.IPv4(192, 0, 2, byte(i+1)).String(), Proto: "udp", Enabled: true})
	}
	if _, err := normalizeDNSServers(many); err == nil {
		t.Fatal("too many accepted")
	}
	if err := validateSettings(&Settings{DNSServers: []UpstreamEntry{{Addr: "nope", Proto: "udp", Enabled: true}}}); err == nil {
		t.Fatal("validateSettings must check dns_servers")
	}
}

// ---------- defaults: Cloudflare + Quad9 interleaved, UltraDNS Public enabled at the bottom ----------

func TestV251DefaultsIncludeUltraDNSAtBottom(t *testing.T) {
	const oldDoH = "https://1.1.1.1/dns-query,https://9.9.9.9/dns-query,https://1.0.0.1/dns-query,https://149.112.112.112/dns-query"
	l := defaultDNSServers(oldDoH, Settings{})
	if len(l) != 6 {
		t.Fatalf("%+v", l)
	}
	if providerOf(l[0].Addr) == providerOf(l[1].Addr) {
		t.Fatalf("the two raced first should be different providers: %s %s", l[0].Addr, l[1].Addr)
	}
	for i, want := range []string{"64.6.64.6:53", "64.6.65.6:53"} {
		d := l[4+i]
		if d.Addr != want || d.Proto != "udp" || !d.Enabled || !strings.HasPrefix(d.Name, "UltraDNS Public") {
			t.Fatalf("ultradns %d: %+v", i, d)
		}
	}
	for _, d := range l[:4] {
		if d.Proto != "doh" || !d.Enabled {
			t.Fatalf("default must stay encrypted on top: %+v", d)
		}
	}
	// presets / ECS feed the defaults; UltraDNS is still appended once
	l = defaultDNSServers(defaultDoH, Settings{UpstreamSet: cfA + "," + googleA, Quad9ECS: true})
	if l[0].Addr != cfA || l[len(l)-1].Addr != "64.6.65.6:53" {
		t.Fatalf("%+v", l)
	}
	// the preset list knows UltraDNS as unencrypted UDP (it has no DoH/DoT)
	p, ok := presetByID("ultradns-1")
	if !ok || p.Encrypted || p.Proto != "udp" || p.Addr != "64.6.64.6:53" || !strings.Contains(p.Note, "Unencrypted") {
		t.Fatalf("%+v", p)
	}
}

func TestV251EffectiveServersFallsBackToDefaults(t *testing.T) {
	l, src, warn := effectiveServers(defaultDoH, Settings{}, false)
	if src != "default" || warn != "" || len(l) != 4 {
		t.Fatal(src, warn, l)
	}
	broken := Settings{DNSServers: []UpstreamEntry{{Addr: "not an ip", Proto: "udp", Enabled: true}}}
	l, src, warn = effectiveServers(defaultDoH, broken, false)
	if src != "default" || warn == "" || len(l) != 4 {
		t.Fatal("broken list must fall back to the defaults", src, warn)
	}
	off := Settings{DNSServers: []UpstreamEntry{{Addr: "1.1.1.1", Proto: "udp"}}}
	if _, src, warn = effectiveServers(defaultDoH, off, false); src != "default" || warn == "" {
		t.Fatal("all-disabled list must fall back to the defaults")
	}
	good := Settings{DNSServers: []UpstreamEntry{{Addr: "64.6.64.6", Proto: "udp", Enabled: true}, {Addr: cfA, Proto: "doh", Enabled: true}}}
	if l, src, _ = effectiveServers(defaultDoH, good, false); src != "custom" || l[0].Addr != "64.6.64.6:53" {
		t.Fatal(src, l)
	}
	if l, src, _ = effectiveServers("https://9.9.9.9/dns-query", good, true); src != "flag" || len(l) != 1 {
		t.Fatal("an explicit -upstreams flag wins", src, l)
	}
}

// ---------- priority drives the race ----------

func warm(u *Upstream, ms int) {
	for i := 0; i < 10; i++ {
		u.record(outOK, time.Duration(ms)*time.Millisecond)
	}
}

func TestV251PriorityDecidesWhoIsRacedFirst(t *testing.T) {
	var ca, cb atomic.Int64
	a := NewUpstream(fakeUp(t, 30*time.Millisecond, "1.0.0.1", &ca, nil), nil)
	b := NewUpstream(fakeUp(t, 0, "2.0.0.2", &cb, nil), nil)
	warm(a, 400) // a looks slow, b looks fast: score mode would race b first
	warm(b, 5)
	rs := &Resolver{DoH: []*Upstream{a, b}, First: 1, Hedge: 2 * time.Second}
	if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("score.example."))); err != nil || u != b {
		t.Fatalf("score mode: %v %v", u, err)
	}
	rs.Priority.Store(true)
	if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("prio.example."))); err != nil || u != a {
		t.Fatalf("priority mode must race the top entry first: %v %v", u, err)
	}
	// swap the order live: now b is first
	rs.SetUpstreams([]*Upstream{b, a})
	if _, u, _ := rs.Resolve(context.Background(), upstreamQuery(q("prio2.example."))); u != b {
		t.Fatalf("after reorder: %v", u)
	}
	// a breaker-open top entry is skipped while a healthy one exists
	rs.SetUpstreams([]*Upstream{a, b})
	a.brkUntil.Store(time.Now().Add(time.Minute).UnixNano())
	if o := rs.order(); len(o) != 1 || o[0] != b {
		t.Fatalf("order with breaker open: %v", o)
	}
}

// Plain UDP entries below the raced-first ones are fallbacks only: never hedged in.
func TestV251UnencryptedBelowTopIsFallbackOnly(t *testing.T) {
	var ca, cb atomic.Int64
	var fail atomic.Bool
	a := NewUpstream(fakeUp(t, 80*time.Millisecond, "1.0.0.1", &ca, &fail), nil)
	b := NewUpstream(fakeUp(t, 0, "64.6.64.6", &cb, nil), nil)
	rs := &Resolver{DoH: []*Upstream{a, b}, First: 1, Hedge: 10 * time.Millisecond}
	rs.Priority.Store(true)
	if _, u, err := rs.Resolve(context.Background(), upstreamQuery(q("fb1.example."))); err != nil || u != a {
		t.Fatalf("%v %v", u, err)
	}
	if cb.Load() != 0 {
		t.Fatal("an unencrypted server below the top was hedged in")
	}
	fail.Store(true) // the top one answers SERVFAIL: the fallback must answer
	r, u, err := rs.Resolve(context.Background(), upstreamQuery(q("fb2.example.")))
	if err != nil || u != b || r.Rcode != dns.RcodeSuccess || cb.Load() != 1 {
		t.Fatalf("fallback: u=%v err=%v calls=%d", u, err, cb.Load())
	}
	raced, fb := rs.split([]*Upstream{a, b}, 1)
	if len(raced) != 1 || len(fb) != 1 {
		t.Fatal(raced, fb)
	}
	// moved to the top it is a primary
	raced, _ = rs.split([]*Upstream{b, a}, 1)
	if raced[0] != b {
		t.Fatal("top entry must be raced")
	}
}

// ---------- live apply through the API, history, persistence, export/import ----------

func dnsTestV24(t *testing.T) (*V24, *settingsStore, *atomic.Int64, string) {
	s, st, au := adsServer(t)
	s.flight = NewFlight(16, time.Minute, t.TempDir())
	s.alerts = NewAlerts(st, nil)
	s.alerts.toast = nil
	var calls atomic.Int64
	addr := fakeUp(t, 0, "6.4.6.4", &calls, nil)
	v := &V24{s: s, audit: au, manageUpstreams: true, upFlag: defaultDoH, explicit: map[string]bool{}}
	return v, st, &calls, addr
}

func callJSON(h http.HandlerFunc, method string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, "/", rd)
	r.RemoteAddr = "192.168.1.5:1234"
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestV251DNSServersAPI(t *testing.T) {
	v, st, calls, fake := dnsTestV24(t)
	res := v.s.res
	// GET: defaults with UltraDNS at the bottom
	w := callJSON(v.serveDNSServers, "GET", nil)
	var view struct {
		Servers []dnsServerView `json:"servers"`
		Source  string          `json:"source"`
		Custom  bool            `json:"custom"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &view)
	if w.Code != 200 || view.Source != "default" || view.Custom || view.Servers[len(view.Servers)-1].Addr != "tls://8.8.8.8:853" {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	// add a server and move it to the top: applied live, no restart
	list := []UpstreamEntry{{Name: "Test UDP", Addr: fake, Proto: "udp", Enabled: true}, {Addr: cfA, Proto: "doh", Enabled: true}, {Addr: "64.6.64.6", Proto: "udp", Enabled: false}}
	w = callJSON(v.serveDNSServers, "POST", map[string]any{"servers": list})
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	ups := res.Ups()
	if len(ups) != 2 || ups[0].URL != fake || ups[0].Label() != "Test UDP" || ups[1].URL != cfA || !res.Priority.Load() {
		t.Fatalf("live list: %v", ups)
	}
	r, u, err := res.Resolve(context.Background(), upstreamQuery(q("live.example.")))
	if err != nil || u.URL != fake || r.Answer[0].(*dns.A).A.String() != "6.4.6.4" || calls.Load() != 1 {
		t.Fatalf("answer did not come through the top server: %v %v", u, err)
	}
	top := ups[0]
	// reorder: the Upstream object (and its stats) is reused
	list[0], list[1] = list[1], list[0]
	if w = callJSON(v.serveDNSServers, "POST", map[string]any{"servers": list}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if ups = res.Ups(); ups[1] != top || ups[0].URL != cfA || top.Wins.Load() != 1 {
		t.Fatal("reorder must keep the existing upstream and its stats")
	}
	// rejected: nothing enabled / bad address; the running list is unchanged
	for _, badList := range [][]UpstreamEntry{{{Addr: fake, Proto: "udp"}}, {{Addr: "dns.example", Proto: "udp", Enabled: true}}, {}} {
		if w = callJSON(v.serveDNSServers, "POST", map[string]any{"servers": badList}); w.Code != 400 {
			t.Fatalf("bad list accepted: %v", badList)
		}
	}
	if len(res.Ups()) != 2 {
		t.Fatal("a rejected save changed the live list")
	}
	// persisted in the data dir and survives a reload (restart)
	st2 := &settingsStore{path: st.path}
	s2, _ := st2.Load()
	if len(s2.DNSServers) != 3 || s2.DNSServers[1].Addr != fake || s2.DNSServers[2].Enabled {
		t.Fatalf("not persisted: %+v", s2.DNSServers)
	}
	l, src, _ := effectiveServers(defaultDoH, s2, false)
	if src != "custom" || l[0].Addr != cfA {
		t.Fatal("reloaded list not used")
	}
	// history (revertable) + audit
	h := st.History()
	if len(h) < 2 || !strings.Contains(strings.Join(h[len(h)-1].Diff, ";"), "dns_servers") {
		t.Fatalf("history: %+v", h)
	}
	// remove the test server
	if w = callJSON(v.serveDNSServers, "POST", map[string]any{"servers": list[:1]}); w.Code != 200 || len(res.Ups()) != 1 || res.Ups()[0].URL != cfA {
		t.Fatal("remove failed", w.Body.String())
	}
	// reset: back to the defaults
	if w = callJSON(v.serveDNSServersReset, "POST", nil); w.Code != 200 || len(st.Get().DNSServers) != 0 || len(res.Ups()) != 4 {
		t.Fatalf("reset: %d %d", w.Code, len(res.Ups()))
	}
	// a preset also replaces a custom list, live
	_ = callJSON(v.serveDNSServers, "POST", map[string]any{"servers": []UpstreamEntry{{Addr: fake, Proto: "udp", Enabled: true}}})
	_, _, err = st.Update("t", "preset", func(s *Settings) error { _, e := applyPreset(s, "reliability", nil); return e })
	if err != nil {
		t.Fatal(err)
	}
	_ = v.applyLive(st.Get())
	if ups = res.Ups(); len(ups) != 5 || ups[0].URL != cfA {
		t.Fatalf("preset not applied live: %v", ups)
	}
	if restartNeeded(Settings{}, Settings{DNSServers: list, UpstreamSet: cfA, Quad9ECS: true, ExtraUpstream: googleA}) {
		t.Fatal("upstream changes apply live: no restart needed")
	}
}

func TestV251GenericSettingsSaveAndRevertApplyLive(t *testing.T) {
	v, st, _, fake := dnsTestV24(t)
	w := callJSON(v.serveSettings, "POST", map[string]any{"dns_servers": []UpstreamEntry{{Addr: fake, Proto: "udp", Enabled: true}}})
	if w.Code != 200 || v.s.res.Ups()[0].URL != fake {
		t.Fatal(w.Body.String())
	}
	h := st.History()
	if w = callJSON(v.serveRevert, "POST", map[string]any{"id": h[len(h)-1].ID}); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if len(v.s.res.Ups()) != 4 {
		t.Fatal("revert not applied live")
	}
	if w = callJSON(v.serveSettings, "POST", map[string]any{"dns_servers": []UpstreamEntry{{Addr: fake, Proto: "udp"}}}); w.Code != 400 {
		t.Fatal("no enabled server accepted via /api/settings")
	}
}

func TestV251ExportImportIncludesDNSServers(t *testing.T) {
	v, st, _, fake := dnsTestV24(t)
	_ = callJSON(v.serveDNSServers, "POST", map[string]any{"servers": []UpstreamEntry{{Name: "Mine", Addr: fake, Proto: "udp", Enabled: true}, {Addr: "64.6.64.6", Proto: "udp", Enabled: true}}})
	b := exportSettings(st.Get(), nil)
	raw, _ := json.Marshal(b)
	if !strings.Contains(string(raw), `"dns_servers"`) || !strings.Contains(string(raw), "64.6.64.6:53") {
		t.Fatal("export misses dns_servers")
	}
	_ = callJSON(v.serveDNSServersReset, "POST", nil)
	var back settingsBackup
	_ = json.Unmarshal(raw, &back)
	if _, err := v.importSettings(back, false, "t"); err != nil {
		t.Fatal(err)
	}
	if ups := v.s.res.Ups(); len(ups) != 2 || ups[0].Label() != "Mine" {
		t.Fatalf("import not applied live: %v", ups)
	}
	back.Settings.DNSServers = []UpstreamEntry{{Addr: "bogus host", Proto: "udp", Enabled: true}}
	if _, err := v.importSettings(back, false, "t"); err == nil {
		t.Fatal("broken dns_servers imported")
	}
}

// ---------- the endpoints need the CSRF token like every other change ----------

func TestV251DNSServersCSRF(t *testing.T) {
	v, _, _, fake := dnsTestV24(t)
	a := NewAuth(filepath.Join(t.TempDir(), "goproxy-auth.json"))
	mux := http.NewServeMux()
	a.Register(mux)
	mux.HandleFunc("/api/dns-servers", v.serveDNSServers)
	mux.HandleFunc("/api/dns-servers/reset", v.serveDNSServersReset)
	srv := httptest.NewServer(a.Middleware(mux))
	defer srv.Close()
	_ = a.Setup("admin", "correct horse")
	lr, _ := http.Post(srv.URL+"/api/auth/login", "application/json", strings.NewReader(`{"username":"admin","password":"correct horse"}`))
	ck := sessionCookie(lr)
	_, val, _ := strings.Cut(ck, "=")
	tok := a.csrfFor(val)
	body := `{"servers":[{"addr":"` + fake + `","proto":"udp","enabled":true}]}`
	send := func(path, tok string) int {
		req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
		req.Header.Set("Cookie", ck)
		if tok != "" {
			req.Header.Set(csrfHeader, tok)
		}
		r, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.StatusCode
	}
	if c := send("/api/dns-servers", ""); c != 403 {
		t.Fatalf("no token: %d", c)
	}
	if c := send("/api/dns-servers/reset", "bad"); c != 403 {
		t.Fatalf("bad token: %d", c)
	}
	if c := send("/api/dns-servers", tok); c != 200 {
		t.Fatalf("with token: %d", c)
	}
	if r, _ := http.Get(srv.URL + "/api/dns-servers"); r.StatusCode != 401 && r.StatusCode != 403 {
		t.Fatalf("GET without login: %d", r.StatusCode)
	}
}

// ---------- DNS-over-TLS client ----------

func TestV251DoTClient(t *testing.T) {
	hs := httptest.NewUnstartedServer(http.NotFoundHandler())
	hs.StartTLS() // only for its 127.0.0.1 certificate
	defer hs.Close()
	cert := hs.TLS.Certificates[0]
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	conns := map[string]bool{}
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		mu.Lock()
		conns[w.RemoteAddr().String()] = true
		mu.Unlock()
		m := aReply(r.Question[0].Name, 60, "8.5.3.8")
		m.Id = r.Id
		_ = w.WriteMsg(m)
	})}
	go srv.ActivateAndServe()
	defer srv.Shutdown()
	d := UpstreamEntry{Name: "Local DoT", Addr: "tls://" + ln.Addr().String(), Proto: "dot", Enabled: true}
	n, err := normalizeDNSServer(d)
	if err != nil {
		t.Fatal(err)
	}
	up := newUpstreamFor(n, nil)
	pool := x509.NewCertPool()
	pool.AddCert(hs.Certificate())
	up.dot.cfg.RootCAs = pool
	if !up.Encrypted() || up.Proto() != "DoT" {
		t.Fatal("DoT upstream must count as encrypted")
	}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		r, err := up.Exchange(ctx, upstreamQuery(q("dot.example.")))
		cancel()
		if err != nil || r.Answer[0].(*dns.A).A.String() != "8.5.3.8" {
			t.Fatalf("query %d: %v", i, err)
		}
	}
	mu.Lock()
	n2 := len(conns)
	mu.Unlock()
	if n2 != 1 {
		t.Fatalf("DoT connection not reused: %d connections", n2)
	}
	// a wrong certificate is refused
	bad := newUpstreamFor(n, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := bad.Exchange(ctx, upstreamQuery(q("dot.example."))); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	up.closeIdle()
}

// ---------- benchmark and UI ----------

func TestV251BenchIncludesUltraDNS(t *testing.T) {
	b := NewBench("", func() []string { return []string{cfA, "64.6.64.6:53", "192.0.2.53:53"} })
	var udp, doh, cur int
	for _, x := range b.targets(false) {
		if x.row.Provider == "UltraDNS" {
			if x.row.Proto == "UDP" {
				udp++
			} else {
				doh++
			}
		}
		if x.row.Current && x.row.Addr == "64.6.64.6:53" {
			cur++
		}
		if x.row.Addr == "192.0.2.53:53" && x.row.Proto != "UDP" {
			t.Fatal("a current UDP server must be benchmarked as UDP")
		}
	}
	if udp != 2 || doh != 0 || cur != 1 {
		t.Fatalf("ultradns rows: udp=%d doh=%d current=%d", udp, doh, cur)
	}
}

func TestV251DashboardHasDNSServers(t *testing.T) {
	js, _ := staticFS.ReadFile("static/v24.js")
	for _, want := range []string{`api("/api/dns-servers")`, `post("/api/dns-servers",{servers:dnsL})`, `/api/dns-servers/reset`, `help("v24dns","DNS Servers"`, `data-dnsup`, `data-dnsdn`, `draggable="true"`, `unencrypted`} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("v24.js lacks %s", want)
		}
	}
	// the Advanced/Devices "?" help texts live in v24.js: the page must share its HELP table
	if !strings.Contains(string(indexHTMLForTest()), "const HELP=window.HELP={") {
		t.Fatal("index.html must expose HELP to v24.js")
	}
}
