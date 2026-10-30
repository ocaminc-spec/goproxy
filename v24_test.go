// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func newStore(t *testing.T) *settingsStore {
	st := &settingsStore{path: filepath.Join(t.TempDir(), "goproxy-settings.json")}
	_, _ = st.Load()
	return st
}

func freeDNSAddr(t *testing.T) string {
	for i := 0; i < 20; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		ln, err := net.Listen("tcp", addr)
		pc.Close()
		if err == nil {
			ln.Close()
			return addr
		}
	}
	t.Fatal("no free port")
	return ""
}

// ---------- item 0: the hang ----------

func TestRunValueNeverGetsInternalFlags(t *testing.T) {
	got := filterArgs([]string{"-takeover", "-cache-gb", "8", "-stop", "--service-restart", "-min-ttl=300s"})
	if strings.Join(got, " ") != "-cache-gb 8 -min-ttl=300s" {
		t.Fatalf("filterArgs: %q", got)
	}
	v, changed := cleanedRunValue(`"C:\GoProxyDNS\goproxy.exe" -cache-gb 8 -takeover`)
	if !changed || v != `"C:\GoProxyDNS\goproxy.exe" -cache-gb 8` {
		t.Fatalf("cleaned: %q %v", v, changed)
	}
	if _, changed := cleanedRunValue(`"C:\GoProxyDNS\goproxy.exe" -tray`); changed {
		t.Fatal("-tray must be kept (service-mode tray entry)")
	}
	v, _ = cleanedRunValue(`C:\GoProxyDNS\goproxy.exe -takeover -update-dir "C:\My Updates"`)
	if v != `C:\GoProxyDNS\goproxy.exe -update-dir "C:\My Updates"` {
		t.Fatalf("quoted arg: %q", v)
	}
	if a := childArgsFrom([]string{"-takeover", "-cache-gb", "8"}); strings.Count(strings.Join(a, " "), "-takeover") != 1 {
		t.Fatalf("child args: %q", a)
	}
}

func TestSharedPCCloseIgnoredUntilShutdown(t *testing.T) {
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pc := &sharedPC{PacketConn: raw}
	_ = pc.Close() // what miekg/dns does on a non-temporary read error
	if _, err := net.Dial("udp", raw.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}
	_ = raw.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 10)
	if _, _, err := pc.ReadFrom(buf); err == nil || strings.Contains(err.Error(), "closed") {
		t.Fatalf("socket should still be open (want timeout), got %v", err)
	}
	pc.shutdown()
	if _, _, err := pc.ReadFrom(buf); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("after shutdown the socket must be closed: %v", err)
	}
}

func TestWatchdogStep(t *testing.T) {
	var fail atomic.Bool
	var recovers, escalates, dumps int
	now := time.Unix(1e9, 0)
	w := NewWatchdog()
	w.now = func() time.Time { return now }
	w.started = now.Add(-time.Hour)
	w.Check = func() error {
		if fail.Load() {
			return errors.New("dns udp: timeout")
		}
		return nil
	}
	fixOnRecover := true
	w.Recover = func(string) error {
		recovers++
		if fixOnRecover {
			fail.Store(false)
		}
		return nil
	}
	w.Escalate = func(string) { escalates++ }
	w.Dump = func(string) { dumps++ }

	fail.Store(true)
	w.Step("")
	w.Step("")
	if recovers != 0 {
		t.Fatal("must wait for 3 failures")
	}
	w.Step("")
	if recovers != 1 || escalates != 0 || dumps != 1 || w.View().Fails != 0 {
		t.Fatalf("recover=%d esc=%d dumps=%d view=%+v", recovers, escalates, dumps, w.View())
	}
	// a listener reported death: act on the first failure
	fail.Store(true)
	w.Step("dns udp listener stopped")
	if recovers != 2 {
		t.Fatal("wake should act at once")
	}
	// re-bind does not help -> escalate
	fixOnRecover = false
	fail.Store(true)
	w.Step("x")
	if escalates != 1 {
		t.Fatalf("expected escalation, got %d", escalates)
	}
	// paused (update handover) resets the count and never acts
	w.Paused = func() bool { return true }
	w.Step("")
	w.Step("")
	w.Step("")
	if escalates != 1 || w.View().Fails != 0 {
		t.Fatal("paused watchdog acted")
	}
	// grace after start
	w.Paused = nil
	w.started = now
	w.Step("")
	if w.View().Fails != 0 {
		t.Fatal("grace period ignored")
	}
}

func TestWatchdogTooManyRecoveriesEscalates(t *testing.T) {
	now := time.Unix(1e9, 0)
	w := NewWatchdog()
	w.now = func() time.Time { return now }
	w.started = now.Add(-time.Hour)
	var fail atomic.Bool
	w.Check = func() error {
		if fail.Load() {
			return errors.New("down")
		}
		return nil
	}
	rec, esc := 0, 0
	w.Recover = func(string) error { rec++; fail.Store(false); return nil }
	w.Escalate = func(string) { esc++ }
	for i := 0; i < 4; i++ {
		fail.Store(true)
		w.Step("died")
		now = now.Add(time.Minute)
	}
	if rec != 3 || esc != 1 {
		t.Fatalf("rec=%d esc=%d (the 4th incident in 10 min must restart the process)", rec, esc)
	}
}

// End to end: a DNS listener dies on its own (as the shared UDP socket did on Windows),
// the death is reported, the self-check fails, and the watchdog's re-bind brings DNS back.
func TestListenerDeathDetectedAndRecovered(t *testing.T) {
	s := zoneServer(t, nil)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/version", serveVersion)
	a := &App{s: s, dnsAddr: freeDNSAddr(t), httpAddr: freeDNSAddr(t), listeners: 1, mux: mux, died: make(chan string, 4)}
	if err := a.bindAll(2 * time.Second); err != nil {
		t.Fatal(err)
	}
	defer func() { a.unbindDNS(); a.unbindHTTP() }()
	if err := selfCheck(a.dnsAddr, a.httpAddr); err != nil {
		t.Fatalf("fresh listeners: %v", err)
	}
	a.mu.Lock()
	udp := a.dns.servers[0]
	a.mu.Unlock()
	_ = udp.Shutdown() // the serve loop ends without GoProxy asking for it
	select {
	case r := <-a.died:
		if !strings.Contains(r, "udp") {
			t.Fatalf("reason: %s", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("listener death was not reported")
	}
	if err := selfCheck(a.dnsAddr, a.httpAddr); err == nil {
		t.Fatal("self-check should fail with UDP down")
	}
	w := NewWatchdog()
	w.started = time.Now().Add(-time.Hour)
	w.Check = func() error { return selfCheck(a.dnsAddr, a.httpAddr) }
	w.Recover = a.recoverListeners
	escalated := false
	w.Escalate = func(string) { escalated = true }
	w.Step("dns udp listener stopped")
	if escalated {
		t.Fatalf("re-bind should have recovered: %+v", w.View())
	}
	if err := selfCheck(a.dnsAddr, a.httpAddr); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestSelfTestNameNotCounted(t *testing.T) {
	s := newTestServer(t, "1.2.3.4", new(atomic.Int64), nil)
	r, res, _ := s.Handle(qt(selfTestName, dns.TypeTXT, false, false))
	if res != "local" || len(r.Answer) != 1 || s.stats.Queries.Load() != 0 {
		t.Fatalf("res=%s answers=%d queries=%d", res, len(r.Answer), s.stats.Queries.Load())
	}
}

// ---------- item 2: IP change ----------

func TestClassifyIP(t *testing.T) {
	lan := func(name, ip string) ifaceAddr {
		return ifaceAddr{Name: name, Up: true, IPs: []net.IP{net.ParseIP(ip)}}
	}
	cases := []struct {
		ifs  []ifaceAddr
		exp  string
		want string
	}{
		{[]ifaceAddr{lan("Wi-Fi", "192.168.1.127")}, "192.168.1.127", "ok"},
		{[]ifaceAddr{lan("Wi-Fi", "192.168.1.140")}, "192.168.1.127", "changed"},
		{[]ifaceAddr{lan("vEthernet (WSL)", "172.20.0.1")}, "192.168.1.127", "no_lan"},
		{[]ifaceAddr{lan("Wi-Fi", "192.168.1.127"), lan("Ethernet", "192.168.1.50")}, "192.168.1.127", "ok"},
		{[]ifaceAddr{{Name: "Wi-Fi", Up: false, IPs: []net.IP{net.ParseIP("192.168.1.127")}}}, "192.168.1.127", "no_lan"},
		{[]ifaceAddr{lan("Wi-Fi", "8.8.8.8")}, "192.168.1.127", "no_lan"},
	}
	for i, c := range cases {
		if got, _ := classifyIP(c.ifs, c.exp); got != c.want {
			t.Errorf("case %d: %s want %s", i, got, c.want)
		}
	}
}

func TestIPWatchDebounceLearnAndAccept(t *testing.T) {
	st := newStore(t)
	al := NewAlerts(st, nil)
	al.toast = nil
	cur := "192.168.1.127"
	w := NewIPWatch(st, al, NewOutages("", st, al))
	w.list = func() []ifaceAddr { return []ifaceAddr{{Name: "Wi-Fi", Up: true, IPs: []net.IP{net.ParseIP(cur)}}} }
	for i := 0; i < 3; i++ {
		w.Sample()
	}
	if st.Get().ExpectedIP != "192.168.1.127" {
		t.Fatalf("not learned: %q", st.Get().ExpectedIP)
	}
	cur = "192.168.1.140"
	w.Sample()
	w.Sample()
	if len(al.Active()) != 0 {
		t.Fatal("alert before debounce")
	}
	w.Sample()
	if a := al.Active(); len(a) != 1 || a[0].Key != "ip-change" || !strings.Contains(a[0].Message, "192.168.1.140") {
		t.Fatalf("alerts: %+v", a)
	}
	if _, err := w.Accept("test"); err != nil || st.Get().ExpectedIP != "192.168.1.140" || len(al.Active()) != 0 {
		t.Fatalf("accept: %v %q %+v", err, st.Get().ExpectedIP, al.Active())
	}
}

// ---------- ntfy ----------

func TestNtfyOffByDefaultAndDelivery(t *testing.T) {
	var mu sync.Mutex
	var reqs []*http.Request
	var bodies []string
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		reqs = append(reqs, r)
		bodies = append(bodies, string(b))
		code := status
		mu.Unlock()
		w.WriteHeader(code)
	}))
	defer srv.Close()
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	n := NewNtfy(nil)
	n.backoff = time.Millisecond
	st := Settings{NtfyServer: srv.URL, NtfyTopic: "secret-topic-123", NtfyToken: "tk_SECRET"}
	if n.Send(st, "k", "t", "m", true) || len(reqs) != 0 {
		t.Fatal("ntfy is off by default: nothing may be sent")
	}
	// alerts with ntfy on but this kind not opted in: nothing either
	store := newStore(t)
	_ = store.Save(Settings{NtfyOn: true, NtfyServer: srv.URL, NtfyTopic: "secret-topic-123"})
	al := NewAlerts(store, n)
	al.toast = nil
	al.Raise(Alert{Key: "q", Kind: "quiet", Title: "Quiet"})
	time.Sleep(50 * time.Millisecond)
	if len(reqs) != 0 {
		t.Fatal("kind not opted in, but sent")
	}
	st.NtfyOn = true
	if !n.Send(st, "k", "Title here", "hello", true) {
		t.Fatal("send failed")
	}
	r := reqs[0]
	if r.URL.Path != "/secret-topic-123" || r.Header.Get("Title") != "Title here" || r.Header.Get("Priority") != "high" || r.Header.Get("Authorization") != "Bearer tk_SECRET" || bodies[0] != "hello" {
		t.Fatalf("request: %s %v %q", r.URL.Path, r.Header, bodies[0])
	}
	if n.Send(st, "k", "again", "x", false) {
		t.Fatal("rate limit: one push per key per 30 min")
	}
	status = 500
	if n.Send(st, "other", "t", "m", false) {
		t.Fatal("500 must not count as delivered")
	}
	if len(reqs) != 4 {
		t.Fatalf("expected 3 tries on failure, total requests %d", len(reqs))
	}
	if strings.Contains(logs.String(), "tk_SECRET") || strings.Contains(logs.String(), "secret-topic-123") {
		t.Fatalf("token or topic leaked into the log: %s", logs.String())
	}
}

// ---------- settings history / audit ----------

func TestSettingsHistoryDiffRevertAndAudit(t *testing.T) {
	st := newStore(t)
	dir := filepath.Dir(st.path)
	au := NewAudit(filepath.Join(dir, "goproxy-audit.jsonl"), func() int { return 90 })
	st.audit = au.Add
	if _, diff, err := st.Update("10.0.0.2", "ntfy", func(s *Settings) error { s.NtfyToken = "tk_x"; s.NtfyTopic = "abc"; return nil }); err != nil || len(diff) != 2 {
		t.Fatalf("%v %v", diff, err)
	}
	if _, _, err := st.Update("10.0.0.2", "features", func(s *Settings) error { s.Features = map[string]bool{"canary": false}; return nil }); err != nil {
		t.Fatal(err)
	}
	h := st.History()
	if len(h) != 2 {
		t.Fatalf("history %d", len(h))
	}
	all, _ := json.Marshal(h)
	if strings.Contains(strings.Join(h[0].Diff, " "), "tk_x") {
		t.Fatal("token in diff")
	}
	_ = all
	if !strings.Contains(strings.Join(h[1].Diff, " "), "features.canary") {
		t.Fatalf("feature=false not in diff: %v", h[1].Diff)
	}
	if st.Get().Feature("canary") {
		t.Fatal("feature switch")
	}
	if _, err := st.Revert(h[1].ID, "10.0.0.2"); err != nil || !st.Get().Feature("canary") {
		t.Fatalf("revert: %v", err)
	}
	if len(st.History()) != 3 {
		t.Fatal("revert must be recorded too")
	}
	last := au.Last(10)
	if len(last) < 3 {
		t.Fatalf("audit: %+v", last)
	}
	if fi, err := os.Stat(filepath.Join(dir, "goproxy-audit.jsonl")); err != nil || (fi.Mode().Perm()&0o077) != 0 {
		t.Fatalf("audit file must be private: %v %v", fi.Mode(), err)
	}
	if fi, _ := os.Stat(st.path); fi.Mode().Perm()&0o077 != 0 {
		t.Fatal("settings file must be private (holds the ntfy token)")
	}
}

func TestValidateSettings(t *testing.T) {
	bad := []Settings{
		{ExpectedIP: "8.8.8.8"},
		{NtfyOn: true},
		{NtfyTopic: "has space"},
		{Features: map[string]bool{"nope": true}},
		{LocalNames: map[string]string{"nas.home": "not-an-ip"}},
		{UpstreamSet: "http://1.1.1.1/dns-query"},
		{UpstreamSet: "https://unknown.example/dns-query"},
	}
	for i, s := range bad {
		if validateSettings(&s) == nil {
			t.Errorf("case %d should fail", i)
		}
	}
	good := Settings{ExpectedIP: "192.168.1.127", NtfyOn: true, NtfyTopic: "abc_DEF-1", LocalNames: map[string]string{"nas.home": "192.168.1.123"}, UpstreamSet: "https://1.1.1.1/dns-query,https://unfiltered.adguard-dns.com/dns-query"}
	if err := validateSettings(&good); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamList(t *testing.T) {
	const oldDoH = "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query,https://9.9.9.9/dns-query,https://149.112.112.112/dns-query" // v2.5.1 defaults
	if l := upstreamList(oldDoH, Settings{Quad9ECS: true}, false); strings.Join(l, ",") != "https://1.1.1.1/dns-query,https://1.0.0.1/dns-query,"+quad9ECS {
		t.Fatalf("ecs: %v", l)
	}
	if l := upstreamList(oldDoH, Settings{Quad9ECS: true}, true); len(l) != 4 || strings.Contains(strings.Join(l, ","), "dns11") {
		t.Fatalf("an explicit -upstreams must win: %v", l)
	}
	if l := upstreamList(oldDoH, Settings{UpstreamSet: cfA + "," + quad9ECS, Quad9ECS: true}, false); len(l) != 2 {
		t.Fatalf("no duplicate ECS: %v", l)
	}
	if l := upstreamList(oldDoH, Settings{ExtraUpstream: "https://x.example/dns-query"}, false); len(l) != 5 {
		t.Fatalf("extra: %v", l)
	}
}

// ---------- local names ----------

func TestLocalNames(t *testing.T) {
	s := newTestServer(t, "1.2.3.4", new(atomic.Int64), nil)
	if err := s.applyLocalNames(Settings{LocalNames: map[string]string{"NAS.home": "192.168.1.123", "printer.lan": "192.168.1.30, fd00::30"}}); err != nil {
		t.Fatal(err)
	}
	r, res, _ := s.Handle(q("nas.HOME."))
	if res != "local" || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.123" || !r.Authoritative {
		t.Fatalf("%s %v", res, r)
	}
	r, _, _ = s.Handle(qt("printer.lan.", dns.TypeAAAA, false, false))
	if len(r.Answer) != 1 {
		t.Fatalf("aaaa %v", r)
	}
	r, _, _ = s.Handle(qt("nas.home.", dns.TypeMX, false, false))
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 0 {
		t.Fatalf("NODATA expected: %v", r)
	}
	if _, err := parseLocalNames(map[string]string{"bad name!": "1.2.3.4"}); err == nil {
		t.Fatal("bad hostname accepted")
	}
	_ = s.applyLocalNames(Settings{Features: map[string]bool{"local_names": false}, LocalNames: map[string]string{"nas.home": "192.168.1.123"}})
	if _, res, _ := s.Handle(q("nas.home.")); res == "local" {
		t.Fatal("feature switch ignored")
	}
}

// ---------- outages ----------

func TestOutagesLogAndCSV(t *testing.T) {
	st := newStore(t)
	path := filepath.Join(t.TempDir(), "goproxy-outages.json")
	o := NewOutages(path, st, nil)
	t0 := time.Date(2026, 10, 3, 20, 0, 0, 0, time.Local)
	o.BeginAt("internet", "all upstreams failing", t0)
	o.BeginAt("internet", "dup", t0.Add(time.Second)) // idempotent
	o.EndAt("internet", t0.Add(4*time.Minute+30*time.Second))
	o.BeginAt("internet", "blip", t0.Add(time.Hour))
	o.EndAt("internet", t0.Add(time.Hour+5*time.Second)) // < MinDur: dropped
	o.BeginAt("lan", "wifi", t0.Add(2*time.Hour))        // left open: a crash
	v := o.View("2026-10")
	if len(v) != 2 || v[1].Minutes != 4.5 || !v[0].Ongoing {
		t.Fatalf("view: %+v", v)
	}
	o2 := NewOutages(path, st, nil) // reload closes the open one
	if o2.Open() != nil {
		t.Fatal("open outage survived a restart")
	}
	rec := httptest.NewRecorder()
	o.serveCSV(rec, httptest.NewRequest("GET", "/api/outages.csv?month=2026-10", nil))
	body := rec.Body.String()
	if !strings.HasPrefix(body, "start,end,duration_minutes,kind,reason") || !strings.Contains(body, "4.5,internet") || !strings.Contains(body, "total") {
		t.Fatalf("csv:\n%s", body)
	}
	rec = httptest.NewRecorder()
	o.serveCSV(rec, httptest.NewRequest("GET", "/api/outages.csv?month=bad", nil))
	if rec.Code != 400 {
		t.Fatal("bad month accepted")
	}
}

// ---------- devices ----------

func TestDevicesGroupsQuietCoverage(t *testing.T) {
	st := newStore(t)
	al := NewAlerts(st, nil)
	al.toast = nil
	d := NewDevices(filepath.Join(t.TempDir(), "goproxy-groups.json"), st, al)
	now := time.Now()
	d.now = func() time.Time { return now }
	d.started = now.Add(-2 * time.Hour)
	for i := 0; i < 300; i++ {
		d.Record("192.168.1.50", dns.TypeA, "cached")
		d.Record("192.168.1.50", dns.TypeAAAA, "forwarded")
	}
	d.Record("192.168.1.77", dns.TypeA, "failed")
	alias, group, watch, qm := "Doorbell", "Cameras", true, 30
	if err := d.Edit(deviceEdit{IP: "192.168.1.77", Alias: &alias, Group: &group, Watched: &watch, QuietMin: &qm}); err != nil {
		t.Fatal(err)
	}
	bad := 1
	if d.Edit(deviceEdit{IP: "192.168.1.77", QuietMin: &bad}) == nil {
		t.Fatal("quiet minutes 1 accepted")
	}
	d.CheckQuiet()
	if len(al.Active()) != 0 {
		t.Fatal("just seen: not quiet")
	}
	now = now.Add(31 * time.Minute)
	d.CheckQuiet()
	if a := al.Active(); len(a) != 1 || !strings.Contains(a[0].Title, "Doorbell") {
		t.Fatalf("quiet alert: %+v", a)
	}
	d.Record("192.168.1.77", dns.TypeA, "cached")
	d.CheckQuiet()
	if len(al.Active()) != 0 {
		t.Fatal("quiet alert not cleared")
	}
	list := d.List(false)
	roll := rollup(list, d.g.Groups)
	found := false
	for _, r := range roll {
		if r.Name == "Cameras" && r.Devices == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("rollup: %+v", roll)
	}
	if err := d.EditGroup(groupEdit{Action: "rename", Name: "Cameras", To: "Outdoor"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Save(); err != nil {
		t.Fatal(err)
	}
	d2 := NewDevices(d.path, st, al)
	if m := d2.g.Devices["192.168.1.77"]; m == nil || m.Group != "Outdoor" || m.Alias != "Doorbell" || m.LastSeen == 0 {
		t.Fatalf("persisted: %+v", m)
	}
	cv := coverage(list, []string{"2001:db8:1::5"})
	if cv.Score != 70 || cv.V6Clients != 0 {
		t.Fatalf("coverage: %+v", cv)
	}
	if coverage(list[:0], nil).Score != -1 {
		t.Fatal("no data must be -1")
	}
}

// ---------- canary ----------

func TestCanaryScoreMovesResolverUnchanged(t *testing.T) {
	var fail atomic.Bool
	up := handlerUp(t, func(r *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		if fail.Load() {
			m.SetRcode(r, dns.RcodeServerFailure)
			return m
		}
		m.SetReply(r)
		if strings.HasSuffix(r.Question[0].Name, ".invalid.") {
			m.Rcode = dns.RcodeNameError
			return m
		}
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("5.5.5.5")}}
		return m
	})
	s := NewDNSServer(context.Background(), NewDNSCache(1<<20, 1000, 4), &Resolver{DoH: []*Upstream{NewUpstream(up, nil)}}, NewBlocklist(nil, nil, []string{"ads.example"}))
	s.tune.StaleTimeout = 0
	s.pinned = NewPinned(nil, nil)
	c := NewCanary(s, filepath.Join(t.TempDir(), "drift.json"))
	if !c.RunOnce() {
		t.Fatalf("healthy canary failed: %+v", c.View().Results)
	}
	// make every upstream lookup fail and empty the cache, so the canary must notice
	fail.Store(true)
	s.cache.Flush()
	tuneBefore := s.tune
	c.RunOnce() // one failure is not enough
	if !c.View().OK {
		t.Fatal("a single failure must not count")
	}
	s.cache.Flush()
	if c.RunOnce() {
		t.Fatal("second failure in a row must fail the canary")
	}
	b := s.health.buckets[len(s.health.buckets)-1]
	if b.CanaryOK != 2 || b.CanaryFail != 1 || b.Scores().Canary >= 100 {
		t.Fatalf("bucket %+v score %d", b, b.Scores().Canary)
	}
	if !reflect.DeepEqual(s.tune, tuneBefore) || s.bl.Size() != 1 {
		t.Fatal("the canary changed resolver behaviour")
	}
	if b.Scores().Overall != (HealthBucket{Start: b.Start}).Scores().Overall {
		t.Fatal("canary must not change the overall score")
	}
}

func TestDriftAlert(t *testing.T) {
	sig := func(cname string) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion("www.youtube.com.", dns.TypeA)
		m.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: "www.youtube.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: cname}}
		return m
	}
	a, b := signature(sig("youtube-ui.l.google.com.")), signature(sig("other.cdn.example."))
	if a == b || a != signature(sig("youtube-ui.l.google.com.")) {
		t.Fatalf("signature: %q %q", a, b)
	}
}

// ---------- kiosk ----------

func TestKioskCannotReachAdmin(t *testing.T) {
	dir := t.TempDir()
	st := &settingsStore{path: filepath.Join(dir, "s.json")}
	_ = st.Save(Settings{Features: map[string]bool{"kiosk": true}})
	auth := NewAuth(filepath.Join(dir, "auth.json"))
	if err := auth.Setup("admin", "correct-horse-1"); err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, "1.2.3.4", new(atomic.Int64), nil)
	s.settings = st
	v := &V24{s: s, auth: auth}
	k := NewKiosk(filepath.Join(dir, "kiosk.json"), auth)
	k.v = v
	mux := http.NewServeMux()
	k.Register(mux)
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("secret settings")) })
	h := auth.Middleware(mux)
	do := func(method, path, body string, ck *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "192.168.1.80:5000"
		if ck != nil {
			r.AddCookie(ck)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := do("GET", "/api/kiosk", "", nil); w.Code != 401 {
		t.Fatalf("no session: %d", w.Code)
	}
	if err := k.SetPassword("tablet1"); err != nil {
		t.Fatal(err)
	}
	if w := do("POST", "/api/kiosk/login", `{"password":"nope"}`, nil); w.Code != 401 {
		t.Fatalf("wrong pw: %d", w.Code)
	}
	w := do("POST", "/api/kiosk/login", `{"password":"tablet1"}`, nil)
	var ck *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == kioskCookie {
			ck = c
		}
	}
	if w.Code != 200 || ck == nil {
		t.Fatalf("kiosk login: %d", w.Code)
	}
	if w := do("GET", "/api/kiosk", "", ck); w.Code != 200 || strings.Contains(w.Body.String(), "192.168.") {
		t.Fatalf("kiosk data: %d %s", w.Code, w.Body.String())
	}
	if w := do("GET", "/api/settings", "", ck); w.Code == 200 && strings.Contains(w.Body.String(), "secret") {
		t.Fatal("kiosk cookie opened an admin API")
	}
	if w := do("POST", "/api/kiosk/password", `{"password":""}`, ck); w.Code == 200 {
		t.Fatal("kiosk cookie changed the kiosk password")
	}
	_ = k.SetPassword("") // removing the password signs tablets out
	if w := do("GET", "/api/kiosk", "", ck); w.Code != 401 {
		t.Fatalf("old kiosk cookie still works: %d", w.Code)
	}
	_ = st.Save(Settings{})
	if w := do("GET", "/api/kiosk", "", nil); !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("kiosk off: %s", w.Body.String())
	}
}

// ---------- item k: monotonic clock ----------

func TestCacheUsesMonotonicClock(t *testing.T) {
	c := NewDNSCache(1<<20, 1000, 4)
	k := cacheKey("mono.example.", dns.TypeA, dns.ClassINET)
	e := c.Set(k, aReply("mono.example.", 300, "1.2.3.4"))
	// a live entry carries a monotonic reading, so expiry comparisons ignore wall-clock jumps
	if !strings.Contains(e.Expires.String(), "m=") {
		t.Fatalf("Expires has no monotonic reading: %s", e.Expires)
	}
	if wall := e.Expires.Round(0); wall.Equal(e.Expires) && !strings.Contains(wall.String(), "m=") {
		_ = wall // Round(0) strips it: that is what the snapshot stores
	}
}

func TestCacheClockJumps(t *testing.T) {
	ck := &clock{time.Unix(2e9, 0)}
	c := NewDNSCache(1<<20, 1000, 4)
	c.now, c.minTTL = ck.now, 300*time.Second
	k := cacheKey("jump.example.", dns.TypeA, dns.ClassINET)
	c.Set(k, aReply("jump.example.", 300, "1.2.3.4")) // like a restored entry: wall time only
	req := q("jump.example.")
	// wall clock jumps back 2 h (bad time sync): the answer must not claim a 2 h TTL
	ck.t = ck.t.Add(-2 * time.Hour)
	e, fresh := c.Get(k)
	if e == nil || !fresh {
		t.Fatal("entry lost on backward jump")
	}
	if ttl := e.Reply(req, ck.now(), false).Answer[0].Header().Ttl; ttl > 300 {
		t.Fatalf("TTL stretched to %d after a backward clock jump", ttl)
	}
	// jumps forward 30 min: expired but still within serve-stale (1 h)
	ck.t = time.Unix(2e9, 0).Add(30 * time.Minute)
	if e, fresh := c.Get(k); e == nil || fresh {
		t.Fatal("want stale")
	}
	// forward 2 h: gone
	ck.t = time.Unix(2e9, 0).Add(2 * time.Hour)
	if e, _ := c.Get(k); e != nil {
		t.Fatal("entry beyond serve-stale")
	}
}

// ---------- item q: large answers fall back to TCP, through the real listeners ----------

func TestLargeAnswerTCPFallbackThroughStartDNS(t *testing.T) {
	s := zoneServer(t, nil)
	addr := freeDNSAddr(t)
	dl, err := startDNS(addr, 2, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer dl.close()
	r, _, err := (&dns.Client{Net: "udp"}).Exchange(qt("big.example.", dns.TypeA, true, false), addr)
	if err != nil || !r.Truncated {
		t.Fatalf("udp: err=%v tc=%v", err, r != nil && r.Truncated)
	}
	r, _, err = (&dns.Client{Net: "tcp"}).Exchange(qt("big.example.", dns.TypeA, true, false), addr)
	if err != nil || r.Truncated || len(r.Answer) != 100 {
		t.Fatalf("tcp: %v %v", err, r)
	}
}

// ---------- flight recorder ----------

func TestFlightRecorder(t *testing.T) {
	dir := t.TempDir()
	f := NewFlight(4, time.Minute, dir)
	f.rec.Store(true)
	for i := 0; i < 6; i++ {
		f.Add(flightEntry{T: time.Now().UnixNano(), Name: "n" + itoa(i) + ".example."})
	}
	if n := len(f.Snapshot()); n != 4 {
		t.Fatalf("ring size %d", n)
	}
	name := f.Dump("test", true)
	if name == "" || len(f.Files()) != 1 {
		t.Fatalf("dump: %q", name)
	}
	if f.Dump("again", false) != "" {
		t.Fatal("dumps are rate-limited")
	}
}

// ---------- item t: benchmark + presets ----------

func TestBenchmarkRanksAndPresets(t *testing.T) {
	slow := handlerUp(t, func(r *dns.Msg) *dns.Msg {
		time.Sleep(30 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.1.1.1")}}
		return m
	})
	fast := handlerUp(t, func(r *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(r)
		if strings.HasPrefix(r.Question[0].Name, "gpbench-") {
			m.Rcode = dns.RcodeNameError
		} else if r.Question[0].Name == "dnssec-failed.org." {
			m.Rcode = dns.RcodeServerFailure
		} else {
			m.AuthenticatedData = true
			m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.1.1.1")}}
		}
		return m
	})
	broken := handlerUp(t, func(r *dns.Msg) *dns.Msg { m := new(dns.Msg); m.SetRcode(r, dns.RcodeServerFailure); return m })
	dir := t.TempDir()
	b := NewBench(filepath.Join(dir, "goproxy-bench.json"), func() []string { return nil })
	b.Pace = 0
	b.cands = []benchCandidate{
		{ID: "a", Name: "Slow", Provider: "P1", DoH: slow},
		{ID: "b", Name: "Fast", Provider: "P2", DoH: fast},
		{ID: "c", Name: "Fast twin", Provider: "P2", DoH: fast},
		{ID: "d", Name: "Broken", Provider: "P3", DoH: broken},
	}
	if err := b.Start("test", false); err != nil {
		t.Fatal(err)
	}
	if err := b.Start("test", false); err == nil {
		t.Fatal("second concurrent run allowed")
	}
	deadline := time.Now().Add(30 * time.Second)
	for b.Latest() == nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	run := b.Latest()
	if run == nil {
		t.Fatal("benchmark did not finish")
	}
	if run.Rows[0].Provider != "P2" || run.Rows[len(run.Rows)-1].Name != "Broken" || run.Rows[0].DNSSEC != "validating" {
		t.Fatalf("ranking: %+v", run.Rows)
	}
	if len(run.Fastest) != 2 || run.Fastest[0] != fast || run.Fastest[1] != slow {
		t.Fatalf("fastest must be 2 different providers: %v", run.Fastest)
	}
	if run.Recommend == "" {
		t.Fatal("no recommendation")
	}
	if err := b.Start("test", false); err == nil {
		t.Fatal("cooldown not enforced")
	}
	if NewBench(b.path, nil).Latest() == nil {
		t.Fatal("results not saved")
	}
	// presets change only upstream settings and land in the config history
	st := newStore(t)
	_ = st.Save(Settings{NtfyTopic: "keep-me", LocalNames: map[string]string{"nas.home": "192.168.1.123"}})
	for _, p := range presetNames {
		latest := &benchRun{Fastest: []string{cfA, googleA}}
		if _, _, err := st.Update("t", "preset "+p, func(s *Settings) error {
			if _, err := applyPreset(s, p, latest); err != nil {
				return err
			}
			s.Preset = p
			return validateSettings(s)
		}); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		cur := st.Get()
		if cur.NtfyTopic != "keep-me" || cur.LocalNames["nas.home"] == "" {
			t.Fatalf("%s touched unrelated settings", p)
		}
		l := upstreamList(defaultDoH, cur, false)
		switch p {
		case "privacy":
			if cur.Quad9ECS || strings.Contains(strings.Join(l, ","), "dns11") {
				t.Fatal("privacy must not use ECS")
			}
		case "streaming":
			if !strings.Contains(strings.Join(l, ","), "dns11") {
				t.Fatalf("streaming: %v", l)
			}
		case "reliability":
			if len(l) != 3 || providerOf(l[0]) == providerOf(l[1]) || providerOf(l[1]) == providerOf(l[2]) {
				t.Fatalf("reliability: %v", l)
			}
		case "default":
			if strings.Join(l, ",") != defaultDoH {
				t.Fatalf("default: %v", l)
			}
		}
	}
	if len(st.History()) < 4 {
		t.Fatal("presets must be in the config history")
	}
	var s Settings
	if _, err := applyPreset(&s, "fastest", nil); err == nil {
		t.Fatal("fastest without a benchmark")
	}
}
