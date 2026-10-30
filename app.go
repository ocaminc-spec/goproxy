// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// App owns the listeners so they can be released and re-bound during a zero-downtime update.
type App struct {
	s                 *DNSServer
	cache             *DNSCache
	dnsAddr, httpAddr string
	listeners         int
	stateFile         string
	cancel            context.CancelFunc
	stop              chan struct{}
	mux               http.Handler
	saveMu            sync.Mutex
	upd               *Updater
	mu                sync.Mutex
	dns               *dnsListeners
	hs                *http.Server
	died              chan string // a listener stopped on its own (see startDNS)
	handedOff         atomic.Bool // a newer process owns the cache file now; do not save over it
}

var theApp *App

var logPath = "goproxy.log"

func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		if r, err := filepath.EvalSymlinks(exe); err == nil {
			exe = r
		}
		return filepath.Dir(exe)
	}
	return "."
}

// setupLog sends the log to stderr and to goproxy.log beside the exe (the windowsgui build has no console,
// which is why a failed start used to be silent).
func setupLog() {
	logPath = filepath.Join(dataDir, "goproxy.log")
	if fi, err := os.Stat(logPath); err == nil && fi.Size() > 5<<20 {
		_ = os.Rename(logPath, logPath+".old")
	}
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	log.SetOutput(newSafeLogWriter(f, consoleWriter()))
	log.SetPrefix(fmt.Sprintf("[%d] ", os.Getpid()))
}

// fatal logs, shows a desktop notification (Windows) and exits.
//
// v2.3.1 showed a modal MessageBox and only exited after someone clicked OK. With the ports
// already released (a failed re-bind after an update, for example) that left a process that
// was alive, idle and "Responding" but answered nothing until it was killed: the hang
// signature. The popup is now shown without blocking and the process exits after at most
// 2 s, so a restart (watchdog, SCM recovery, the next sign-in) can happen.
func fatal(msg string) {
	log.Print("FATAL: " + msg)
	if !serviceMode {
		done := make(chan struct{})
		go func() { notifyError("GoProxy DNS failed to start", msg); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	} else {
		eventLogError("FATAL: " + msg)
	}
	os.Exit(1)
}

// sharedPC is the one UDP socket that all N readers share on Windows. miekg/dns closes the
// PacketConn when its serve loop returns, so in v2.3.1 a single reader hitting a
// non-temporary read error (on Windows only EINTR/EMFILE/timeouts count as temporary, so a
// WSAENETRESET from an ICMP "TTL expired" or a Wi-Fi adapter reset qualifies) closed port 53
// for every reader, silently: the process kept running, idle, answering nothing. Close is
// now ignored unless GoProxy itself is shutting the listeners down.
type sharedPC struct {
	net.PacketConn
	closing atomic.Bool
	once    sync.Once
}

func (p *sharedPC) Close() error {
	if !p.closing.Load() {
		return nil
	}
	var err error
	p.once.Do(func() { err = p.PacketConn.Close() })
	return err
}

func (p *sharedPC) shutdown() { p.closing.Store(true); _ = p.Close() }

// dnsListeners is one bound set of port-53 servers.
type dnsListeners struct {
	servers  []*dns.Server
	pc       *sharedPC
	stopping atomic.Bool
}

// startDNS binds N UDP listeners (SO_REUSEPORT on Linux/macOS, N readers on one socket on Windows)
// plus a TCP listener. Any error closes what was opened. died is called (once per server) if a
// serve loop ends while the listeners are not being shut down.
// udpSockBuf is the UDP socket buffer size from the performance profile (0 = OS default).
var udpSockBuf int

func startDNS(addr string, n int, h dns.Handler, died func(string)) (*dnsListeners, error) {
	n = max(n, 1)
	dl := &dnsListeners{}
	fail := func(err error) (*dnsListeners, error) {
		dl.stopping.Store(true)
		for _, s := range dl.servers {
			_ = s.Shutdown()
		}
		if dl.pc != nil {
			dl.pc.shutdown()
		}
		return nil, err
	}
	start := func(srv *dns.Server) error {
		started := make(chan error, 1)
		var up atomic.Bool
		srv.NotifyStartedFunc = func() { up.Store(true); started <- nil }
		go func() {
			var err error
			if srv.PacketConn != nil || srv.Listener != nil {
				err = srv.ActivateAndServe()
			} else {
				err = srv.ListenAndServe()
			}
			if !up.Load() {
				if err == nil {
					err = errors.New("listener ended before it started")
				}
				started <- err // start-up failure, reported below
				return
			}
			if !dl.stopping.Load() && died != nil {
				died(fmt.Sprintf("dns %s listener on %s stopped: %v", srv.Net, addr, err))
			}
		}()
		if err := <-started; err != nil {
			return fmt.Errorf("dns %s %s: %w", srv.Net, addr, err)
		}
		dl.servers = append(dl.servers, srv)
		return nil
	}
	if runtime.GOOS == "windows" {
		raw, err := net.ListenPacket("udp", addr)
		if err != nil {
			return fail(fmt.Errorf("dns udp %s: %w", addr, err))
		}
		dl.pc = &sharedPC{PacketConn: raw}
		for i := 0; i < n; i++ {
			if err := start(&dns.Server{PacketConn: dl.pc, Net: "udp", Handler: h, UDPSize: 65535}); err != nil {
				return fail(err)
			}
		}
	} else {
		for i := 0; i < n; i++ {
			pc, err := listenUDP(addr, n > 1, udpSockBuf)
			if err != nil {
				return fail(fmt.Errorf("dns udp %s: %w", addr, err))
			}
			if err := start(&dns.Server{PacketConn: pc, Net: "udp", Handler: h, UDPSize: 65535}); err != nil {
				_ = pc.Close()
				return fail(err)
			}
		}
	}
	udpListeners = n
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fail(fmt.Errorf("dns tcp %s: %w", addr, err))
	}
	if err := start(&dns.Server{Listener: ln, Net: "tcp", Handler: h, ReadTimeout: 5 * time.Second, IdleTimeout: func() time.Duration { return 10 * time.Second }}); err != nil {
		return fail(err)
	}
	return dl, nil
}

// close shuts every server down (in parallel: they share one socket on Windows).
func (dl *dnsListeners) close() {
	if dl == nil {
		return
	}
	dl.stopping.Store(true)
	var wg sync.WaitGroup
	for _, s := range dl.servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = s.ShutdownContext(ctx)
			cancel()
		}()
	}
	if dl.pc != nil {
		go func() { time.Sleep(3 * time.Second); dl.pc.shutdown() }()
	}
	wg.Wait()
	if dl.pc != nil {
		dl.pc.shutdown()
	}
}

// bindAll binds DNS then the dashboard, retrying for up to `retry` (a port can stay held for a
// moment after the previous process was killed). Polls every 20 ms so a handoff gap stays tiny.
func (a *App) bindAll(retry time.Duration) error {
	deadline := time.Now().Add(retry)
	var last error
	lastLog := time.Time{}
	for {
		err := a.bindOnce()
		if err == nil {
			return nil
		}
		last = err
		if time.Now().After(deadline) {
			return last
		}
		if time.Since(lastLog) > 2*time.Second {
			log.Printf("bind: %v (retrying for up to %v)", err, retry)
			lastLog = time.Now()
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (a *App) bindOnce() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.dns == nil {
		dl, err := startDNS(a.dnsAddr, a.listeners, a.s, a.listenerDied)
		if err != nil {
			return err
		}
		a.dns = dl
	}
	if a.hs == nil {
		ln, err := net.Listen("tcp", a.httpAddr)
		if err != nil {
			return fmt.Errorf("dashboard %s: %w", a.httpAddr, err)
		}
		hs := &http.Server{Handler: a.mux, ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
		a.hs = hs
		go func() {
			if err := hs.Serve(ln); err != nil && err != http.ErrServerClosed {
				a.listenerDied("dashboard listener stopped: " + err.Error())
			}
		}()
	}
	return nil
}

// unbindDNS releases port 53 (UDP+TCP). unbindHTTP releases the dashboard port.
func (a *App) unbindDNS() {
	a.mu.Lock()
	dl := a.dns
	a.dns = nil
	a.mu.Unlock()
	dl.close()
}

// listenerDied records a listener that stopped by itself and wakes the watchdog.
func (a *App) listenerDied(reason string) {
	log.Print("listener: " + reason)
	if a.died == nil {
		return
	}
	select {
	case a.died <- reason:
	default:
	}
}

func (a *App) unbindHTTP() {
	a.mu.Lock()
	hs := a.hs
	a.hs = nil
	a.mu.Unlock()
	if hs != nil {
		_ = hs.Close()
	}
}

func (a *App) warmStart(ctx context.Context, load bool) {
	s := a.s
	if s.cacheFile == "" {
		return
	}
	if load {
		t0 := time.Now()
		n, err := a.cache.LoadFile(s.cacheFile)
		s.restored.Store(int64(n))
		switch {
		case err == nil:
			log.Printf("cache: restored %d entries from %s in %v", n, s.cacheFile, time.Since(t0).Round(time.Millisecond))
		case os.IsNotExist(err):
			log.Printf("cache: no snapshot yet (%s)", s.cacheFile)
		default:
			log.Printf("cache: restored %d entries; %v", n, err)
		}
	}
	names, _ := s.LoadState(a.stateFile)
	if s.tune.WarmupN > 0 && len(names) > s.tune.WarmupN {
		names = names[:s.tune.WarmupN]
	} else if s.tune.WarmupN <= 0 {
		names = nil
	}
	names = preloadNames(s.tune.WarmupList, names)
	if len(names) > 0 {
		s.Warmup(ctx, names)
		log.Printf("warm-up: %d domains checked", len(names))
	}
}

// SaveAll writes the cache snapshot, health history and query history.
func (a *App) SaveAll() {
	s := a.s
	if s.cacheFile == "" {
		return
	}
	a.saveMu.Lock()
	defer a.saveMu.Unlock()
	t0 := time.Now()
	n, err := a.cache.Save(s.cacheFile)
	log.Printf("cache: saved %d entries in %v (%v)", n, time.Since(t0).Round(time.Millisecond), err)
	if err := s.health.Save(); err != nil {
		log.Printf("health: %v", err)
	}
	if err := s.SaveState(a.stateFile); err != nil {
		log.Printf("history: %v", err)
	}
	if err := s.devices.Save(); err != nil {
		log.Printf("devices: %v", err)
	}
}

// autosave snapshots everything every `every` so a crash or power cut loses little.
func (a *App) autosave(ctx context.Context, every time.Duration) {
	if every <= 0 || a.s.cacheFile == "" {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !a.handedOff.Load() {
				a.SaveAll()
			}
		}
	}
}

func (a *App) Stop(save bool) {
	if !save {
		a.handedOff.Store(true)
	}
	closeOnce(a.stop)
}

func (a *App) shutdown() {
	log.Print("shutdown...")
	a.cancel()
	a.unbindDNS()
	if !a.handedOff.Load() {
		a.SaveAll()
	}
	a.mu.Lock()
	hs := a.hs
	a.mu.Unlock()
	if hs != nil {
		c, cc := context.WithTimeout(context.Background(), 3*time.Second)
		_ = hs.Shutdown(c)
		cc()
	}
	log.Print("bye")
}

func isLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// POST /api/shutdown — localhost only. Saves the cache and exits.
func (a *App) serveShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopback(r) {
		http.Error(w, "shutdown is only allowed from this computer", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"pid":` + fmt.Sprint(os.Getpid()) + `}`))
	log.Printf("shutdown requested via API from %s", r.RemoteAddr)
	go func() { time.Sleep(100 * time.Millisecond); a.Stop(true) }()
}

func localURL(httpAddr, path string) string {
	host, port, err := net.SplitHostPort(httpAddr)
	if err != nil || host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + path
}

// runStopCmd implements `goproxy -stop`: named event (Windows), else POST /api/shutdown; then waits
// until the dashboard stops answering (the cache is saved before that happens).
func runStopCmd(httpAddr string) int {
	if serviceInstalled() && stopViaSCM() { // needs Administrator; otherwise the API below works too
		fmt.Println("goproxy service stopped")
		return 0
	}
	signaled := signalStopEvent()
	if !signaled {
		c := &http.Client{Timeout: 3 * time.Second}
		req, _ := http.NewRequest(http.MethodPost, localURL(httpAddr, "/api/shutdown"), nil)
		req.Header.Set("X-GoProxy-Stop", "1") // custom header: a web page cannot send it cross-site
		resp, err := c.Do(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "goproxy is not running:", err)
			return 1
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok":true`) {
			fmt.Fprintln(os.Stderr, "the running GoProxy is too old for -stop (v2.3.0+ needed); quit it from the tray or Task Manager")
			return 1
		}
	}
	c := &http.Client{Timeout: time.Second}
	for i := 0; i < 300; i++ {
		resp, err := c.Get(localURL(httpAddr, "/api/version"))
		if err != nil {
			fmt.Println("goproxy stopped")
			return 0
		}
		resp.Body.Close()
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "goproxy did not stop within 30s")
	return 2
}

// healthCheck resolves name through our own listener. Any real answer (NOERROR/NXDOMAIN) passes.
func healthCheck(dnsAddr, name string) error {
	host, port, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	c := &dns.Client{Timeout: 2 * time.Second}
	var last error
	for i := 0; i < 3; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		r, _, err := c.Exchange(m, addr)
		if err == nil && (r.Rcode == dns.RcodeSuccess || r.Rcode == dns.RcodeNameError) {
			if _, _, err := (&dns.Client{Net: "tcp", Timeout: 2 * time.Second}).Exchange(m, addr); err != nil {
				last = fmt.Errorf("tcp: %w", err)
				continue
			}
			return nil
		}
		if err == nil {
			err = fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
		}
		last = err
	}
	return last
}

// handoffChild is the new process's side of the stdin/stdout handshake with the old process.
type handoffChild struct{ in *bufio.Reader }

func newHandoffChild() *handoffChild { return &handoffChild{in: bufio.NewReader(os.Stdin)} }

func (h *handoffChild) say(s string) { _, _ = os.Stdout.WriteString(s + "\n") }

// ready tells the old process we are loaded, and waits for it to release the ports.
func (h *handoffChild) ready() error {
	h.say("READY " + Version)
	line, err := h.in.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "GO" {
		return errors.New("unexpected: " + line)
	}
	return nil
}
func (h *handoffChild) ok()             { h.say("OK") }
func (h *handoffChild) fail(msg string) { h.say("FAIL " + msg) }

// preloadNames: the configured list first, then the most-queried names, without duplicates.
func preloadNames(list, top []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range append(append([]string(nil), list...), top...) {
		n = normName(n)
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}
