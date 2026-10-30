// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// selfTestName is answered by GoProxy itself (never forwarded), so a self-query proves the
// listener and the query path work without depending on the internet.
const selfTestName = "goproxy-selftest.invalid."

func selfTestReply(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(req)
	m.RecursionAvailable = true
	if req.IsEdns0() != nil {
		m.SetEdns0(ednsUDPSize, false)
	}
	if req.Question[0].Qtype == dns.TypeTXT || req.Question[0].Qtype == dns.TypeA {
		hdr := dns.RR_Header{Name: req.Question[0].Name, Class: dns.ClassINET, Ttl: 0, Rrtype: req.Question[0].Qtype}
		if req.Question[0].Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)}}
		} else {
			m.Answer = []dns.RR{&dns.TXT{Hdr: hdr, Txt: []string{"ok " + Version}}}
		}
	}
	return m
}

// selfCheck queries our own listener over UDP and TCP, and the dashboard over HTTP.
func selfCheck(dnsAddr, httpAddr string) error {
	host, port, err := net.SplitHostPort(dnsAddr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	m := new(dns.Msg)
	m.SetQuestion(selfTestName, dns.TypeA)
	for _, n := range []string{"udp", "tcp"} {
		r, _, err := (&dns.Client{Net: n, Timeout: 2 * time.Second}).Exchange(m, addr)
		if err != nil {
			return fmt.Errorf("dns %s self-query: %w", n, err)
		}
		if r.Rcode != dns.RcodeSuccess {
			return fmt.Errorf("dns %s self-query: rcode %s", n, dns.RcodeToString[r.Rcode])
		}
	}
	if httpAddr != "" {
		c := &http.Client{Timeout: 3 * time.Second}
		resp, err := c.Get(localURL(httpAddr, "/api/version"))
		if err != nil {
			return fmt.Errorf("dashboard self-check: %w", err)
		}
		resp.Body.Close()
	}
	return nil
}

// Watchdog detects a listener that stopped answering (the v2.3.1 hang) and recovers:
// first by re-binding the ports in-process, then, if that does not help, by restarting the
// process (Windows Service: exit so the SCM restarts it; portable: start a fresh copy).
type Watchdog struct {
	Every    time.Duration
	Fails    int           // consecutive failed checks before acting
	Grace    time.Duration // no checks this long after start
	Check    func() error
	Paused   func() bool // e.g. while an update hands over the ports
	Recover  func(reason string) error
	Escalate func(reason string)
	Dump     func(reason string)
	now      func() time.Time

	mu         sync.Mutex
	started    time.Time
	fails      int
	lastErr    string
	recoveries []time.Time
	lastOK     time.Time
	events     []string
	wake       chan string
}

func NewWatchdog() *Watchdog {
	return &Watchdog{Every: 15 * time.Second, Fails: 3, Grace: 90 * time.Second, now: time.Now, wake: make(chan string, 4)}
}

// Wake asks for an immediate check (a listener reported that it stopped).
func (w *Watchdog) Wake(reason string) {
	select {
	case w.wake <- reason:
	default:
	}
}

func (w *Watchdog) note(s string) {
	log.Print("watchdog: " + s)
	w.mu.Lock()
	w.events = append(w.events, w.now().Format("2006-01-02 15:04:05")+" "+s)
	if len(w.events) > 30 {
		w.events = w.events[len(w.events)-30:]
	}
	w.mu.Unlock()
}

type watchdogView struct {
	Enabled    bool     `json:"enabled"`
	Fails      int      `json:"consecutive_failures"`
	LastError  string   `json:"last_error,omitempty"`
	LastOK     string   `json:"last_ok,omitempty"`
	Recoveries int      `json:"recoveries"`
	Events     []string `json:"events"`
}

func (w *Watchdog) View() watchdogView {
	if w == nil {
		return watchdogView{}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	v := watchdogView{Enabled: true, Fails: w.fails, LastError: w.lastErr, Recoveries: len(w.recoveries), Events: append([]string(nil), w.events...)}
	if !w.lastOK.IsZero() {
		v.LastOK = w.lastOK.Format(time.RFC3339)
	}
	return v
}

func (w *Watchdog) Run(ctx context.Context) {
	w.started = w.now()
	t := time.NewTicker(w.Every)
	defer t.Stop()
	for {
		reason := ""
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case reason = <-w.wake:
		}
		w.Step(reason)
	}
}

// Step runs one check (exported for tests). reason != "" means a listener reported death:
// act on the first failed check instead of waiting for Fails in a row.
func (w *Watchdog) Step(reason string) {
	now := w.now()
	if reason == "" && now.Sub(w.started) < w.Grace {
		return
	}
	if w.Paused != nil && w.Paused() {
		w.mu.Lock()
		w.fails = 0
		w.mu.Unlock()
		return
	}
	err := w.Check()
	w.mu.Lock()
	if err == nil {
		w.fails, w.lastOK = 0, now
		w.mu.Unlock()
		return
	}
	w.fails++
	w.lastErr = err.Error()
	n := w.fails
	w.mu.Unlock()
	if n < w.Fails && reason == "" {
		return
	}
	why := err.Error()
	if reason != "" {
		why = reason + "; " + why
	}
	w.note(fmt.Sprintf("not answering (%d failed checks): %s", n, why))
	if w.Dump != nil {
		w.Dump(why)
	}
	// too many in-process recoveries recently: restart the process instead
	w.mu.Lock()
	var recent []time.Time
	for _, t := range w.recoveries {
		if now.Sub(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	w.recoveries = append(recent, now)
	tooMany := len(recent) >= 3
	w.mu.Unlock()
	if !tooMany && w.Recover != nil {
		if rerr := w.Recover(why); rerr == nil {
			if cerr := w.Check(); cerr == nil {
				w.note("recovered by re-binding the listeners")
				w.mu.Lock()
				w.fails, w.lastOK = 0, w.now()
				w.mu.Unlock()
				return
			} else {
				why += "; still failing after re-bind: " + cerr.Error()
			}
		} else {
			why += "; re-bind failed: " + rerr.Error()
		}
	}
	w.note("restarting GoProxy: " + why)
	if w.Escalate != nil {
		w.Escalate(why)
	}
}

// dumpGoroutines writes every goroutine's stack to goproxy-hang-*.txt (kept: last 5), so
// the next hang can be diagnosed from the file instead of guessed at.
func dumpGoroutines(reason string) string {
	dir := dataDir
	name := filepath.Join(dir, "goproxy-hang-"+time.Now().Format("20060102-150405")+".txt")
	f, err := os.Create(name)
	if err != nil {
		return ""
	}
	fmt.Fprintf(f, "GoProxy v%s pid %d at %s\nreason: %s\n\n", Version, os.Getpid(), time.Now().Format(time.RFC3339), reason)
	_ = pprof.Lookup("goroutine").WriteTo(f, 2)
	f.Close()
	old, _ := filepath.Glob(filepath.Join(dir, "goproxy-hang-*.txt"))
	sort.Strings(old)
	for len(old) > 5 {
		_ = os.Remove(old[0])
		old = old[1:]
	}
	log.Printf("watchdog: goroutine dump written to %s", name)
	return name
}

// recoverListeners closes and re-binds DNS and the dashboard in-process.
func (a *App) recoverListeners(reason string) error {
	done := make(chan error, 1)
	go func() {
		a.unbindDNS()
		a.unbindHTTP()
		done <- a.bindAll(10 * time.Second)
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		return errors.New("re-bind did not finish within 30 s")
	}
}

// restartProcess is the last resort. Service: exit non-zero so the SCM recovery actions
// restart us. Portable: save (bounded), release the ports, start a fresh copy, exit.
func (a *App) restartProcess(reason string) {
	saved := make(chan struct{})
	go func() { a.SaveAll(); close(saved) }()
	select {
	case <-saved:
	case <-time.After(15 * time.Second):
		log.Print("watchdog: cache save did not finish in 15 s; restarting without it")
	}
	a.handedOff.Store(true)
	if serviceMode {
		eventLogError("GoProxy stopped answering and is exiting so Windows restarts it: " + reason)
		os.Exit(3)
	}
	go func() { a.unbindDNS(); a.unbindHTTP() }()
	time.Sleep(500 * time.Millisecond)
	exe, _, _ := exePaths()
	cmd := exec.Command(exe, filterArgs(os.Args[1:])...)
	cmd.Dir = exeDir()
	detach(cmd)
	if err := cmd.Start(); err != nil {
		log.Printf("watchdog: could not start a new copy: %v", err)
	}
	os.Exit(3)
}

func isSelfTest(name string) bool { return strings.EqualFold(name, selfTestName) }
