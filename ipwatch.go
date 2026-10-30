// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// IP-change watch (spec 02): notices when the address the house uses for DNS is no
// longer this PC's address (the DHCP change that broke DNS once).

type ifaceAddr struct {
	Name     string
	Up       bool
	Loopback bool
	IPs      []net.IP
}

var virtualAdapterHints = []string{"vethernet", "hyper-v", "virtualbox", "vmware", "wsl", "tailscale", "zerotier", "docker", "br-", "veth", "virbr", "loopback", "vpn", "tap", "tun", "wireguard", "npcap"}

func virtualAdapter(name string) bool {
	n := strings.ToLower(name)
	for _, h := range virtualAdapterHints {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

// lanIPv4s returns the private IPv4 addresses on up, physical-looking adapters.
func lanIPv4s(ifs []ifaceAddr) []string {
	var out []string
	for _, i := range ifs {
		if !i.Up || i.Loopback || virtualAdapter(i.Name) {
			continue
		}
		for _, ip := range i.IPs {
			if v4 := ip.To4(); v4 != nil && v4.IsPrivate() {
				out = append(out, v4.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

// classifyIP: ok (expected present) | changed (expected gone, another LAN IP present) | no_lan.
func classifyIP(ifs []ifaceAddr, expected string) (string, []string) {
	cur := lanIPv4s(ifs)
	if len(cur) == 0 {
		return "no_lan", cur
	}
	if expected == "" {
		return "ok", cur
	}
	for _, c := range cur {
		if c == expected {
			return "ok", cur
		}
	}
	return "changed", cur
}

func systemIfaces() []ifaceAddr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []ifaceAddr
	for _, i := range ifs {
		a := ifaceAddr{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0}
		addrs, _ := i.Addrs()
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				a.IPs = append(a.IPs, n.IP)
			}
		}
		out = append(out, a)
	}
	return out
}

type IPWatch struct {
	mu       sync.Mutex
	state    string // confirmed state
	pending  string
	pendingN int
	current  []string
	since    time.Time
	noLanAt  time.Time
	Need     int // matching samples in a row before a state change counts
	list     func() []ifaceAddr
	settings *settingsStore
	alerts   *Alerts
	outages  *Outages
	now      func() time.Time
}

func NewIPWatch(st *settingsStore, al *Alerts, out *Outages) *IPWatch {
	return &IPWatch{state: "starting", Need: 3, list: systemIfaces, settings: st, alerts: al, outages: out, now: time.Now}
}

type ipWatchView struct {
	Enabled  bool     `json:"enabled"`
	State    string   `json:"state"`
	Expected string   `json:"expected_ip"`
	Current  []string `json:"current_ips"`
	Since    string   `json:"since,omitempty"`
}

func (w *IPWatch) View() ipWatchView {
	if w == nil {
		return ipWatchView{}
	}
	st := w.settings.Get()
	w.mu.Lock()
	defer w.mu.Unlock()
	v := ipWatchView{Enabled: st.Feature("ip_watch"), State: w.state, Expected: st.ExpectedIP, Current: append([]string(nil), w.current...)}
	if !w.since.IsZero() {
		v.Since = w.since.Format(time.RFC3339)
	}
	return v
}

// Sample takes one reading (every 30 s from Run; called directly by tests).
func (w *IPWatch) Sample() {
	st := w.settings.Get()
	if !st.Feature("ip_watch") {
		w.alerts.Clear("ip-change", "")
		w.alerts.Clear("no-lan", "")
		return
	}
	state, cur := classifyIP(w.list(), st.ExpectedIP)
	w.mu.Lock()
	w.current = cur
	if state == w.pending {
		w.pendingN++
	} else {
		w.pending, w.pendingN = state, 1
	}
	if w.pendingN < w.Need || state == w.state {
		w.mu.Unlock()
		return
	}
	prev := w.state
	w.state, w.since = state, w.now()
	w.mu.Unlock()
	w.onChange(prev, state, cur, st)
}

func (w *IPWatch) onChange(prev, state string, cur []string, st Settings) {
	if state != "no_lan" && !w.noLanAt.IsZero() {
		w.alerts.Clear("no-lan", fmt.Sprintf("Network is back after %v.", w.now().Sub(w.noLanAt).Round(time.Second)))
		w.outages.End("lan")
		w.noLanAt = time.Time{}
	}
	switch state {
	case "ok":
		if st.ExpectedIP == "" && len(cur) > 0 {
			_, _, _ = w.settings.Update("auto", "learned this PC's LAN address", func(s *Settings) error { s.ExpectedIP = cur[0]; return nil })
		}
		w.alerts.Clear("ip-change", fmt.Sprintf("This PC has %s again; house DNS works normally.", w.settings.Get().ExpectedIP))
	case "changed":
		w.alerts.Raise(Alert{Key: "ip-change", Kind: "ip", Title: "PC IP address changed",
			Message: fmt.Sprintf("GoProxy: PC IP changed %s -> %s. House DNS points at the old IP. Fix the router DHCP reservation (or press Accept new IP if this is intended), or clients will fail over to a backup DNS server.", st.ExpectedIP, strings.Join(cur, ", "))})
	case "no_lan":
		w.noLanAt = w.now()
		w.outages.Begin("lan", "this PC has no network connection (Wi-Fi down?)")
		w.alerts.Raise(Alert{Key: "no-lan", Kind: "ip", Title: "PC lost its network", Message: "The GoProxy PC has no LAN address right now (Wi-Fi down?). Devices fall back to their second DNS server."})
	}
}

// Accept makes the current LAN address the expected one.
func (w *IPWatch) Accept(by string) (string, error) {
	w.mu.Lock()
	cur := append([]string(nil), w.current...)
	w.mu.Unlock()
	if len(cur) == 0 {
		cur = lanIPv4s(w.list())
	}
	if len(cur) == 0 {
		return "", fmt.Errorf("this PC has no LAN address right now")
	}
	_, _, err := w.settings.Update(by, "accepted new PC IP", func(s *Settings) error { s.ExpectedIP = cur[0]; return nil })
	if err == nil {
		w.mu.Lock()
		w.state, w.pending, w.pendingN, w.since = "ok", "ok", w.Need, w.now()
		w.mu.Unlock()
		w.alerts.Clear("ip-change", "New PC IP "+cur[0]+" accepted.")
	}
	return cur[0], err
}

func (w *IPWatch) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		w.Sample()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
