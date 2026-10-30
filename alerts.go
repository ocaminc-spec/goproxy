// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Alert is something the house should know about (IP changed, a quiet camera, an outage).
// It shows as a dashboard banner, a tray balloon, and (only if switched on) an ntfy push.
type Alert struct {
	Key     string `json:"key"`
	Level   string `json:"level"` // warning | info
	Title   string `json:"title"`
	Message string `json:"message"`
	Since   string `json:"since"`
	Kind    string `json:"kind"` // ip | quiet | outage | dns | drift | canary
}

type alertHistory struct {
	At      string `json:"at"`
	Event   string `json:"event"` // raised | cleared
	Key     string `json:"key"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Pushed  bool   `json:"pushed"`
}

type Alerts struct {
	mu       sync.Mutex
	active   map[string]Alert
	hist     []alertHistory
	settings *settingsStore
	ntfy     *Ntfy
	toast    func(title, msg string)
	hook     func(Alert) // v2.7.0 webhook (sends only when switched on)
	now      func() time.Time
}

func NewAlerts(st *settingsStore, n *Ntfy) *Alerts {
	return &Alerts{active: map[string]Alert{}, settings: st, ntfy: n, toast: notifyToast, now: time.Now}
}

// pushAllowed: ntfy is off by default; each kind has its own opt-in.
func pushAllowed(st Settings, kind string) bool {
	if !st.ntfyReady() {
		return false
	}
	switch kind {
	case "ip":
		return st.NtfyIPChange
	case "quiet":
		return st.NtfyQuiet
	case "outage":
		return st.NtfyOutage
	}
	return false
}

func (a *Alerts) Raise(al Alert) {
	if a == nil {
		return
	}
	a.mu.Lock()
	if _, ok := a.active[al.Key]; ok {
		a.mu.Unlock()
		return
	}
	if al.Level == "" {
		al.Level = "warning"
	}
	al.Since = a.now().Format(time.RFC3339)
	a.active[al.Key] = al
	st := a.settings.Get()
	push := pushAllowed(st, al.Kind)
	a.hist = append(a.hist, alertHistory{At: al.Since, Event: "raised", Key: al.Key, Title: al.Title, Message: al.Message, Pushed: push})
	a.trim()
	a.mu.Unlock()
	log.Printf("alert: %s: %s", al.Title, al.Message)
	if a.toast != nil {
		a.toast(al.Title, al.Message)
	}
	if push && a.ntfy != nil {
		go a.ntfy.Send(st, al.Key, al.Title, al.Message, al.Level == "warning")
	}
	if a.hook != nil {
		a.hook(al)
	}
}

func (a *Alerts) Clear(key, recovered string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	al, ok := a.active[key]
	if !ok {
		a.mu.Unlock()
		return
	}
	delete(a.active, key)
	st := a.settings.Get()
	push := pushAllowed(st, al.Kind) && recovered != ""
	a.hist = append(a.hist, alertHistory{At: a.now().Format(time.RFC3339), Event: "cleared", Key: key, Title: al.Title, Message: recovered, Pushed: push})
	a.trim()
	a.mu.Unlock()
	if recovered != "" {
		log.Printf("alert cleared: %s: %s", al.Title, recovered)
	}
	if push && a.ntfy != nil {
		go a.ntfy.Send(st, key+":ok", "Recovered: "+al.Title, recovered, false)
	}
}

func (a *Alerts) trim() {
	if len(a.hist) > 200 {
		a.hist = a.hist[len(a.hist)-200:]
	}
}

func (a *Alerts) Active() []Alert {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Alert, 0, len(a.active))
	for _, v := range a.active {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since < out[j].Since })
	return out
}

func (a *Alerts) History() []alertHistory {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]alertHistory(nil), a.hist...)
}

// ---------------- ntfy ----------------

// Ntfy posts to an ntfy server. Nothing is sent unless the user switched ntfy on and set
// a topic. The token is never logged or returned to the dashboard.
type Ntfy struct {
	mu      sync.Mutex
	last    map[string]time.Time
	client  *http.Client
	every   time.Duration // min gap per key
	backoff time.Duration
	now     func() time.Time
}

func NewNtfy(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Ntfy {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if dial != nil {
		tr.DialContext = dial
	}
	return &Ntfy{last: map[string]time.Time{}, client: &http.Client{Timeout: 5 * time.Second, Transport: tr}, every: 30 * time.Minute, backoff: 2 * time.Second, now: time.Now}
}

// Send returns whether a message was delivered. force skips the per-key rate limit (test button).
func (n *Ntfy) Send(st Settings, key, title, msg string, high bool) bool {
	return n.send(st, key, title, msg, high, false)
}

func (n *Ntfy) send(st Settings, key, title, msg string, high, force bool) bool {
	if n == nil || !st.ntfyReady() {
		return false
	}
	n.mu.Lock()
	if t, ok := n.last[key]; ok && !force && n.now().Sub(t) < n.every {
		n.mu.Unlock()
		return false
	}
	n.last[key] = n.now()
	n.mu.Unlock()
	server := strings.TrimRight(strings.TrimSpace(st.NtfyServer), "/")
	if server == "" {
		server = "https://ntfy.sh"
	}
	u := server + "/" + strings.Trim(strings.TrimSpace(st.NtfyTopic), "/")
	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodPost, u, bytes.NewBufferString(msg))
		req.Header.Set("Title", title)
		req.Header.Set("Tags", "warning")
		if high {
			req.Header.Set("Priority", "high")
		}
		if st.NtfyToken != "" {
			req.Header.Set("Authorization", "Bearer "+st.NtfyToken)
		}
		resp, err := n.client.Do(req)
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // url.Error would print the topic URL
		}
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode < 300 {
				return true
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		log.Printf("ntfy: send failed (try %d/3): %v", i+1, err) // URL and token never logged
		if i < 2 {
			time.Sleep(n.backoff << i)
		}
	}
	return false
}
