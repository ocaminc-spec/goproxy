// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Blocklist: hosts-format / plain-domain lists, plus allow and deny lists. Subdomains inherit.
type Blocklist struct {
	set    atomic.Pointer[map[string]struct{}]
	allow  atomic.Pointer[map[string]struct{}]
	paused atomic.Bool
	// Enabled turns the ad-blocking feature on (-blocking=true). When false nothing is
	// downloaded and nothing is blocked, not even the deny list.
	Enabled  bool
	URLs     []string
	Files    []string // extra local list files
	Allow    []string
	Deny     []string
	Updated  atomic.Int64
	Updating atomic.Bool
	kick     chan struct{}
	// v2.7.0: switched on from the dashboard (settings), live, without the -blocking flag.
	live   atomic.Bool
	mu     sync.Mutex // guards URLs / Allow / Deny when changed from settings
	client *http.Client
}

func NewBlocklist(urls, allow, deny []string) *Blocklist {
	b := &Blocklist{Enabled: true, URLs: urls, Allow: allow, Deny: deny, client: &http.Client{Timeout: 60 * time.Second}, kick: make(chan struct{}, 1)}
	e := map[string]struct{}{}
	b.set.Store(&e)
	b.Load(nil)
	return b
}

// ParseList adds every domain in a hosts or domain-per-line file to dst.
func ParseList(r io.Reader, dst map[string]struct{}) int {
	n := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		var d string
		switch len(f) {
		case 0:
			continue
		case 1:
			d = f[0]
		default:
			for _, h := range f[1:] {
				if addDomain(h, dst) {
					n++
				}
			}
			continue
		}
		if addDomain(d, dst) {
			n++
		}
	}
	return n
}

func addDomain(d string, dst map[string]struct{}) bool {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	d = strings.TrimPrefix(d, "*.")
	switch d {
	case "", "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0":
		return false
	}
	if !strings.Contains(d, ".") || strings.ContainsAny(d, "/:") {
		return false
	}
	dst[d] = struct{}{}
	return true
}

// Load replaces the active set from already-fetched readers (nil = only deny list).
func (b *Blocklist) Load(readers []io.Reader) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := map[string]struct{}{}
	for _, r := range readers {
		ParseList(r, m)
	}
	for _, d := range b.Deny {
		addDomain(d, m)
	}
	a := map[string]struct{}{}
	for _, d := range b.Allow {
		addDomain(d, a)
	}
	b.set.Store(&m)
	b.allow.Store(&a)
	b.Updated.Store(time.Now().Unix())
	return len(m)
}

// UpdateNow asks the refresh loop to re-download the lists now (non-blocking).
func (b *Blocklist) UpdateNow() {
	select {
	case b.kick <- struct{}{}:
	default:
	}
}

func (b *Blocklist) Refresh(ctx context.Context) {
	b.Updating.Store(true)
	defer b.Updating.Store(false)
	var rs []io.Reader
	b.mu.Lock()
	urls := append([]string(nil), b.URLs...)
	b.mu.Unlock()
	for _, u := range urls {
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := b.client.Do(req)
		if err != nil {
			log.Printf("blocklist: %s: %v", u, err)
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 {
			log.Printf("blocklist: %s: status %d %v", u, resp.StatusCode, err)
			continue
		}
		rs = append(rs, strings.NewReader(string(body)))
	}
	for _, f := range b.Files {
		if data, err := os.ReadFile(f); err == nil {
			rs = append(rs, strings.NewReader(string(data)))
		}
	}
	b.mu.Lock()
	nd := len(b.Deny)
	b.mu.Unlock()
	if len(rs) == 0 && b.Size() > nd {
		return // keep the previous list on total failure
	}
	n := b.Load(rs)
	log.Printf("blocklist: %d domains loaded", n)
}

// Run downloads the lists while blocking is on (flag or dashboard). When it is off nothing
// is downloaded; switching it on from the dashboard kicks a download at once.
func (b *Blocklist) Run(ctx context.Context, every time.Duration) {
	if b.On() {
		b.Refresh(ctx)
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if b.On() {
				b.Refresh(ctx)
			}
		case <-b.kick:
			if b.On() {
				b.Refresh(ctx)
			}
		}
	}
}

// On: blocking is available (the -blocking flag or v2.7.0 dashboard switch).
func (b *Blocklist) On() bool { return b != nil && (b.Enabled || b.live.Load()) }

// SetSources (v2.7.0) replaces the subscription URLs and allow / block lists from the
// dashboard. nil keeps the current value. Returns whether a re-download is needed.
func (b *Blocklist) SetSources(on bool, urls, allow, deny []string) bool {
	b.mu.Lock()
	changed := !equalStrings(b.URLs, urls) && urls != nil
	if urls != nil {
		b.URLs = urls
	}
	listsChanged := (allow != nil && !equalStrings(b.Allow, allow)) || (deny != nil && !equalStrings(b.Deny, deny))
	if allow != nil {
		b.Allow = allow
	}
	if deny != nil {
		b.Deny = deny
	}
	b.mu.Unlock()
	was := b.live.Swap(on)
	if listsChanged && !changed && b.Size() > 0 {
		b.reapplyLists()
	}
	need := on && (!was || changed || b.Size() == 0)
	if need {
		b.UpdateNow()
	}
	return need
}

// reapplyLists rebuilds allow / deny on top of the downloaded set (no download).
func (b *Blocklist) reapplyLists() {
	b.mu.Lock()
	defer b.mu.Unlock()
	m := map[string]struct{}{}
	for k := range *b.set.Load() {
		m[k] = struct{}{}
	}
	for _, d := range b.Deny {
		addDomain(d, m)
	}
	a := map[string]struct{}{}
	for _, d := range b.Allow {
		addDomain(d, a)
	}
	b.set.Store(&m)
	b.allow.Store(&a)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (b *Blocklist) Size() int { return len(*b.set.Load()) }

// Blocked reports whether name (or a parent domain) is blocked and not allowed.
func (b *Blocklist) Blocked(name string) bool {
	if !b.On() || b.paused.Load() {
		return false
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	set, allow := *b.set.Load(), *b.allow.Load()
	if len(set) == 0 {
		return false
	}
	for d := name; d != ""; {
		if _, ok := allow[d]; ok {
			return false
		}
		if _, ok := set[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}
