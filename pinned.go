// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"sort"
	"strings"
	"sync"
)

const defaultPinned = "youtube.com,www.youtube.com,m.youtube.com,i.ytimg.com,yt3.ggpht.com,youtubei.googleapis.com,netflix.com,www.netflix.com,api-global.netflix.com,assets.nflxext.com"

// Pinned is the set of names that are always kept cached and refreshed, plus suffixes
// whose observed hosts are pinned automatically (e.g. *.googlevideo.com).
type Pinned struct {
	mu       sync.RWMutex
	m        map[string]bool // name -> auto-pinned?
	suffixes []string
	max      int
}

func NewPinned(names, autoSuffixes []string) *Pinned {
	p := &Pinned{m: map[string]bool{}, max: 1024}
	for _, n := range names {
		if n = normName(n); n != "" {
			p.m[n] = false
		}
	}
	for _, s := range autoSuffixes {
		if s = normName(s); s != "" {
			p.suffixes = append(p.suffixes, s)
		}
	}
	return p
}

func normName(n string) string {
	return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), "."), "*.")
}

// Observe auto-pins name if it falls under an auto-pin suffix. Cheap on the hot path.
func (p *Pinned) Observe(name string) {
	if p == nil {
		return
	}
	for _, s := range p.suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			p.mu.RLock()
			_, ok := p.m[name]
			full := len(p.m) >= p.max
			p.mu.RUnlock()
			if !ok && !full {
				p.mu.Lock()
				p.m[name] = true
				p.mu.Unlock()
			}
			return
		}
	}
}

// Has reports whether name (lower case, no trailing dot) is pinned, by hand or automatically.
func (p *Pinned) Has(name string) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	_, ok := p.m[name]
	p.mu.RUnlock()
	return ok
}

type pinView struct {
	Name    string `json:"name"`
	Auto    bool   `json:"auto"`
	Service string `json:"service"`
}

// serviceOf groups pinned names for the dashboard.
func serviceOf(n string) string {
	for _, x := range []struct{ svc, suf string }{
		{"YouTube", "youtube.com"}, {"YouTube", "ytimg.com"}, {"YouTube", "ggpht.com"}, {"YouTube", "googlevideo.com"}, {"YouTube", "youtubei.googleapis.com"},
		{"Netflix", "netflix.com"}, {"Netflix", "nflxext.com"}, {"Netflix", "nflxso.net"}, {"Netflix", "nflxvideo.net"},
		{"Connectivity checks", "gstatic.com"}, {"Connectivity checks", "clients3.google.com"}, {"Connectivity checks", "connectivitycheck.android.com"},
		{"Connectivity checks", "captive.apple.com"}, {"Connectivity checks", "msftconnecttest.com"}, {"Connectivity checks", "msftncsi.com"}, {"Connectivity checks", "detectportal.firefox.com"},
	} {
		if n == x.suf || strings.HasSuffix(n, "."+x.suf) {
			return x.svc
		}
	}
	return "Other"
}

func (p *Pinned) List() []pinView {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	out := make([]pinView, 0, len(p.m))
	for n, a := range p.m {
		out = append(out, pinView{n, a, serviceOf(n)})
	}
	p.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Service != out[j].Service {
			return svcRank(out[i].Service) < svcRank(out[j].Service)
		}
		if out[i].Auto != out[j].Auto {
			return !out[i].Auto
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (p *Pinned) suffixesOrNil() []string {
	if p == nil {
		return nil
	}
	return p.suffixes
}

func svcRank(s string) int {
	switch s {
	case "YouTube":
		return 0
	case "Netflix":
		return 1
	case "Connectivity checks":
		return 2
	}
	return 3
}
