// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// "Why was this blocked / answered?" (v2.4.2). Read-only: looks at the cache, the pinned
// list, the blocklist, the Ads & Tracking filter (for a given device) and the recent log.
// It never sends anything upstream and never changes the cache.

type whyCache struct {
	Type    string `json:"type"`
	State   string `json:"state"` // fresh | stale | not cached
	TTLLeft int64  `json:"ttl_left_sec,omitempty"`
	Hits    int64  `json:"hits,omitempty"`
	Answer  string `json:"answer,omitempty"`
}

type whyView struct {
	Name        string     `json:"name"`
	Client      string     `json:"client,omitempty"`
	Verdict     string     `json:"verdict"`
	Steps       []string   `json:"steps"`
	Local       string     `json:"local,omitempty"`
	Pinned      bool       `json:"pinned"`
	Service     string     `json:"service,omitempty"`
	Protected   bool       `json:"protected"`
	Blocklist   bool       `json:"blocklist_blocks"`
	AdsListed   bool       `json:"ads_listed"`
	AdsMatch    string     `json:"ads_match,omitempty"`
	AdsOn       bool       `json:"ads_on_for_client"`
	AdsWhy      string     `json:"ads_reason"`
	Cache       []whyCache `json:"cache"`
	Recent      []LogEntry `json:"recent"`
	LastUpsteam string     `json:"last_upstream,omitempty"`
}

func validLookupName(n string) bool {
	if n == "" || len(n) > 253 || strings.ContainsAny(n, " /:@\\") {
		return false
	}
	_, ok := dns.IsDomainName(n)
	return ok
}

func (s *DNSServer) Why(name, client string) whyView {
	name = normName(name)
	v := whyView{Name: name, Client: client}
	if client != "" {
		client = normIP(client)
		v.Client = client
	}
	fq := dns.Fqdn(name)
	// 1. local names
	if zp := s.local.Load(); zp != nil {
		if ips, ok := (*zp)[name]; ok {
			v.Local = strings.Join(func() []string {
				var o []string
				for _, ip := range ips {
					o = append(o, ip.String())
				}
				return o
			}(), ", ")
		}
	}
	// 2. pinned / protected
	if s.pinned != nil {
		s.pinned.mu.RLock()
		_, v.Pinned = s.pinned.m[name]
		s.pinned.mu.RUnlock()
		if !v.Pinned {
			for _, sfx := range s.pinned.suffixes {
				if name == sfx || strings.HasSuffix(name, "."+sfx) {
					v.Pinned = true
				}
			}
		}
	}
	if sv := serviceOf(name); sv != "Other" {
		v.Service = sv
	}
	v.Protected = s.protectedName(name)
	// 3. filters
	v.Blocklist = s.bl.Blocked(fq)
	v.AdsListed, v.AdsMatch = s.ads.Listed(fq)
	v.AdsOn, v.AdsWhy = s.ads.Decision(client)
	// 4. cache
	now := s.cache.now()
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS} {
		c := whyCache{Type: dns.TypeToString[t], State: "not cached"}
		if e, fresh := s.cache.Get(cacheKey(fq, t, dns.ClassINET)); e != nil {
			c.State, c.Hits = "stale", e.Hits.Load()
			if fresh {
				c.State, c.TTLLeft = "fresh", int64(e.Expires.Sub(now)/time.Second)
			}
			q := new(dns.Msg)
			q.SetQuestion(fq, t)
			if r := e.Reply(q, now, !fresh); r != nil {
				var parts []string
				for _, rr := range r.Answer {
					switch x := rr.(type) {
					case *dns.A:
						parts = append(parts, x.A.String())
					case *dns.AAAA:
						parts = append(parts, x.AAAA.String())
					case *dns.CNAME:
						parts = append(parts, "→ "+strings.TrimSuffix(x.Target, "."))
					}
					if len(parts) >= 6 {
						break
					}
				}
				if len(parts) == 0 {
					parts = append(parts, dns.RcodeToString[r.Rcode]+" (no address)")
				}
				c.Answer = strings.Join(parts, ", ")
			}
		}
		v.Cache = append(v.Cache, c)
	}
	// 5. recent lookups of this name (newest first)
	all, _ := s.logs.Since(0)
	for i := len(all) - 1; i >= 0 && len(v.Recent) < 10; i-- {
		if all[i].Domain == name {
			v.Recent = append(v.Recent, all[i])
			if v.LastUpsteam == "" && all[i].Upstream != "" {
				v.LastUpsteam = all[i].Upstream
			}
		}
	}
	if v.LastUpsteam == "" && s.flight != nil {
		fl := s.flight.Snapshot()
		for i := len(fl) - 1; i >= 0; i-- {
			if fl[i].Name == name && fl[i].Up != "" {
				v.LastUpsteam = fl[i].Up
				break
			}
		}
	}
	// verdict, in the same order the server decides
	step := func(s string) { v.Steps = append(v.Steps, s) }
	switch {
	case v.Local != "":
		v.Verdict = "answered by GoProxy itself (local name → " + v.Local + ")"
		step("1. Local names: match → answered here, nothing else is checked.")
	case v.Blocklist:
		v.Verdict = "blocked by the ad-blocking blocklist"
		step("1. Local names: no match.")
		step("2. Blocklist (Pi-hole style, -blocking): BLOCKED.")
	case v.AdsListed && v.AdsOn:
		v.Verdict = "blocked by the Ads & Tracking filter (" + v.AdsMatch + ", " + v.AdsWhy + ")"
		step("1. Local names: no match.")
		step("2. Blocklist: not blocked.")
		step("3. Ads & Tracking filter: on the list (" + v.AdsMatch + ") and ON for this device → BLOCKED.")
	default:
		step("1. Local names: no match.")
		step("2. Blocklist: not blocked" + map[bool]string{true: " (protected)", false: ""}[v.Protected] + ".")
		switch {
		case v.Protected:
			step("3. Ads & Tracking filter: protected name (pinned / connectivity check / video player): never blocked.")
		case v.AdsListed:
			step("3. Ads & Tracking filter: on the list (" + v.AdsMatch + ") but OFF for this device (" + v.AdsWhy + ").")
		default:
			step("3. Ads & Tracking filter: not on the list.")
		}
		st := "not cached: the next lookup goes to the upstreams"
		for _, c := range v.Cache {
			if c.Type == "A" && c.State != "not cached" {
				st = "cached (" + c.State + ")"
			}
		}
		step("4. Cache (A record): " + st + ".")
		v.Verdict = "answered normally (" + st + ")"
		if v.LastUpsteam != "" {
			step("5. Last upstream that answered it: " + v.LastUpsteam + ".")
		}
	}
	if v.Pinned {
		step("Pinned: kept cached and refreshed before it expires (" + orStr(v.Service, "pinned") + ").")
	}
	return v
}

func (s *DNSServer) serveWhy(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("name")))
	name = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(name, "https://"), "http://"), "/")
	if i := strings.IndexByte(name, '/'); i >= 0 {
		name = name[:i]
	}
	if !validLookupName(name) {
		jsonErr(w, 400, "enter a domain name like doubleclick.net")
		return
	}
	client := strings.TrimSpace(r.URL.Query().Get("client"))
	if client != "" && net.ParseIP(client) == nil {
		jsonErr(w, 400, "device must be an IP address")
		return
	}
	writeJSON(w, s.Why(name, client))
}
