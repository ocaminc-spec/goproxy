// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.6.0 Health panel: Uptime Kuma monitors shown inside the GoProxy dashboard. GoProxy
// reads Kuma's PUBLIC status-page JSON (no login, no API key needed):
//   GET <kuma>/api/status-page/<slug>             monitor names / ids
//   GET <kuma>/api/status-page/heartbeat/<slug>   recent beats + 24 h uptime per monitor
// Kuma must be on the LAN (private IP). Failures show as "Uptime Kuma unreachable", never
// break the dashboard. Results are cached 20 s so many open dashboards don't hammer Kuma.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type kumaMonitor struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Up        *bool   `json:"up"` // nil = no beats yet
	PingMs    float64 `json:"ping_ms"`
	Uptime24h float64 `json:"uptime_24h"` // 0..1
	Msg       string  `json:"msg,omitempty"`
}

var kumaSlugRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

func validateKuma(base, slug string) error {
	if base == "" {
		return nil
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("Uptime Kuma URL must look like http://192.168.1.123:3001")
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !isPrivateIP(ip.String()) {
		return fmt.Errorf("Uptime Kuma must be a LAN IP address")
	}
	if slug != "" && !kumaSlugRE.MatchString(slug) {
		return fmt.Errorf("status page slug: lowercase letters, digits and - only")
	}
	return nil
}

var (
	kumaMu    sync.Mutex
	kumaCache struct {
		key string
		at  time.Time
		v   map[string]any
	}
)

func kumaGet(ctx context.Context, u string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := peerClient.Do(req)
	if err != nil {
		return fmt.Errorf("unreachable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d (does the status page exist?)", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(out)
}

// fetchKuma reads both endpoints and merges them per monitor.
func fetchKuma(ctx context.Context, base, slug string) ([]kumaMonitor, error) {
	base = strings.TrimRight(base, "/")
	var page struct {
		PublicGroupList []struct {
			MonitorList []struct {
				ID   int    `json:"id"`
				Name string `json:"name"`
			} `json:"monitorList"`
		} `json:"publicGroupList"`
	}
	if err := kumaGet(ctx, base+"/api/status-page/"+slug, &page); err != nil {
		return nil, err
	}
	var hb struct {
		HeartbeatList map[string][]struct {
			Status int      `json:"status"`
			Ping   *float64 `json:"ping"`
			Msg    string   `json:"msg"`
		} `json:"heartbeatList"`
		UptimeList map[string]float64 `json:"uptimeList"`
	}
	if err := kumaGet(ctx, base+"/api/status-page/heartbeat/"+slug, &hb); err != nil {
		return nil, err
	}
	var out []kumaMonitor
	for _, g := range page.PublicGroupList {
		for _, m := range g.MonitorList {
			km := kumaMonitor{ID: m.ID, Name: m.Name}
			id := strconv.Itoa(m.ID)
			if beats := hb.HeartbeatList[id]; len(beats) > 0 {
				b := beats[len(beats)-1]
				up := b.Status == 1
				km.Up = &up
				if b.Ping != nil {
					km.PingMs = *b.Ping
				}
				if !up {
					km.Msg = b.Msg
				}
			}
			km.Uptime24h = hb.UptimeList[id+"_24"]
			out = append(out, km)
		}
	}
	return out, nil
}

func (s *DNSServer) serveKuma(w http.ResponseWriter, r *http.Request) {
	st := s.settings.Get()
	if st.KumaURL == "" {
		writeJSON(w, map[string]any{"configured": false})
		return
	}
	slug := st.KumaSlug
	if slug == "" {
		slug = "dns"
	}
	key := st.KumaURL + "|" + slug
	kumaMu.Lock()
	if kumaCache.key == key && time.Since(kumaCache.at) < 20*time.Second {
		v := kumaCache.v
		kumaMu.Unlock()
		writeJSON(w, v)
		return
	}
	kumaMu.Unlock()
	mons, err := fetchKuma(r.Context(), st.KumaURL, slug)
	v := map[string]any{"configured": true, "url": st.KumaURL, "slug": slug, "monitors": mons}
	if err != nil {
		v["error"] = "Uptime Kuma: " + err.Error()
	}
	kumaMu.Lock()
	kumaCache.key, kumaCache.at, kumaCache.v = key, time.Now(), v
	kumaMu.Unlock()
	writeJSON(w, v)
}
