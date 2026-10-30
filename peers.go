// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.6.0 multi-server dashboard. One GoProxy can show and control its peers (e.g. the
// primary server 192.168.1.108 and the NAS container 192.168.1.75).
//
// Peer link: every server that should be reachable sets the same shared peer token
// (Advanced > Servers; stored AES-GCM encrypted, see secrets.go). The peer API
// (/api/peer/status, /api/peer/flush, /api/peer/blocking) is
//   - LAN only (private / loopback source address),
//   - authenticated by the X-GoProxy-Peer header (constant-time compare),
//   - read-mostly: status, plus flush cache and filter on/off. Nothing else.
// The local admin (normal login + CSRF) asks the peers through /api/peers; a peer that is
// down or misconfigured shows as an error card, it never breaks the dashboard.

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	peerHeader   = "X-GoProxy-Peer"
	peerTimeout  = 2500 * time.Millisecond
	maxPeers     = 8
	minPeerToken = 16
)

// PeerEntry is one other GoProxy dashboard, e.g. {"NAS", "http://192.168.1.75:8080"}.
type PeerEntry struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// PeerStatus is what a peer shares: no clients, no logs, no settings.
type PeerStatus struct {
	Name          string         `json:"name"`
	Version       string         `json:"version"`
	UptimeSec     int64          `json:"uptime_sec"`
	Queries       int64          `json:"queries"`
	QPS           float64        `json:"qps"`
	HitRatio      float64        `json:"hit_ratio"`
	BlockedRatio  float64        `json:"blocked_ratio"`
	P50Ms         float64        `json:"p50_ms"`
	P99Ms         float64        `json:"p99_ms"`
	CacheEntries  int64          `json:"cache_entries"`
	BlockingOn    bool           `json:"blocking_on"`
	BlockingAvail bool           `json:"blocking_available"`
	ParallelAll   bool           `json:"parallel_all"`
	LastWinner    string         `json:"last_winner,omitempty"`
	Offline       bool           `json:"internet_down"`
	Profile       string         `json:"profile"`
	DevVolOn      bool           `json:"device_volume"`
	Devices       []DeviceVolRow `json:"devices,omitempty"`
}

func validatePeers(ps []PeerEntry) error {
	if len(ps) > maxPeers {
		return fmt.Errorf("at most %d servers", maxPeers)
	}
	for _, p := range ps {
		u, err := url.Parse(strings.TrimSpace(p.URL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%q: use a URL like http://192.168.1.75:8080", p.URL)
		}
		if ip := net.ParseIP(u.Hostname()); ip == nil || !isPrivateIP(ip.String()) {
			return fmt.Errorf("%q: peers must be a LAN IP address (no names, nothing on the internet)", p.URL)
		}
	}
	return nil
}

func (s *DNSServer) peerStatus() PeerStatus {
	st := s.snapshot()
	h, _ := os.Hostname()
	return PeerStatus{Name: h, Version: Version, UptimeSec: st.UptimeSec, Queries: st.Queries, QPS: st.QPS, HitRatio: st.HitRatio,
		BlockedRatio: st.BlockedRatio, P50Ms: st.P50Ms, P99Ms: st.P99Ms, CacheEntries: st.CacheEntries,
		BlockingOn: s.bl.On() && !s.bl.paused.Load(), BlockingAvail: s.bl.On(), ParallelAll: st.ParallelAll,
		LastWinner: st.LastWinner, Offline: s.res.Offline(), Profile: s.profile,
		DevVolOn: s.devvol != nil && s.devvol.On.Load(), Devices: s.deviceVolume()}
}

// peerAuthOK: LAN source + the shared token (an empty token = peer API off).
func (s *DNSServer) peerAuthOK(r *http.Request) bool {
	tok := s.settings.Get().PeerToken
	got := r.Header.Get(peerHeader)
	if len(tok) < minPeerToken || got == "" || !isPrivateIP(remoteIP(r)) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(got)) == 1
}

// servePeerAPI handles the incoming side (called by other GoProxy servers).
func (s *DNSServer) servePeerAPI(w http.ResponseWriter, r *http.Request) {
	if !s.peerAuthOK(r) {
		jsonErr(w, 403, "peer link not allowed")
		return
	}
	switch r.URL.Path {
	case "/api/peer/status":
		writeJSON(w, s.peerStatus())
	case "/api/peer/sync": // v2.7.0: synced settings (no secrets) + newest-change stamp
		writeJSON(w, s.peerSyncState())
	case "/api/peer/flush":
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST only")
			return
		}
		n := s.cache.Flush()
		auditf("peer "+remoteIP(r), "cache flushed", "")
		writeJSON(w, map[string]any{"ok": true, "flushed": n})
	case "/api/peer/blocking":
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST only")
			return
		}
		if !s.bl.On() {
			jsonErr(w, 409, "ad blocking is not available on this server")
			return
		}
		on := r.URL.Query().Get("enabled") != "false"
		s.setBlockingPaused(!on, "peer "+remoteIP(r))
		writeJSON(w, map[string]any{"ok": true, "blocking_on": on})
	default:
		jsonErr(w, 404, "unknown peer call")
	}
}

var peerClient = &http.Client{Timeout: peerTimeout, Transport: &http.Transport{
	Proxy: nil, MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: peerTimeout,
	DialContext: (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext}}

func peerCall(ctx context.Context, p PeerEntry, tok, method, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, peerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.URL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set(peerHeader, tok)
	resp, err := peerClient.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return errors.New("not answering (timeout)")
		}
		return errors.New("unreachable")
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode == 403 {
		return errors.New("peer token rejected (set the same token on both servers)")
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	return json.Unmarshal(b, out)
}

type peerView struct {
	PeerEntry
	OK     bool        `json:"ok"`
	Error  string      `json:"error,omitempty"`
	Status *PeerStatus `json:"status,omitempty"`
	Local  bool        `json:"local,omitempty"`
}

// servePeers: GET = this server + every peer (in parallel, each with its own timeout);
// POST {index, action: flush|blocking_on|blocking_off} = act on one peer.
func (s *DNSServer) servePeers(w http.ResponseWriter, r *http.Request) {
	st := s.settings.Get()
	if r.Method == http.MethodPost {
		var b struct {
			Index  int    `json:"index"`
			Action string `json:"action"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b); err != nil || b.Index < 0 || b.Index >= len(st.Peers) {
			jsonErr(w, 400, "bad request")
			return
		}
		p := st.Peers[b.Index]
		path := map[string]string{"flush": "/api/peer/flush", "blocking_on": "/api/peer/blocking?enabled=true", "blocking_off": "/api/peer/blocking?enabled=false"}[b.Action]
		if path == "" {
			jsonErr(w, 400, "unknown action")
			return
		}
		var out map[string]any
		if err := peerCall(r.Context(), p, st.PeerToken, http.MethodPost, path, &out); err != nil {
			jsonErr(w, 502, p.Name+": "+err.Error())
			return
		}
		auditf(remoteIP(r), "peer "+b.Action, p.Name)
		writeJSON(w, out)
		return
	}
	ls := s.peerStatus()
	views := make([]peerView, len(st.Peers)+1)
	views[0] = peerView{PeerEntry: PeerEntry{Name: "This server", URL: ""}, OK: true, Status: &ls, Local: true}
	var wg sync.WaitGroup
	for i, p := range st.Peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := peerView{PeerEntry: p}
			var ps PeerStatus
			if st.PeerToken == "" {
				v.Error = "no peer token set"
			} else if err := peerCall(r.Context(), p, st.PeerToken, http.MethodGet, "/api/peer/status", &ps); err != nil {
				v.Error = err.Error()
			} else {
				v.OK, v.Status = true, &ps
			}
			views[i+1] = v
		}()
	}
	wg.Wait()
	writeJSON(w, map[string]any{"servers": views, "has_token": st.PeerToken != ""})
}

// servePeerConfig: GET the list (never the token); POST {peers, token?} saves them.
func (s *DNSServer) servePeerConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var b struct {
			Peers []PeerEntry `json:"peers"`
			Token *string     `json:"token"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&b); err != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		if err := validatePeers(b.Peers); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if b.Token != nil && *b.Token != "" && len(*b.Token) < minPeerToken {
			jsonErr(w, 400, fmt.Sprintf("peer token: at least %d characters", minPeerToken))
			return
		}
		_, _, err := s.settings.Update(remoteIP(r), "servers (peers)", func(st *Settings) error {
			st.Peers = b.Peers
			if b.Token != nil {
				st.PeerToken = *b.Token
			}
			return nil
		})
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
	}
	st := s.settings.Get()
	writeJSON(w, map[string]any{"peers": st.Peers, "has_token": st.PeerToken != ""})
}

// serveHealthz is the unauthenticated /health for Uptime Kuma & co: status only, no data.
// 200 "ok" when DNS can reach the internet, 503 "degraded" while every upstream fails.
func (s *DNSServer) serveHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.res.Offline() {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "degraded\n")
		return
	}
	_, _ = io.WriteString(w, "ok\n")
}
