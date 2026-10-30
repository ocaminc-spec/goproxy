// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"os"
)

// savedState is query history + lifetime counters, persisted next to the cache snapshot.
type savedState struct {
	Version  string           `json:"version"`
	Domains  []hostStat       `json:"domains"`
	Blocked  []hostStat       `json:"blocked"`
	Clients  []hostStat       `json:"clients"`
	Counters map[string]int64 `json:"counters"`
	QTypes   map[string]int64 `json:"qtypes"`
	AdsDaily map[string]int64 `json:"ads_daily,omitempty"` // v2.4.2: filter blocks per day
}

func (s *DNSServer) SaveState(path string) error {
	st := savedState{Version: Version, Domains: s.domains.Top(5000), Blocked: s.blocked.Top(2000), Clients: s.clients.Top(1024),
		Counters: map[string]int64{"queries": s.stats.Queries.Load(), "hits": s.stats.Hits.Load(), "stale_hits": s.stats.StaleHits.Load(),
			"misses": s.stats.Misses.Load(), "blocked": s.stats.Blocked.Load(), "forwarded": s.stats.Forwarded.Load(), "failures": s.stats.Failures.Load(),
			"stale_rescued": s.stats.StaleRescued.Load(), "prefetches": s.stats.Prefetches.Load(), "refreshes": s.stats.Refreshes.Load(), "siblings": s.stats.Siblings.Load(),
			"keep_hot": s.stats.KeepHot.Load(), "warmed": s.stats.Warmed.Load(), "pinned": s.stats.Pinned.Load(), "coalesced": s.stats.Coalesced.Load()},
		QTypes: map[string]int64{}, AdsDaily: s.ads.snapshot()}
	for i := range s.stats.QTypes {
		if v := s.stats.QTypes[i].Load(); v > 0 {
			st.QTypes[qtypeName(uint16(i))] = v
		}
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := writeFileSync(path+".tmp", b); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

// LoadState restores history and counters; it returns the domains ranked by popularity.
func (s *DNSServer) LoadState(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st savedState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	s.domains.Restore(st.Domains)
	s.blocked.Restore(st.Blocked)
	s.clients.Restore(st.Clients)
	s.ads.restore(st.AdsDaily)
	c := st.Counters
	s.stats.Queries.Add(c["queries"])
	s.stats.Hits.Add(c["hits"])
	s.stats.StaleHits.Add(c["stale_hits"])
	s.stats.Misses.Add(c["misses"])
	s.stats.Blocked.Add(c["blocked"])
	s.stats.Forwarded.Add(c["forwarded"])
	s.stats.Failures.Add(c["failures"])
	s.stats.StaleRescued.Add(c["stale_rescued"])
	s.stats.Prefetches.Add(c["prefetches"])
	s.stats.Refreshes.Add(c["refreshes"])
	s.stats.Siblings.Add(c["siblings"])
	s.stats.KeepHot.Add(c["keep_hot"])
	s.stats.Warmed.Add(c["warmed"])
	s.stats.Pinned.Add(c["pinned"])
	s.stats.Coalesced.Add(c["coalesced"])
	for name, v := range st.QTypes {
		if t := qtypeFromName(name); t < 256 {
			s.stats.QTypes[t].Add(v)
		}
	}
	var names []string
	for _, d := range st.Domains {
		names = append(names, d.Host)
	}
	return names, nil
}

func writeFileSync(path string, b []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
