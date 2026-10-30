// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.1 Pro mode APIs: query log search, cache inspector, per-upstream latency histograms
// and race details, and raw metrics in Prometheus text format.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func (x *V28) registerPro(mux *http.ServeMux) {
	mux.HandleFunc("/api/v28/pro/log", x.serveProLog)
	mux.HandleFunc("/api/v28/pro/cache", x.serveProCache)
	mux.HandleFunc("/api/v28/pro/upstreams", x.serveProUpstreams)
	mux.HandleFunc("/api/v28/pro/metrics", x.serveProMetrics)
}

func (x *V28) serveProLog(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	needle := strings.ToLower(strings.TrimSpace(q.Get("q")))
	res, cl, ty, up := q.Get("result"), q.Get("client"), strings.ToUpper(q.Get("type")), q.Get("upstream")
	minMs, _ := strconv.ParseFloat(q.Get("min_ms"), 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	all := x.s.logs.All()
	out := make([]LogEntry, 0, min(limit, len(all)))
	counts := map[string]int{}
	for _, e := range all {
		if needle != "" && !strings.Contains(strings.ToLower(e.Domain), needle) && !strings.Contains(e.Client, needle) {
			continue
		}
		if cl != "" && e.Client != cl || ty != "" && e.Type != ty || up != "" && !strings.Contains(e.Upstream, up) || e.LatencyMs < minMs {
			continue
		}
		counts[e.Result]++
		if res != "" && e.Result != res {
			continue
		}
		if len(out) < limit {
			out = append(out, e)
		}
	}
	writeJSON(w, map[string]any{"entries": out, "kept": len(all), "counts": counts})
}

type cacheView struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     int64    `json:"ttl_sec"` // negative = stale for that long
	OrigTTL uint32   `json:"orig_ttl"`
	Hits    int64    `json:"hits"`
	Bytes   int64    `json:"bytes"`
	Neg     bool     `json:"negative"`
	Answers []string `json:"answers"`
	AgeSec  int64    `json:"age_sec"`
}

func (x *V28) serveProCache(w http.ResponseWriter, r *http.Request) {
	c := x.s.cache
	if r.Method == http.MethodPost {
		var b struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&b); err != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		n := 0
		if b.Key != "" && c.Delete(b.Key) {
			n++
		}
		if b.Name != "" { // every type of this name
			for _, t := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeSRV, dns.TypePTR, dns.TypeSOA} {
				if c.Delete(cacheKey(b.Name, t, dns.ClassINET)) {
					n++
				}
			}
		}
		writeJSON(w, map[string]any{"ok": true, "removed": n})
		return
	}
	sub := r.URL.Query().Get("q")
	keys, ents, total := c.Find(sub, 200)
	now := c.now()
	out := make([]cacheView, 0, len(keys))
	for i, k := range keys {
		e := ents[i]
		name, ty, _ := strings.Cut(k, "|")
		ty, _, _ = strings.Cut(ty, "|")
		v := cacheView{Key: k, Name: strings.TrimSuffix(name, "."), Type: ty, TTL: int64(e.Expires.Sub(now) / time.Second), OrigTTL: e.OrigTTL,
			Hits: e.Hits.Load(), Bytes: e.size, Neg: e.Negative, AgeSec: int64(now.Sub(e.Stored) / time.Second)}
		for j, rr := range e.Msg.Answer {
			if j == 6 {
				v.Answers = append(v.Answers, fmt.Sprintf("+%d more", len(e.Msg.Answer)-6))
				break
			}
			h := rr.Header()
			v.Answers = append(v.Answers, dns.TypeToString[h.Rrtype]+" "+strings.TrimPrefix(rr.String(), h.String()))
		}
		out = append(out, v)
	}
	writeJSON(w, map[string]any{"entries": out, "matched": total, "entries_total": c.entries.Load()})
}

func (u *Upstream) latHist() (h [impBuckets]uint64, p50, p95 float64) {
	u.latMu.Lock()
	n := u.latCnt
	xs := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		v := float64(u.latBuf[i]) / 1e6
		xs = append(xs, v)
		h[impBucket(v)]++
	}
	u.latMu.Unlock()
	if len(xs) > 0 {
		sort.Float64s(xs)
		p50, p95 = xs[len(xs)/2], xs[min(len(xs)-1, len(xs)*95/100)]
	}
	return
}

func (x *V28) serveProUpstreams(w http.ResponseWriter, r *http.Request) {
	rs := x.s.res
	stats := rs.Stats()
	type up struct {
		UpstreamStat
		Hist   [impBuckets]uint64 `json:"hist"`
		P50    float64            `json:"p50_ms"`
		Recent int                `json:"recent_n"`
		Warms  int64              `json:"warms"`
		H3OK   int64              `json:"h3_ok"`
	}
	var out []up
	ups := append(append([]*Upstream{}, rs.Ups()...), rs.Fallback...)
	for i, st := range stats {
		v := up{UpstreamStat: st}
		if i < len(ups) {
			v.Hist, v.P50, _ = ups[i].latHist()
			for _, c := range v.Hist {
				v.Recent += int(c)
			}
			v.Warms, v.H3OK = ups[i].Warms.Load(), ups[i].H3OK.Load()
		}
		out = append(out, v)
	}
	writeJSON(w, map[string]any{"upstreams": out, "bounds_ms": impBounds, "hedged": rs.Hedged.Load(), "last_winner": rs.LastWinner(),
		"parallel_all": rs.ParallelAll.Load(), "smart": rs.Smart.Load(), "smart_n": rs.SmartN.Load(), "widened": rs.Widened()})
}

func (x *V28) serveProMetrics(w http.ResponseWriter, r *http.Request) {
	st := x.s.stats
	var b strings.Builder
	g := func(name, help string, v any, labels ...string) {
		l := ""
		if len(labels) > 0 {
			l = "{" + strings.Join(labels, ",") + "}"
		}
		fmt.Fprintf(&b, "# HELP goproxy_%s %s\ngoproxy_%s%s %v\n", name, help, name, l, v)
	}
	g("info", "version", 1, fmt.Sprintf(`version=%q`, Version))
	g("queries_total", "all queries", st.Queries.Load())
	g("cache_hits_total", "fresh cache answers", st.Hits.Load())
	g("stale_hits_total", "stale answers (RFC 8767)", st.StaleHits.Load())
	g("misses_total", "cache misses", st.Misses.Load())
	g("blocked_total", "blocked", st.Blocked.Load())
	g("failures_total", "failed lookups", st.Failures.Load())
	g("prefetches_total", "prefetches", st.Prefetches.Load())
	g("cache_entries", "entries in RAM", x.s.cache.entries.Load())
	g("cache_bytes", "bytes in RAM", x.s.cache.Bytes())
	g("hedged_total", "lookups where the hedge fired", x.s.res.Hedged.Load())
	for _, u := range x.s.res.Ups() {
		lb := fmt.Sprintf(`upstream=%q,proto=%q`, upName(u), u.Proto())
		fmt.Fprintf(&b, "goproxy_upstream_queries_total{%s} %d\n", lb, u.Queries.Load())
		fmt.Fprintf(&b, "goproxy_upstream_wins_total{%s} %d\n", lb, u.Wins.Load())
		fmt.Fprintf(&b, "goproxy_upstream_errors_total{%s} %d\n", lb, u.Errors.Load())
		fmt.Fprintf(&b, "goproxy_upstream_probe_ms{%s} %.2f\n", lb, float64(u.probeEWMA.Load())/1e6)
		fmt.Fprintf(&b, "goproxy_upstream_warms_total{%s} %d\n", lb, u.Warms.Load())
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(b.String()))
}
