// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.8.0 query metadata time-series: one fixed 128-byte record per minute in a ring file
// (30 days = 43,200 slots, ~5.5 MB max, never grows). Aggregates only: results, query
// types, response codes, latency histogram, forwarded latency, distinct clients (estimate).

import (
	"encoding/binary"
	"hash/maphash"
	"math"
	"math/bits"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tsSlots   = 30 * 1440
	tsRecSize = 128
	tsFields  = 30
)

// field indexes (uint32 each, after T)
const (
	tfQ = iota
	tfCached
	tfFwd
	tfBlocked
	tfFailed
	tfStale
	tfLocal
	tfThreat
	tfFlagged
	tfA
	tfAAAA
	tfHTTPS
	tfOtherType
	tfNoErr
	tfNX
	tfServfail
	tfRcOther
	tfClients
	tfHist // 11 buckets
	tfEnd  = tfHist + 11
)

type tsAcc struct {
	min    int64
	c      [tfEnd]atomic.Uint32
	fwdSum atomic.Uint64 // microseconds
	bitmap [64]atomic.Uint64
}

type TSPoint struct {
	T        int64      `json:"t"` // unix seconds (start)
	Q        uint32     `json:"q"`
	Cached   uint32     `json:"cached"`
	Fwd      uint32     `json:"fwd"`
	Blocked  uint32     `json:"blocked"`
	Failed   uint32     `json:"failed"`
	Stale    uint32     `json:"stale"`
	Local    uint32     `json:"local"`
	Threat   uint32     `json:"threat"`
	Flagged  uint32     `json:"flagged"`
	A        uint32     `json:"a"`
	AAAA     uint32     `json:"aaaa"`
	HTTPS    uint32     `json:"https"`
	Other    uint32     `json:"other_type"`
	NoErr    uint32     `json:"noerror"`
	NX       uint32     `json:"nxdomain"`
	Servfail uint32     `json:"servfail"`
	RcOther  uint32     `json:"rc_other"`
	Clients  uint32     `json:"clients"`
	Hist     [11]uint32 `json:"hist"`
	FwdAvgMs float64    `json:"fwd_avg_ms"`
	fwdSumUs uint64
	n        int
}

type TSDB struct {
	path string
	f    *os.File
	mu   sync.Mutex
	cur  atomic.Pointer[tsAcc]
	pend *tsAcc
	seed maphash.Seed
	now  func() time.Time
	mem  map[int64]TSPoint // used when no file (tests / unwritable dir)
}

func OpenTSDB(path string) *TSDB {
	t := &TSDB{path: path, seed: maphash.MakeSeed(), now: time.Now, mem: map[int64]TSPoint{}}
	if path != "" {
		if f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600); err == nil {
			t.f = f
		}
	}
	t.cur.Store(&tsAcc{min: t.now().Unix() / 60})
	return t
}

func histIdx(ms float64) int {
	for i, b := range histBounds {
		if ms <= b {
			return i
		}
	}
	return 10
}

// Observe is called once per answered query (hot path: atomics only).
func (t *TSDB) Observe(result string, qtype uint16, rcode int, d time.Duration, client string) {
	if t == nil {
		return
	}
	a := t.cur.Load()
	a.c[tfQ].Add(1)
	switch result {
	case "cached":
		a.c[tfCached].Add(1)
	case "forwarded", "refreshed":
		a.c[tfFwd].Add(1)
		a.fwdSum.Add(uint64(d.Microseconds()))
	case "blocked":
		a.c[tfBlocked].Add(1)
	case "threat":
		a.c[tfThreat].Add(1)
	case "flagged":
		a.c[tfFlagged].Add(1)
	case "failed":
		a.c[tfFailed].Add(1)
	case "stale":
		a.c[tfStale].Add(1)
	case "local":
		a.c[tfLocal].Add(1)
	}
	switch qtype {
	case 1:
		a.c[tfA].Add(1)
	case 28:
		a.c[tfAAAA].Add(1)
	case 65:
		a.c[tfHTTPS].Add(1)
	default:
		a.c[tfOtherType].Add(1)
	}
	switch rcode {
	case 0:
		a.c[tfNoErr].Add(1)
	case 3:
		a.c[tfNX].Add(1)
	case 2:
		a.c[tfServfail].Add(1)
	case -1:
	default:
		a.c[tfRcOther].Add(1)
	}
	a.c[tfHist+histIdx(float64(d.Nanoseconds())/1e6)].Add(1)
	if client != "" {
		h := maphash.String(t.seed, client) % 4096
		a.bitmap[h/64].Or(1 << (h % 64))
	}
}

// Tick rolls the minute over and writes the previous one (call about once a second).
func (t *TSDB) Tick() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pend != nil {
		t.write(t.pend)
		t.pend = nil
	}
	m := t.now().Unix() / 60
	if a := t.cur.Load(); a.min != m {
		t.pend = t.cur.Swap(&tsAcc{min: m}) // written next tick, after late writers are done
	}
}

// Flush writes the current partial minute (shutdown).
func (t *TSDB) Flush() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pend != nil {
		t.write(t.pend)
		t.pend = nil
	}
	t.write(t.cur.Load())
}

func (a *tsAcc) point() TSPoint {
	p := TSPoint{T: a.min * 60}
	v := func(i int) uint32 { return a.c[i].Load() }
	p.Q, p.Cached, p.Fwd, p.Blocked, p.Failed, p.Stale, p.Local, p.Threat, p.Flagged = v(tfQ), v(tfCached), v(tfFwd), v(tfBlocked), v(tfFailed), v(tfStale), v(tfLocal), v(tfThreat), v(tfFlagged)
	p.A, p.AAAA, p.HTTPS, p.Other = v(tfA), v(tfAAAA), v(tfHTTPS), v(tfOtherType)
	p.NoErr, p.NX, p.Servfail, p.RcOther = v(tfNoErr), v(tfNX), v(tfServfail), v(tfRcOther)
	for i := range p.Hist {
		p.Hist[i] = v(tfHist + i)
	}
	zero := 0
	for i := range a.bitmap {
		zero += 64 - bits.OnesCount64(a.bitmap[i].Load())
	}
	if zero < 4096 {
		if zero == 0 {
			zero = 1
		}
		p.Clients = uint32(math.Round(-4096 * math.Log(float64(zero)/4096)))
	}
	p.fwdSumUs = a.fwdSum.Load()
	p.n = 1
	return p
}

func (t *TSDB) write(a *tsAcc) {
	p := a.point()
	if p.Q == 0 {
		return
	}
	if t.f == nil {
		t.mem[a.min] = p
		if len(t.mem) > tsSlots {
			for k := range t.mem {
				if k < a.min-tsSlots {
					delete(t.mem, k)
				}
			}
		}
		return
	}
	var b [tsRecSize]byte
	binary.LittleEndian.PutUint32(b[0:], uint32(a.min))
	binary.LittleEndian.PutUint64(b[4:], p.fwdSumUs)
	vals := []uint32{p.Q, p.Cached, p.Fwd, p.Blocked, p.Failed, p.Stale, p.Local, p.Threat, p.Flagged, p.A, p.AAAA, p.HTTPS, p.Other, p.NoErr, p.NX, p.Servfail, p.RcOther, p.Clients}
	vals = append(vals, p.Hist[:]...)
	for i, x := range vals {
		binary.LittleEndian.PutUint32(b[12+4*i:], x)
	}
	_, _ = t.f.WriteAt(b[:], int64(a.min%tsSlots)*tsRecSize)
}

func decodeTS(b []byte) (TSPoint, bool) {
	m := int64(binary.LittleEndian.Uint32(b[0:]))
	if m == 0 {
		return TSPoint{}, false
	}
	p := TSPoint{T: m * 60, fwdSumUs: binary.LittleEndian.Uint64(b[4:]), n: 1}
	r := func(i int) uint32 { return binary.LittleEndian.Uint32(b[12+4*i:]) }
	p.Q, p.Cached, p.Fwd, p.Blocked, p.Failed, p.Stale, p.Local, p.Threat, p.Flagged = r(0), r(1), r(2), r(3), r(4), r(5), r(6), r(7), r(8)
	p.A, p.AAAA, p.HTTPS, p.Other = r(9), r(10), r(11), r(12)
	p.NoErr, p.NX, p.Servfail, p.RcOther, p.Clients = r(13), r(14), r(15), r(16), r(17)
	for i := range p.Hist {
		p.Hist[i] = r(18 + i)
	}
	return p, true
}

// Range returns per-minute points in [from, to) (unix seconds), oldest first.
func (t *TSDB) Range(from, to int64) []TSPoint {
	t.mu.Lock()
	defer t.mu.Unlock()
	f, l := from/60, (to+59)/60
	if l-f > tsSlots {
		f = l - tsSlots
	}
	var out []TSPoint
	if t.f == nil {
		for m := f; m < l; m++ {
			if p, ok := t.mem[m]; ok {
				out = append(out, p)
			}
		}
		return out
	}
	buf := make([]byte, tsRecSize)
	for m := f; m < l; m++ {
		if _, err := t.f.ReadAt(buf, int64(m%tsSlots)*tsRecSize); err != nil {
			continue
		}
		if p, ok := decodeTS(buf); ok && p.T/60 == m {
			out = append(out, p)
		}
	}
	return out
}

func (p *TSPoint) add(o TSPoint) {
	p.Q += o.Q
	p.Cached += o.Cached
	p.Fwd += o.Fwd
	p.Blocked += o.Blocked
	p.Failed += o.Failed
	p.Stale += o.Stale
	p.Local += o.Local
	p.Threat += o.Threat
	p.Flagged += o.Flagged
	p.A += o.A
	p.AAAA += o.AAAA
	p.HTTPS += o.HTTPS
	p.Other += o.Other
	p.NoErr += o.NoErr
	p.NX += o.NX
	p.Servfail += o.Servfail
	p.RcOther += o.RcOther
	p.Clients = max(p.Clients, o.Clients)
	for i := range p.Hist {
		p.Hist[i] += o.Hist[i]
	}
	p.fwdSumUs += o.fwdSumUs
	p.n += o.n
}

func (p *TSPoint) finish() {
	if p.Fwd > 0 {
		p.FwdAvgMs = float64(p.fwdSumUs) / float64(p.Fwd) / 1000
	}
}

// Series downsamples [from, to) into buckets of step seconds.
func (t *TSDB) Series(from, to, step int64) []TSPoint {
	pts := t.Range(from, to)
	if step < 60 {
		step = 60
	}
	var out []TSPoint
	for _, p := range pts {
		b := p.T - p.T%step
		if len(out) > 0 && out[len(out)-1].T == b {
			out[len(out)-1].add(p)
			continue
		}
		p.T = b
		out = append(out, p)
	}
	for i := range out {
		out[i].finish()
	}
	return out
}

// Sum aggregates [from, to).
func (t *TSDB) Sum(from, to int64) TSPoint {
	var s TSPoint
	for _, p := range t.Range(from, to) {
		s.add(p)
	}
	s.finish()
	return s
}

func (p TSPoint) HitRate() float64 {
	d := p.Cached + p.Fwd + p.Stale
	if d == 0 {
		return 0
	}
	return float64(p.Cached+p.Stale) / float64(d)
}

func (p TSPoint) P95() float64 {
	var h [11]int64
	for i, v := range p.Hist {
		h[i] = int64(v)
	}
	return histP95(h)
}

func (t *TSDB) FileBytes() int64 {
	if t.f == nil {
		return 0
	}
	if st, err := t.f.Stat(); err == nil {
		return st.Size()
	}
	return 0
}

// Oldest returns the unix time of the oldest stored minute (0 = none). v2.8.1.
func (t *TSDB) Oldest() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	var best int64
	if t.f == nil {
		for m := range t.mem {
			if best == 0 || m < best {
				best = m
			}
		}
		return best * 60
	}
	buf := make([]byte, tsRecSize)
	for i := int64(0); i < tsSlots; i++ {
		if _, err := t.f.ReadAt(buf, i*tsRecSize); err != nil {
			break
		}
		if p, ok := decodeTS(buf); ok && p.T > 0 && (best == 0 || p.T < best) {
			best = p.T
		}
	}
	return best
}
