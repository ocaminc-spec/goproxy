// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.6.0 per-device query volume (opt-in: setting device_volume, default OFF). Aggregate
// counters only, per client IP: no per-query log. Hot path cost when on: one sync.Map load
// (lock-free after first sight) plus two atomic adds into minute and hour ring buckets.
// When off: a single atomic bool check.

import (
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const devVolMax = 4096 // devices tracked; more are folded into "other"

type volBucket struct {
	epoch   atomic.Int64 // minute (or hour) number this bucket holds
	q, blkd atomic.Int64
}

type devVol struct {
	min  [60]volBucket
	hour [24]volBucket
}

func bump(b *volBucket, epoch int64, blocked bool) {
	if e := b.epoch.Load(); e != epoch {
		// a new period: first writer resets (a racing add may be lost; counts are approximate)
		if b.epoch.CompareAndSwap(e, epoch) {
			b.q.Store(0)
			b.blkd.Store(0)
		}
	}
	b.q.Add(1)
	if blocked {
		b.blkd.Add(1)
	}
}

type DeviceVolume struct {
	On    atomic.Bool
	m     sync.Map // ip -> *devVol
	n     atomic.Int64
	other devVol
	now   func() time.Time
}

func NewDeviceVolume() *DeviceVolume { return &DeviceVolume{now: time.Now} }

func (d *DeviceVolume) Record(ip string, blocked bool) {
	if d == nil || !d.On.Load() {
		return
	}
	v, ok := d.m.Load(ip)
	if !ok {
		if d.n.Load() >= devVolMax {
			v = &d.other
		} else {
			var loaded bool
			v, loaded = d.m.LoadOrStore(ip, &devVol{})
			if !loaded {
				d.n.Add(1)
			}
		}
	}
	dv := v.(*devVol)
	t := d.now().Unix()
	m, h := t/60, t/3600
	bump(&dv.min[m%60], m, blocked)
	bump(&dv.hour[h%24], h, blocked)
}

type DeviceVolRow struct {
	IP         string  `json:"ip"`
	Name       string  `json:"name,omitempty"`
	PerMin     int64   `json:"per_min"` // last full minute
	Hour       int64   `json:"hour"`
	HourBlock  int64   `json:"hour_blocked"`
	Day        int64   `json:"day"`
	DayBlock   int64   `json:"day_blocked"`
	AvgPerMin  float64 `json:"avg_per_min"` // over the last hour
	Spike      bool    `json:"spike"`
	SpikeRatio float64 `json:"spike_ratio,omitempty"`
}

func sumRing(r []volBucket, cur, span int64) (q, b int64) {
	for i := range r {
		e := r[i].epoch.Load()
		if e > cur-span && e <= cur {
			q += r[i].q.Load()
			b += r[i].blkd.Load()
		}
	}
	return
}

// Snapshot: top devices by 24 h volume. Spike = last minute >= 5x the hour average and >= 60 q/min.
func (d *DeviceVolume) Snapshot(names func(string) string, limit int) []DeviceVolRow {
	t := d.now().Unix()
	m, h := t/60, t/3600
	var out []DeviceVolRow
	add := func(ip string, dv *devVol) {
		r := DeviceVolRow{IP: ip}
		if b := &dv.min[(m-1+60)%60]; b.epoch.Load() == m-1 {
			r.PerMin = b.q.Load()
		}
		r.Hour, r.HourBlock = sumRing(dv.min[:], m, 60)
		r.Day, r.DayBlock = sumRing(dv.hour[:], h, 24)
		if r.Day == 0 && r.Hour == 0 {
			return
		}
		r.AvgPerMin = float64(r.Hour) / 60
		if r.PerMin >= 60 && float64(r.PerMin) >= 5*r.AvgPerMin {
			r.Spike = true
			if r.AvgPerMin > 0 {
				r.SpikeRatio = float64(r.PerMin) / r.AvgPerMin
			}
		}
		if names != nil && ip != "other" {
			r.Name = names(ip)
		}
		out = append(out, r)
	}
	d.m.Range(func(k, v any) bool { add(k.(string), v.(*devVol)); return true })
	add("other", &d.other)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Spike != out[j].Spike {
			return out[i].Spike
		}
		return out[i].Day > out[j].Day
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *DNSServer) deviceVolume() []DeviceVolRow {
	if s.devvol == nil || !s.devvol.On.Load() {
		return nil
	}
	var nm func(string) string
	if s.names != nil {
		nm = s.names.Name
	}
	return s.devvol.Snapshot(nm, 50)
}

// GET /api/devices/volume -> {enabled, devices}
func (s *DNSServer) serveDeviceVolume(w http.ResponseWriter, r *http.Request) {
	on := s.devvol != nil && s.devvol.On.Load()
	writeJSON(w, map[string]any{"enabled": on, "devices": s.deviceVolume()})
}
