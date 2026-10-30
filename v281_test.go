// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestImpactMarkersPersistAndCompare(t *testing.T) {
	d := t.TempDir()
	ip, vp := filepath.Join(d, "i.bin"), filepath.Join(d, "v.json")
	old := Version
	defer func() { Version = old }()
	base := time.Unix(1_800_000_000, 0)
	now := base
	Version = "9.0.0"
	im := OpenImpact(ip, vp, nil)
	im.now = func() time.Time { return now }
	// 2 h of "before" minutes with slow cold lookups
	for m := 0; m < 120; m++ {
		for i := 0; i < 10; i++ {
			im.Observe("forwarded", 40*time.Millisecond)
			im.Observe("cached", 100*time.Microsecond)
		}
		now = now.Add(time.Minute)
		im.Tick()
	}
	im.Close()
	Version = "9.0.1"
	im = OpenImpact(ip, vp, nil)
	im.now = func() time.Time { return now }
	ms := im.Markers()
	if len(ms) != 2 || ms[0].Version != "9.0.0" || ms[1].Version != "9.0.1" {
		t.Fatalf("markers %+v", ms)
	}
	im.markers[1].T = now.Unix()
	for m := 0; m < 60; m++ {
		for i := 0; i < 10; i++ {
			im.Observe("forwarded", 10*time.Millisecond)
		}
		now = now.Add(time.Minute)
		im.Tick()
	}
	c := im.Compare()
	last := c[len(c)-1]
	if !last.Before.Detail || !last.After.Detail {
		t.Fatalf("no detail %+v", last)
	}
	if !(last.After.ColdMed < last.Before.ColdMed) || last.Before.ColdMed < 25 || last.Before.ColdMed > 52 {
		t.Fatalf("cold before %.2f after %.2f", last.Before.ColdMed, last.After.ColdMed)
	}
	if last.Complete || math.Abs(last.AfterHrs-1) > 0.02 {
		t.Fatalf("after hrs %v", last.AfterHrs)
	}
	// a restart on the same version adds no marker
	im.Close()
	im = OpenImpact(ip, vp, nil)
	if len(im.Markers()) != 2 {
		t.Fatal("duplicate marker")
	}
	im.Close()
}

func TestHistQ(t *testing.T) {
	var h [impBuckets]uint64
	h[impBucket(3)] = 100
	if q := histQ(h, .5); q < 1.6 || q > 3.2 {
		t.Fatal(q)
	}
}

func TestCacheFindDelete(t *testing.T) {
	c := NewDNSCache(1<<20, 0, 4)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	rr, _ := dns.NewRR("example.com. 300 IN A 192.0.2.1")
	m.Answer = []dns.RR{rr}
	k := cacheKey("example.com", dns.TypeA, dns.ClassINET)
	c.Set(k, m)
	keys, _, n := c.Find("EXAMPLE", 10)
	if n != 1 || keys[0] != k {
		t.Fatal(keys, n)
	}
	if !c.Delete(k) || c.Delete(k) || c.entries.Load() != 0 {
		t.Fatal("delete")
	}
}

func TestVersionMarkersPublic(t *testing.T) {
	versionMarkers = func() []VersionMarker { return []VersionMarker{{Version: "1", T: 5}} }
	defer func() { versionMarkers = nil }()
	rec := httptest.NewRecorder()
	serveVersion(rec, httptest.NewRequest(http.MethodGet, "/api/version?brief=1", nil))
	b := rec.Body.String()
	if !strings.Contains(b, `"markers":[{"version":"1","t":5}]`) || strings.Contains(b, "changelog") || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal(b)
	}
}
