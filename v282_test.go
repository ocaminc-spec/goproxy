// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"testing"
	"time"
)

func TestHomeLabel(t *testing.T) {
	for in, want := range map[string]string{"Alexs-iPhone.lan.": "alexs-iphone", "192-168-0-5": "", "": "", "localhost": "", "NAS_01": "nas-01"} {
		if got := homeLabel(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestDevAggShiftAndTrim(t *testing.T) {
	x := &V282{dev: map[string]*devAgg{}, now: time.Now}
	for i := 0; i < v282MaxDomains+50; i++ {
		x.observe("192.168.1.5", string(rune('a'+i%26))+time.Duration(i).String()+".com", "cached", time.Millisecond)
	}
	x.observe("192.168.1.5", "x.com", "blocked", time.Millisecond)
	a := x.dev["192.168.1.5"]
	if len(a.Domains) > v282MaxDomains || a.Q != int64(v282MaxDomains+51) || a.Blocked != 1 {
		t.Fatalf("domains=%d q=%d blocked=%d", len(a.Domains), a.Q, a.Blocked)
	}
	h := a.Hours[v282Hours-1]
	a.shift(a.HourBase + v282Hours + 2)
	if a.Hours[v282Hours-4] != h || a.Hours[v282Hours-1] != 0 {
		t.Fatal("shift wrong")
	}
}
