// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"
)

func numCPU() int { return max(runtime.NumCPU(), 1) }

const clkTck = 100.0 // USER_HZ, 100 on every Linux we ship for

func readCPU() cpuTimes {
	var c cpuTimes
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return c
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return c
	}
	f := strings.Fields(s[i+1:]) // f[0] = state; utime = f[11], stime = f[12]
	if len(f) < 13 {
		return c
	}
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	c.proc = (ut + st) / clkTck
	b, err = os.ReadFile("/proc/stat")
	if err != nil {
		return c
	}
	line, _, _ := strings.Cut(string(b), "\n")
	g := strings.Fields(line)
	if len(g) < 5 || g[0] != "cpu" {
		return c
	}
	var tot, idle float64
	for k, v := range g[1:] {
		x, _ := strconv.ParseFloat(v, 64)
		tot += x
		if k == 3 || k == 4 { // idle, iowait
			idle += x
		}
	}
	c.busy, c.total, c.ok = (tot-idle)/clkTck, tot/clkTck, true
	return c
}

func hostMemUsedPct() (float64, bool) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	var total, avail float64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total <= 0 {
		return 0, false
	}
	return clampPct(100 * (total - avail) / total), true
}
