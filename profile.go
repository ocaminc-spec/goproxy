// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"runtime"
)

// v2.6.0 performance profiles. A profile only changes the defaults of flags that were not
// given on the command line (or saved in the Advanced tab), so everything stays tunable.
//
//	max      (default; primary server, NAS): all cores, one SO_REUSEPORT UDP socket per core,
//	         4 MB socket buffers, keep the top 1000 names hot, prefetch popular names at 25 %
//	         of TTL left after 2 hits, preload 2000 names at 200/s with 8 workers.
//	balanced (small boxes): at most 4 UDP sockets, 1 MB buffers, top 200 hot, prefetch
//	         after 3 hits at 20 %, preload 500 names at 50/s with 4 workers.
//
// Both keep serve-stale, the sharded cache (256 shards) and pooled keep-alive DoH (HTTP/2)
// and DoT connections.
type perfProfile struct {
	UDPListeners, SockBuf, KeepHot, PrefetchHits, Warmup, WarmupWorkers int
	PrefetchAt, WarmupRate                                              float64
}

func profileFor(name string) (perfProfile, error) {
	n := runtime.NumCPU()
	switch name {
	case "", "max":
		return perfProfile{UDPListeners: n, SockBuf: 4 << 20, KeepHot: 1000, PrefetchHits: 2, PrefetchAt: 0.25, Warmup: 2000, WarmupWorkers: 8, WarmupRate: 200}, nil
	case "balanced":
		return perfProfile{UDPListeners: min(n, 4), SockBuf: 1 << 20, KeepHot: 200, PrefetchHits: 3, PrefetchAt: 0.2, Warmup: 500, WarmupWorkers: 4, WarmupRate: 50}, nil
	}
	return perfProfile{}, fmt.Errorf("unknown -profile %q (use max or balanced)", name)
}
