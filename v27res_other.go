// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build !linux && !windows

package main

import "runtime"

func numCPU() int                     { return max(runtime.NumCPU(), 1) }
func readCPU() cpuTimes               { return cpuTimes{} }
func hostMemUsedPct() (float64, bool) { return 0, false }
