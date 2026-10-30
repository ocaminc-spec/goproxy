// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func numCPU() int { return max(runtime.NumCPU(), 1) }

var procGetSystemTimes = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemTimes")

func ftSec(f windows.Filetime) float64 {
	return float64(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) / 1e7
}

func readCPU() cpuTimes {
	var c cpuTimes
	var cr, ex, k, u windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &cr, &ex, &k, &u); err != nil {
		return c
	}
	c.proc = ftSec(k) + ftSec(u)
	var idle, kern, user windows.Filetime
	r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kern)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return c
	}
	tot := ftSec(kern) + ftSec(user) // kernel time includes idle
	c.busy, c.total, c.ok = tot-ftSec(idle), tot, true
	return c
}

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

type memoryStatusEx struct {
	Length, MemoryLoad                                 uint32
	TotalPhys, AvailPhys, TotalPageFile, AvailPageFile uint64
	TotalVirtual, AvailVirtual, AvailExtendedVirtual   uint64
}

func hostMemUsedPct() (float64, bool) {
	var m memoryStatusEx
	m.Length = uint32(unsafe.Sizeof(m))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 0, false
	}
	return float64(m.MemoryLoad), true
}
