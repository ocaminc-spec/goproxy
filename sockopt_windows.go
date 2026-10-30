// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package main

import "net"

func listenUDP(addr string, _ bool, _ int) (net.PacketConn, error) {
	return net.ListenPacket("udp", addr)
}
