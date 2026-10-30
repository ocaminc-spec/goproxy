// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package main

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenUDP opens one UDP socket with SO_REUSEPORT (so N sockets share the port and the
// kernel spreads packets across cores) and a larger receive/send buffer (v2.6.0 profiles).
func listenUDP(addr string, reuse bool, buf int) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if reuse {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}
			if buf > 0 { // best effort: the kernel caps it at net.core.rmem_max
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, buf)
				_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, buf)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp", addr)
}
