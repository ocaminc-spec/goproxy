// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package main

import "errors"

// serviceMode is true when the Windows Service Control Manager started this process.
var serviceMode = false

const serviceName = "GoProxyDNS"

func isWindowsService() bool   { return false }
func eventLogError(msg string) {}
func serviceInstalled() bool   { return false }
func installService(args []string) int {
	println("Windows Service mode is only available on Windows (use goproxy.service with systemd)")
	return 1
}
func uninstallService() int                                                 { return installService(nil) }
func serviceRestartHelper(dnsAddr, healthName string, restartOnly bool) int { return 1 }

func beginService(ready, done <-chan struct{}, stop func()) (wait func()) { return func() {} }
func attachConsole()                                                      {}
func serviceState() (int, error)                                          { return 0, errors.New("no service") }

func startServiceRestart(cur string, restartOnly bool) error { return errors.New("not supported") }
func stopViaSCM() bool                                       { return false }
func runTray(httpAddr string) int                            { println("the tray is Windows only"); return 1 }
func notifyToast(title, msg string)                          {}
