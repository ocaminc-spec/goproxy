// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build !windows

package main

import "os/exec"

// Headless on Linux: just wait for graceful shutdown to finish.
func runPlatform(addr string, stop chan struct{}, done <-chan struct{}) { <-done }

const defaultUpdateDir = "off"

func notifyError(title, msg string) {}
func watchStopEvent(fn func())      {}
func signalStopEvent() bool         { return false }

func hideWindow(cmd *exec.Cmd) {}

func detach(cmd *exec.Cmd) {}
