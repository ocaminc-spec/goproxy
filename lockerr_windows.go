// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isFileLockErr: another process has the file open without sharing delete/write access
// (typically the antivirus scanning a new .exe) — transient, worth retrying.
func isFileLockErr(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_USER_MAPPED_FILE)
}
