// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import "testing"

func TestDataDirDefaultsAndFlag(t *testing.T) {
	if resolveDataDir("/tmp/x") != "/tmp/x" {
		t.Fatal("-data-dir must win")
	}
	if d := resolveDataDir(""); d != exeDir() { // non-Windows / portable: next to the exe, as before
		t.Fatalf("portable default %s", d)
	}
	for _, a := range []string{"-reset-password", "-stop"} {
		for _, c := range childArgsFrom([]string{"-data-dir", "D", a}) {
			if c == a {
				t.Fatalf("%s must not be passed to the updated process", a)
			}
		}
	}
}
