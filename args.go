// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import "strings"

// internalFlags are one-shot or mode flags that must never be copied into a new process's
// command line (the updater child, the HKCU Run entry, the service's arguments).
//
// v2.3.1 copied os.Args into the Run entry when "Start with Windows" was ticked. In a
// process started by the updater, os.Args contains -takeover, so the next sign-in started
// GoProxy in takeover mode: it printed READY and waited on stdin for "GO" forever, alive and
// idle with no DNS or dashboard. Filtering here closes that path.
var internalFlags = []string{"takeover", "stop", "reset-password", "version", "service", "tray",
	"install-service", "uninstall-service", "service-restart", "restart-only", "portable"}

func flagName(a string) (name string, hasValue bool) {
	if !strings.HasPrefix(a, "-") {
		return "", false
	}
	n := strings.TrimLeft(a, "-")
	n, _, hasValue = strings.Cut(n, "=")
	return n, hasValue
}

func isInternalFlag(a string) bool {
	n, _ := flagName(a)
	for _, f := range internalFlags {
		if n == f {
			return true
		}
	}
	return false
}

// filterArgs drops internal flags (they are all booleans, so they never take a separate
// value argument).
func filterArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if isInternalFlag(a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// quoteArgs renders args for a Windows command line (Run key, service ImagePath).
func quoteArgs(args []string) string {
	var b []string
	for _, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\"") {
			a = `"` + strings.ReplaceAll(a, `"`, `\"`) + `"`
		}
		b = append(b, a)
	}
	return strings.Join(b, " ")
}

// oneShotFlags must never be in a startup entry: they only make sense for one launch.
var oneShotFlags = map[string]bool{"takeover": true, "stop": true, "reset-password": true, "service-restart": true, "restart-only": true, "install-service": true, "uninstall-service": true, "version": true}

// cleanedRunValue rewrites a Run-key command line without one-shot flags. The exe part
// (quoted or not) is kept exactly as it was.
func cleanedRunValue(v string) (string, bool) {
	v = strings.TrimSpace(v)
	exe, rest := v, ""
	if strings.HasPrefix(v, `"`) {
		if i := strings.Index(v[1:], `"`); i >= 0 {
			exe, rest = v[:i+2], v[i+2:]
		}
	} else if i := strings.IndexByte(v, ' '); i >= 0 {
		exe, rest = v[:i], v[i:]
	}
	args := splitCmdline(rest)
	var keep []string
	changed := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if n, _ := flagName(a); n != "" && oneShotFlags[n] {
			changed = true
			continue
		}
		keep = append(keep, a)
	}
	if !changed {
		return v, false
	}
	if len(keep) == 0 {
		return exe, true
	}
	return exe + " " + quoteArgs(keep), true
}

// splitCmdline splits a Windows-style command line tail on spaces, honouring double quotes.
func splitCmdline(s string) []string {
	var out []string
	var cur strings.Builder
	inQ, have := false, false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			have = true
		case (r == ' ' || r == '\t') && !inQ:
			if have {
				out = append(out, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteRune(r)
			have = true
		}
	}
	if have {
		out = append(out, cur.String())
	}
	return out
}
