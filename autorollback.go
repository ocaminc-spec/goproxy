// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Auto-rollback (v2.4.2, OFF by default: Advanced · Updates). For 5 minutes after a version
// was installed from the dashboard (upload, update check or update folder), the NEW version
// watches itself. If its own DNS / dashboard check fails 3 times in a row, or the self-test
// fails (while the internet is up), it rolls back to goproxy.prev.exe with the usual
// zero-downtime handover. A rollback (manual or automatic) and a plain Restart are never
// watched, so it can not loop.

const autoRollbackWindow = 5 * time.Minute

type rollbackProbe struct {
	enabled  func() bool
	check    func() error // DNS UDP+TCP and dashboard answer (watchdog self-check)
	selfTest func() bool  // canary RunOnce: false = a name failed twice in a row
	offline  func() bool  // all upstreams failing: the internet, not the new version
	every    time.Duration
	now      func() time.Time
}

// watchable reports whether this process was just installed by an update and must watch itself.
func watchable(rec lastUpdate, version string, now time.Time) (time.Time, bool) {
	if rec.To != version || rec.Error != "" {
		return time.Time{}, false
	}
	k := strings.ToLower(rec.Kind)
	if strings.Contains(k, "rollback") || strings.HasPrefix(k, "restart") {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339, rec.At)
	if err != nil {
		return time.Time{}, false
	}
	end := at.Add(autoRollbackWindow)
	return end, now.Before(end)
}

// rollbackDecision runs the probe until the window ends. It returns a reason when the new
// version should be rolled back, "" when it proved healthy (or the feature is off).
func rollbackDecision(ctx context.Context, end time.Time, p rollbackProbe) string {
	fails := 0
	for p.now().Before(end) {
		select {
		case <-ctx.Done():
			return ""
		case <-time.After(p.every):
		}
		if !p.enabled() {
			return ""
		}
		if err := p.check(); err != nil {
			fails++
			if fails >= 3 {
				return "DNS/dashboard self-check failed 3 times: " + err.Error()
			}
		} else {
			fails = 0
		}
		if p.selfTest != nil && !p.selfTest() && (p.offline == nil || !p.offline()) {
			return "the self-test failed (YouTube / Netflix / connectivity names)"
		}
	}
	return ""
}

// WatchAfterUpdate is started once at launch.
func (u *Updater) WatchAfterUpdate(ctx context.Context, p rollbackProbe) {
	b, err := os.ReadFile(u.recordPath())
	if err != nil {
		return
	}
	var rec lastUpdate
	if json.Unmarshal(b, &rec) != nil {
		return
	}
	end, ok := watchable(rec, Version, p.now())
	if !ok || !p.enabled() {
		return
	}
	_, prev, _ := exePaths()
	if _, err := os.Stat(prev); err != nil {
		return
	}
	u.logf("auto-rollback: watching v%s until %s", Version, end.Format("15:04:05"))
	reason := rollbackDecision(ctx, end, p)
	if reason == "" {
		if p.enabled() && ctx.Err() == nil {
			u.logf("auto-rollback: v%s stayed healthy for 5 minutes", Version)
		}
		return
	}
	data, err := os.ReadFile(prev)
	if err != nil {
		u.logf("auto-rollback wanted (%s) but the previous version can't be read: %v", reason, err)
		return
	}
	u.logf("auto-rollback: %s; going back to v%s", reason, rec.From)
	auditf("local", "auto-rollback", fmt.Sprintf("v%s -> v%s: %s", Version, rec.From, reason))
	go notifyError("GoProxy rolled back", fmt.Sprintf("v%s failed its checks after the update (%s). GoProxy went back to v%s.", Version, reason, rec.From))
	u.start(data, "auto-rollback")
}
