// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Audit log (item l): logins, failed logins, password and settings changes, updates,
// flush, shutdown. One JSON object per line in goproxy-audit.jsonl (no passwords, ever).
type auditEntry struct {
	At     string `json:"at"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Detail string `json:"detail,omitempty"`
}

type Audit struct {
	mu   sync.Mutex
	path string
	days func() int
	now  func() time.Time
	n    int
}

func NewAudit(path string, days func() int) *Audit {
	return &Audit{path: path, days: days, now: time.Now}
}

var theAudit *Audit

// auditf records an event (safe to call with a nil Audit).
func auditf(ip, action, detail string) {
	if theAudit != nil {
		theAudit.Add(ip, action, detail)
	}
}

func (a *Audit) Add(ip, action, detail string) {
	if a == nil || a.path == "" {
		return
	}
	b, _ := json.Marshal(auditEntry{At: a.now().Format(time.RFC3339), IP: ip, Action: action, Detail: detail})
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	f.Close()
	if a.n++; a.n%200 == 1 {
		a.pruneLocked()
	}
}

func (a *Audit) read() []auditEntry {
	f, err := os.Open(a.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []auditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var e auditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// pruneLocked drops entries older than the retention (default 90 days).
func (a *Audit) pruneLocked() {
	all := a.read()
	cut := a.now().AddDate(0, 0, -orInt(a.days(), 90)).Format(time.RFC3339)
	var keep []auditEntry
	for _, e := range all {
		if e.At >= cut {
			keep = append(keep, e)
		}
	}
	if len(keep) == len(all) {
		return
	}
	var buf []byte
	for _, e := range keep {
		b, _ := json.Marshal(e)
		buf = append(append(buf, b...), '\n')
	}
	if os.WriteFile(a.path+".tmp", buf, 0o600) == nil {
		_ = os.Rename(a.path+".tmp", a.path)
	}
}

// Last returns the newest n entries, newest first.
func (a *Audit) Last(n int) []auditEntry {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	all := a.read()
	a.mu.Unlock()
	var out []auditEntry
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}
