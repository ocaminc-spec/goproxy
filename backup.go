// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// Settings backup / restore (v2.4.2). The export holds the dashboard settings and, optionally,
// device names and groups. It never contains secrets: no password hash, no sessions, no kiosk
// password, no ntfy token. Import is only accepted from the home network, is validated like
// a normal Save, keeps the current ntfy token, and is recorded in Config history (Revert
// undoes it) and the audit log.

type settingsBackup struct {
	App      string      `json:"app"`
	Format   int         `json:"format"`
	Version  string      `json:"version"`
	Exported string      `json:"exported"`
	Settings Settings    `json:"settings"`
	Devices  *groupsFile `json:"devices,omitempty"`
}

func exportSettings(st Settings, dev *Devices) settingsBackup {
	st = st.clone()
	st.NtfyToken, st.PeerToken = "", ""
	st.V27.WebhookURL, st.V27.WebhookToken = "", ""
	b := settingsBackup{App: "GoProxy DNS", Format: 1, Version: Version, Exported: time.Now().Format(time.RFC3339), Settings: st}
	if dev != nil {
		dev.mu.Lock()
		raw, _ := json.Marshal(dev.g)
		dev.mu.Unlock()
		var g groupsFile
		if json.Unmarshal(raw, &g) == nil {
			b.Devices = &g
		}
	}
	return b
}

func (v *V24) serveExport(w http.ResponseWriter, r *http.Request) {
	b := exportSettings(v.s.settings.Get(), v.s.devices)
	auditf(v.by(r), "settings exported", "")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="goproxy-settings-%s.json"`, time.Now().Format("2006-01-02")))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(b)
}

func (v *V24) importSettings(b settingsBackup, withDevices bool, by string) ([]string, error) {
	if b.App != "GoProxy DNS" || b.Format != 1 {
		return nil, errors.New("this is not a GoProxy settings backup")
	}
	_, diff, err := v.s.settings.Update(by, "imported from a backup (v"+b.Version+", "+b.Exported+")", func(s *Settings) error {
		n := b.Settings.clone()
		n.NtfyToken, n.PeerToken = s.NtfyToken, s.PeerToken // secrets are never in a backup: keep ours
		n.V27.WebhookURL, n.V27.WebhookToken = s.V27.WebhookURL, s.V27.WebhookToken
		n.BlockingPaused = s.BlockingPaused
		if err := validateSettings(&n); err != nil {
			return err
		}
		if err := validateAds(&n, v.s.protectedName); err != nil {
			return err
		}
		*s = n
		return nil
	})
	if err != nil {
		return nil, err
	}
	if withDevices && b.Devices != nil && v.s.devices != nil {
		d := v.s.devices
		d.mu.Lock()
		if b.Devices.Devices == nil {
			b.Devices.Devices = map[string]*deviceMeta{}
		}
		d.g = *b.Devices
		err = d.saveLocked()
		d.mu.Unlock()
		if err != nil {
			return diff, err
		}
		diff = append(diff, fmt.Sprintf("device names & groups replaced (%d devices, %d groups)", len(b.Devices.Devices), len(b.Devices.Groups)))
	}
	auditf(by, "settings imported", fmt.Sprintf("%d change(s), devices=%v", len(diff), withDevices && b.Devices != nil))
	_ = v.applyLive(v.s.settings.Get())
	return diff, nil
}

func (v *V24) serveImport(w http.ResponseWriter, r *http.Request) {
	if !postOnly(w, r) {
		return
	}
	if !trustedClient(r) {
		jsonErr(w, 403, "settings can only be imported from the home network")
		return
	}
	var body struct {
		Backup      settingsBackup `json:"backup"`
		WithDevices bool           `json:"with_devices"`
	}
	if err := readJSON(r, &body); err != nil {
		jsonErr(w, 400, "the file is not valid JSON")
		return
	}
	diff, err := v.importSettings(body.Backup, body.WithDevices, v.by(r))
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "diff": diff, "restart_needed": restartNeeded(v.started, v.s.settings.Get())})
}
