// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

//go:embed static/kiosk.html
var kioskPage []byte

const kioskCookie = "goproxy_kiosk"

// Kiosk (item h): a read-only status page for a tablet or TV at /kiosk. It has its own
// optional view-only password; the kiosk session opens only /kiosk and /api/kiosk, never
// the dashboard or any control. Off by default (Settings · Features · kiosk).
type Kiosk struct {
	mu   sync.Mutex
	path string
	cfg  struct {
		Hash   string `json:"bcrypt_hash"`
		Secret string `json:"session_secret"`
		Gen    int64  `json:"generation"`
	}
	auth *Auth
	v    *V24
	now  func() time.Time
}

func NewKiosk(path string, a *Auth) *Kiosk {
	k := &Kiosk{path: path, auth: a, now: time.Now}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &k.cfg)
	}
	return k
}

func (k *Kiosk) hasPassword() bool { k.mu.Lock(); defer k.mu.Unlock(); return k.cfg.Hash != "" }

func (k *Kiosk) save() error {
	b, _ := json.MarshalIndent(k.cfg, "", "  ")
	if err := os.WriteFile(k.path+".tmp", b, 0o600); err != nil {
		return err
	}
	return os.Rename(k.path+".tmp", k.path)
}

func (k *Kiosk) SetPassword(pw string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if pw == "" {
		k.cfg.Hash = ""
		k.cfg.Gen++
		return k.save()
	}
	if len(pw) < 4 || len(pw) > 72 {
		return fmt.Errorf("kiosk password: 4 to 72 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcryptCost)
	if err != nil {
		return err
	}
	if k.cfg.Secret == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		k.cfg.Secret = hex.EncodeToString(b)
	}
	k.cfg.Hash = string(h)
	k.cfg.Gen++
	return k.save()
}

func (k *Kiosk) sign(body string) string {
	key, _ := hex.DecodeString(k.cfg.Secret)
	m := hmac.New(sha256.New, key)
	m.Write([]byte("kiosk|" + body))
	return hex.EncodeToString(m.Sum(nil))
}

func (k *Kiosk) sessionOK(r *http.Request) bool {
	ck, err := r.Cookie(kioskCookie)
	if err != nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cfg.Hash == "" {
		return false
	}
	body, sig, ok := strings.Cut(ck.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(k.sign(body))) {
		return false
	}
	gen, exp, ok := strings.Cut(body, "|")
	e, err := strconv.ParseInt(exp, 10, 64)
	return ok && err == nil && gen == strconv.FormatInt(k.cfg.Gen, 10) && k.now().Unix() < e
}

// allowed: kiosk switched on, and an admin session or a kiosk session.
func (k *Kiosk) allowed(r *http.Request) bool {
	if !k.v.s.settings.Get().Feature("kiosk") {
		return false
	}
	return k.auth.Session(r) != "" || k.sessionOK(r)
}

func (k *Kiosk) Register(mux *http.ServeMux) {
	mux.HandleFunc("/kiosk", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(kioskPage)
	})
	mux.HandleFunc("/api/kiosk/login", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		ip := remoteIP(r)
		if !k.v.s.settings.Get().Feature("kiosk") || !k.hasPassword() {
			jsonErr(w, 404, "the kiosk view-only login is not set up")
			return
		}
		if d := k.auth.locked(ip); d > 0 {
			jsonErr(w, 429, fmt.Sprintf("too many failed attempts; try again in %d s", int(d.Seconds())+1))
			return
		}
		var b struct{ Password string }
		if readJSON(r, &b) != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		k.mu.Lock()
		hash := k.cfg.Hash
		k.mu.Unlock()
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(b.Password)) != nil {
			k.auth.recordFail(ip)
			auditf(ip, "kiosk login failed", "")
			jsonErr(w, 401, "wrong password")
			return
		}
		k.auth.clearFail(ip)
		k.mu.Lock()
		exp := k.now().Add(365 * 24 * time.Hour)
		body := strconv.FormatInt(k.cfg.Gen, 10) + "|" + strconv.FormatInt(exp.Unix(), 10)
		val := body + "." + k.sign(body)
		k.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: kioskCookie, Value: val, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Expires: exp, Secure: r.TLS != nil})
		auditf(ip, "kiosk login", "")
		writeJSON(w, map[string]any{"ok": true})
	})
	// admin only (behind the normal login): set or remove the kiosk password
	mux.HandleFunc("/api/kiosk/password", func(w http.ResponseWriter, r *http.Request) {
		if !postOnly(w, r) {
			return
		}
		var b struct{ Password string }
		if readJSON(r, &b) != nil {
			jsonErr(w, 400, "bad request")
			return
		}
		if err := k.SetPassword(b.Password); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		auditf(k.v.by(r), map[bool]string{true: "kiosk password removed", false: "kiosk password set"}[b.Password == ""], "")
		writeJSON(w, map[string]any{"ok": true, "has_password": k.hasPassword()})
	})
	mux.HandleFunc("/api/kiosk", func(w http.ResponseWriter, r *http.Request) {
		if !k.v.s.settings.Get().Feature("kiosk") {
			writeJSON(w, map[string]any{"enabled": false})
			return
		}
		if !k.allowed(r) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "enabled": true, "login": k.hasPassword(), "error": "login required"})
			return
		}
		writeJSON(w, k.data())
	})
}

type kioskDevice struct {
	Name   string `json:"name"`
	Group  string `json:"group"`
	AgoSec int64  `json:"ago_sec"`
	Quiet  bool   `json:"quiet"`
}

// data is deliberately small: no IP addresses, no domains, no controls.
func (k *Kiosk) data() map[string]any {
	s := k.v.s
	s.health.Sample(s.healthSnap())
	view := s.health.View()
	var latest HealthScores = HealthScores{-1, -1, -1, -1, -1, -1}
	for i := len(view) - 1; i >= 0; i-- {
		if view[i].Scores.Overall >= 0 {
			latest = view[i].Scores
			break
		}
	}
	var online []kioskDevice
	watchedQuiet := 0
	for _, d := range s.devices.List(false) {
		if d.Watched && d.Quiet {
			watchedQuiet++
		}
		if d.Online || d.Watched {
			name := d.Name
			if name == "" || net.ParseIP(name) != nil || name == d.PTR && d.Alias == "" {
				name = "Unnamed device" // the kiosk never shows addresses or reverse-DNS names
			}
			online = append(online, kioskDevice{Name: name, Group: d.Group, AgoSec: d.AgoSec, Quiet: d.Quiet})
		}
	}
	var titles []string
	for _, a := range s.alerts.Active() {
		titles = append(titles, a.Title)
	}
	recent := k.v.out.View("")
	if len(recent) > 5 {
		recent = recent[:5]
	}
	for i := range recent {
		recent[i].Reason = ""
	}
	return map[string]any{"ok": true, "enabled": true, "version": Version, "time": k.now().Format(time.RFC3339), "health": latest,
		"canary_ok": s.canary.View().OK, "internet_down": k.v.out.Open() != nil, "outages": recent, "devices": online,
		"quiet_watched": watchedQuiet, "alerts": titles, "ip_state": k.v.ipw.View().State}
}
