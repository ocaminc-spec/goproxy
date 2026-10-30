// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

//go:embed static/login.html
var loginPage []byte

const (
	authCookie     = "goproxy_session"
	csrfCookie     = "goproxy_csrf"   // v2.5.0: readable by the dashboard JS, echoed in csrfHeader
	csrfHeader     = "X-GoProxy-CSRF" // required on every state-changing request with a session
	sessionTTL     = 30 * 24 * time.Hour
	bcryptCost     = 12
	minPasswordLen = 8
	lockAfter      = 5           // failed logins from one address before a lockout
	lockBase       = time.Minute // first lockout; doubles each time
	lockMax        = 30 * time.Minute
)

// authConfig is goproxy-auth.json: only a bcrypt hash is stored, never the password.
type authConfig struct {
	Username string `json:"username"`
	Hash     string `json:"bcrypt_hash"`
	Secret   string `json:"session_secret"` // HMAC key for session cookies (survives updates/restarts)
	Gen      int64  `json:"generation"`     // bumped on password change: old sessions stop working
	Created  string `json:"created"`
}

var (
	dummyOnce sync.Once
	dummyHash []byte
)

type failState struct {
	n     int
	trips int
	until time.Time
	last  time.Time
}

// Auth guards the dashboard and every API. DNS (port 53) is not affected.
type Auth struct {
	path string
	mu   sync.Mutex
	cfg  *authConfig
	mod  time.Time // mtime of the loaded file (picks up -reset-password while running)
	chk  time.Time
	fail map[string]*failState
	now  func() time.Time
}

func NewAuth(path string) *Auth {
	a := &Auth{path: path, fail: map[string]*failState{}, now: time.Now}
	a.reload(true)
	return a
}

func (a *Auth) reload(force bool) {
	if !force && a.now().Sub(a.chk) < 2*time.Second {
		return
	}
	a.chk = a.now()
	st, err := os.Stat(a.path)
	if err != nil {
		a.cfg, a.mod = nil, time.Time{}
		return
	}
	if !force && st.ModTime().Equal(a.mod) && a.cfg != nil {
		return
	}
	b, err := os.ReadFile(a.path)
	var c authConfig
	if err != nil || json.Unmarshal(b, &c) != nil || c.Username == "" || c.Hash == "" || len(c.Secret) < 32 {
		log.Printf("auth: %s unreadable or invalid; the dashboard stays locked (run goproxy -reset-password on this PC)", a.path)
		a.cfg = &authConfig{} // fail closed: nobody can log in, and setup is NOT offered
		a.mod = st.ModTime()
		return
	}
	a.cfg, a.mod = &c, st.ModTime()
}

// Configured reports whether an account exists (false = first-run setup).
func (a *Auth) Configured() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reload(false)
	return a.cfg != nil
}

func (a *Auth) save(c *authConfig) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, a.path); err != nil {
		return err
	}
	if st, err := os.Stat(a.path); err == nil {
		a.mod = st.ModTime()
	}
	a.cfg = c
	return nil
}

func validCreds(user, pass string) error {
	if u := strings.TrimSpace(user); u == "" || len(u) > 64 || u != user {
		return errors.New("username must be 1-64 characters with no leading/trailing spaces")
	}
	if utf8.RuneCountInString(pass) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if len(pass) > 72 {
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

// Setup creates the first account. It fails once an account exists.
func (a *Auth) Setup(user, pass string) error {
	if err := validCreds(user, pass); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcryptCost)
	if err != nil {
		return err
	}
	sec := make([]byte, 32)
	_, _ = rand.Read(sec)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reload(true)
	if a.cfg != nil {
		return errors.New("an account already exists")
	}
	return a.save(&authConfig{Username: user, Hash: string(h), Secret: hex.EncodeToString(sec), Gen: 1, Created: a.now().Format(time.RFC3339)})
}

// Check verifies credentials (constant-time on the username, bcrypt on the password).
func (a *Auth) Check(user, pass string) bool {
	a.mu.Lock()
	c := a.cfg
	a.mu.Unlock()
	if c == nil || c.Hash == "" {
		dummyOnce.Do(func() { dummyHash, _ = bcrypt.GenerateFromPassword([]byte("x"), bcryptCost) })
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pass)) // same cost either way
		return false
	}
	okU := subtle.ConstantTimeCompare([]byte(user), []byte(c.Username)) == 1
	okP := bcrypt.CompareHashAndPassword([]byte(c.Hash), []byte(pass)) == nil
	return okU && okP
}

func (a *Auth) ChangePassword(user, old, pass string) error {
	if !a.Check(user, old) {
		return errors.New("current password is wrong")
	}
	if err := validCreds(user, pass); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pass), bcryptCost)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	c := *a.cfg
	c.Hash, c.Gen = string(h), c.Gen+1
	return a.save(&c)
}

// session token: base64(user|gen|expiry) . hex(hmac)
func (a *Auth) issue(c *authConfig) (string, time.Time) {
	exp := a.now().Add(sessionTTL)
	body := base64.RawURLEncoding.EncodeToString([]byte(c.Username + "|" + strconv.FormatInt(c.Gen, 10) + "|" + strconv.FormatInt(exp.Unix(), 10)))
	return body + "." + a.mac(c, body), exp
}

func (a *Auth) mac(c *authConfig, body string) string {
	key, _ := hex.DecodeString(c.Secret)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(body))
	return hex.EncodeToString(m.Sum(nil))
}

// Session returns the logged-in username for r, or "".
func (a *Auth) Session(r *http.Request) string {
	ck, err := r.Cookie(authCookie)
	if err != nil {
		return ""
	}
	a.mu.Lock()
	a.reload(false)
	c := a.cfg
	a.mu.Unlock()
	if c == nil || c.Secret == "" {
		return ""
	}
	body, sig, ok := strings.Cut(ck.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(a.mac(c, body))) {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return ""
	}
	p := strings.Split(string(raw), "|")
	if len(p) != 3 || p[0] != c.Username || p[1] != strconv.FormatInt(c.Gen, 10) {
		return ""
	}
	exp, err := strconv.ParseInt(p[2], 10, 64)
	if err != nil || a.now().Unix() > exp {
		return ""
	}
	return p[0]
}

func (a *Auth) setCookie(w http.ResponseWriter, r *http.Request, val string, exp time.Time) {
	ck := &http.Cookie{Name: authCookie, Value: val, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil}
	if val == "" {
		ck.MaxAge = -1
	} else {
		ck.Expires = exp
	}
	http.SetCookie(w, ck)
	csrf := ""
	if val != "" {
		csrf = a.csrfFor(val)
	}
	a.setCSRFCookie(w, r, csrf, exp)
}

// csrfFor derives the CSRF token from a session cookie value: HMAC(secret, "csrf|"+session).
// It is bound to that session (a new login or password change gives a new token) and needs
// no server-side state. "" when there is no account.
func (a *Auth) csrfFor(session string) string {
	a.mu.Lock()
	c := a.cfg
	a.mu.Unlock()
	if c == nil || c.Secret == "" || session == "" {
		return ""
	}
	return a.mac(c, "csrf|"+session)[:32]
}

// setCSRFCookie sets the double-submit cookie (NOT HttpOnly: the dashboard JS copies it into
// the X-GoProxy-CSRF header; another site can neither read it nor set the header).
func (a *Auth) setCSRFCookie(w http.ResponseWriter, r *http.Request, tok string, exp time.Time) {
	ck := &http.Cookie{Name: csrfCookie, Value: tok, Path: "/", SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil}
	if tok == "" {
		ck.MaxAge = -1
	} else {
		ck.Expires = exp
	}
	http.SetCookie(w, ck)
}

// csrfOK checks the token header of a state-changing request that carries a valid session.
func (a *Auth) csrfOK(r *http.Request) bool {
	ck, err := r.Cookie(authCookie)
	if err != nil {
		return false
	}
	want := a.csrfFor(ck.Value)
	got := r.Header.Get(csrfHeader)
	return want != "" && len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// ensureCSRFCookie re-issues the CSRF cookie on authenticated page/API GETs when it is missing
// or stale (sessions from before v2.5.0, or a cookie cleared by the browser).
func (a *Auth) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	ck, err := r.Cookie(authCookie)
	if err != nil {
		return
	}
	want := a.csrfFor(ck.Value)
	if want == "" {
		return
	}
	if have, err := r.Cookie(csrfCookie); err == nil && have.Value == want {
		return
	}
	a.setCSRFCookie(w, r, want, a.now().Add(sessionTTL))
}

func stateChanging(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

func remoteIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// locked reports how long logins from ip are blocked.
func (a *Auth) locked(ip string) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	if f := a.fail[ip]; f != nil {
		if d := f.until.Sub(a.now()); d > 0 {
			return d
		}
	}
	return 0
}

func (a *Auth) recordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if len(a.fail) > 4096 { // bound memory
		for k, f := range a.fail {
			if now.Sub(f.last) > time.Hour {
				delete(a.fail, k)
			}
		}
	}
	f := a.fail[ip]
	if f == nil {
		f = &failState{}
		a.fail[ip] = f
	}
	if now.Sub(f.last) > time.Hour {
		f.n, f.trips = 0, 0
	}
	f.n++
	f.last = now
	if f.n >= lockAfter {
		d := lockBase << min(f.trips, 5)
		f.until = now.Add(min(d, lockMax))
		f.trips++
		f.n = 0
		log.Printf("auth: %s locked out for %v after %d failed logins", ip, min(d, lockMax), lockAfter)
		go auditf(ip, "locked out", fmt.Sprintf("%v after %d failed logins", min(d, lockMax), lockAfter))
	}
}

func (a *Auth) clearFail(ip string) {
	a.mu.Lock()
	delete(a.fail, ip)
	a.mu.Unlock()
}

func isPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && (p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast())
}

// sameOrigin rejects cross-site requests (CSRF / cross-site WebSocket hijacking).
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// non-browser client, or a same-origin GET; a browser that sends Fetch Metadata
		// but no Origin must still be same-origin (v2.5.0)
		sfs := r.Header.Get("Sec-Fetch-Site")
		return sfs == "" || sfs == "same-origin" || sfs == "none"
	}
	u, err := url.Parse(o)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

func readCreds(r *http.Request) (map[string]string, error) {
	var m map[string]string
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&m); err != nil {
		return nil, errors.New("bad request")
	}
	return m, nil
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
}

// Register adds the /login page and /api/auth/* endpoints.
func (a *Auth) Register(mux *http.ServeMux) {
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write(loginPage)
	})
	mux.HandleFunc("/api/auth/status", func(w http.ResponseWriter, r *http.Request) {
		st := map[string]any{"configured": a.Configured(), "user": a.Session(r), "setup_allowed": isPrivateIP(remoteIP(r))}
		if st["user"] != "" {
			if ck, err := r.Cookie(authCookie); err == nil {
				st["csrf"] = a.csrfFor(ck.Value) // same value as the goproxy_csrf cookie
			}
		}
		writeJSON(w, st)
	})
	mux.HandleFunc("/api/auth/setup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST only")
			return
		}
		if !isPrivateIP(remoteIP(r)) {
			jsonErr(w, 403, "first-time setup is only allowed from this PC or the home network")
			return
		}
		m, err := readCreds(r)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if err := a.Setup(m["username"], m["password"]); err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		log.Printf("auth: account %q created from %s", m["username"], remoteIP(r))
		auditf(remoteIP(r), "login created", "user "+m["username"])
		a.mu.Lock()
		tok, exp := a.issue(a.cfg)
		a.mu.Unlock()
		a.setCookie(w, r, tok, exp)
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST only")
			return
		}
		ip := remoteIP(r)
		if d := a.locked(ip); d > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(d.Seconds())+1))
			jsonErr(w, 429, fmt.Sprintf("too many failed logins; try again in %d s", int(d.Seconds())+1))
			return
		}
		m, err := readCreds(r)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if !a.Check(m["username"], m["password"]) {
			a.recordFail(ip)
			log.Printf("auth: failed login for %q from %s", m["username"], ip)
			auditf(ip, "login failed", "user "+m["username"])
			jsonErr(w, 401, "wrong username or password")
			return
		}
		a.clearFail(ip)
		a.mu.Lock()
		tok, exp := a.issue(a.cfg)
		a.mu.Unlock()
		a.setCookie(w, r, tok, exp)
		log.Printf("auth: %q logged in from %s", m["username"], ip)
		auditf(ip, "login", "user "+m["username"])
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonErr(w, 405, "POST only")
			return
		}
		if u := a.Session(r); u != "" {
			auditf(remoteIP(r), "logout", "user "+u)
		}
		a.setCookie(w, r, "", time.Time{})
		writeJSON(w, map[string]any{"ok": true})
	})
	mux.HandleFunc("/api/auth/password", func(w http.ResponseWriter, r *http.Request) {
		user := a.Session(r)
		if r.Method != http.MethodPost || user == "" {
			jsonErr(w, 401, "log in first")
			return
		}
		ip := remoteIP(r)
		if d := a.locked(ip); d > 0 {
			jsonErr(w, 429, fmt.Sprintf("too many failed attempts; try again in %d s", int(d.Seconds())+1))
			return
		}
		m, err := readCreds(r)
		if err != nil {
			jsonErr(w, 400, err.Error())
			return
		}
		if err := a.ChangePassword(user, m["current"], m["password"]); err != nil {
			if !a.Check(user, m["current"]) {
				a.recordFail(ip)
			}
			jsonErr(w, 400, err.Error())
			return
		}
		a.mu.Lock()
		tok, exp := a.issue(a.cfg) // other sessions are now invalid; keep this one
		a.mu.Unlock()
		a.setCookie(w, r, tok, exp)
		log.Printf("auth: password changed for %q from %s", user, ip)
		auditf(ip, "password changed", "user "+user)
		writeJSON(w, map[string]any{"ok": true})
	})
}

// publicPath: reachable without a session.
func publicPath(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/peer/") { // v2.6.0: own check (LAN + shared peer token)
		return true
	}
	switch r.URL.Path {
	case "/health": // v2.6.0 monitoring: "ok"/"degraded" only, no data
		return r.Method == http.MethodGet || r.Method == http.MethodHead
	case "/login", "/api/auth/status", "/api/auth/setup", "/api/auth/login", "/api/auth/logout", "/icon.png", "/icon.ico", "/favicon.ico":
		return true
	case "/kiosk", "/api/kiosk", "/api/kiosk/login": // check their own (kiosk or admin) session
		return true
	case "/api/tray/status": // the tray process on this PC; minimal, no private data
		return isLoopback(r) && r.Method == http.MethodGet
	case "/api/version": // polled by `goproxy -stop` and the updater on this PC
		return isLoopback(r) && r.Method == http.MethodGet
	case "/api/shutdown": // `goproxy -stop`: loopback + a custom header (blocks CSRF from web pages)
		return isLoopback(r) && r.Header.Get("X-GoProxy-Stop") == "1"
	}
	return false
}

// Middleware protects everything (pages, APIs, WebSocket, updates) behind the login.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r) {
			jsonErr(w, 403, "cross-site request blocked")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/ws/") && !sameOrigin(r) {
			http.Error(w, "cross-site WebSocket blocked", http.StatusForbidden)
			return
		}
		if publicPath(r) {
			next.ServeHTTP(w, r)
			return
		}
		if a.Session(r) != "" {
			if stateChanging(r.Method) && !a.csrfOK(r) {
				jsonErr(w, 403, "missing or wrong CSRF token: reload the dashboard page and try again")
				return
			}
			if !stateChanging(r.Method) {
				a.ensureCSRFCookie(w, r)
			}
			next.ServeHTTP(w, r)
			return
		}
		if r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/index.html") {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		jsonErr(w, 401, "login required")
	})
}

// resetPassword implements `goproxy -reset-password`, run on the PC itself: it removes the
// account so the next visit to the dashboard shows first-time setup again.
func resetPassword(path string) int {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "could not reset:", err)
		return 1
	}
	fmt.Println("dashboard login removed; open the dashboard on this PC to create a new username and password")
	log.Printf("auth: account removed with -reset-password")
	return 0
}
