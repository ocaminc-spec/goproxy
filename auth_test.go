// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func authSrv(t *testing.T) (*Auth, *httptest.Server, string) {
	path := filepath.Join(t.TempDir(), "goproxy-auth.json")
	a := NewAuth(path)
	mux := http.NewServeMux()
	a.Register(mux)
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) })
	mux.HandleFunc("/api/update/upload", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) })
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"version":"x"}`)) })
	mux.HandleFunc("/ws/stats", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err == nil {
			c.WriteMessage(websocket.TextMessage, []byte("hi"))
			c.Close()
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("dashboard")) })
	srv := httptest.NewServer(a.Middleware(mux))
	t.Cleanup(srv.Close)
	testAuth = a
	return a, srv, path
}

// testAuth lets post() behave like the dashboard JS: echo the session's CSRF token.
var testAuth *Auth

func csrfHeaderFor(cookie string) string {
	if testAuth == nil {
		return ""
	}
	_, v, _ := strings.Cut(cookie, "=")
	return testAuth.csrfFor(v)
}

func post(t *testing.T, srv *httptest.Server, path, body, cookie string) *http.Response {
	req, _ := http.NewRequest("POST", srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
		req.Header.Set(csrfHeader, csrfHeaderFor(cookie))
	}
	r, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func get(t *testing.T, srv *httptest.Server, path, cookie string) *http.Response {
	req, _ := http.NewRequest("GET", srv.URL+path, nil)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	r, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func sessionCookie(r *http.Response) string {
	for _, c := range r.Cookies() {
		if c.Name == authCookie && c.Value != "" {
			return c.Name + "=" + c.Value
		}
	}
	return ""
}

func TestAuthFirstRunSetupNoDefaults(t *testing.T) {
	a, srv, path := authSrv(t)
	if a.Configured() {
		t.Fatal("no account should exist on first run")
	}
	if r := get(t, srv, "/", ""); r.StatusCode != http.StatusSeeOther || r.Header.Get("Location") != "/login" {
		t.Fatalf("dashboard must redirect to /login: %d", r.StatusCode)
	}
	for _, p := range []string{"/api/stats", "/ws/stats"} {
		if r := get(t, srv, p, ""); r.StatusCode != 401 {
			t.Fatalf("%s without login: %d", p, r.StatusCode)
		}
	}
	if r := post(t, srv, "/api/update/upload", "", ""); r.StatusCode != 401 {
		t.Fatalf("update without login: %d", r.StatusCode)
	}
	if r := post(t, srv, "/api/auth/login", `{"username":"admin","password":"admin"}`, ""); r.StatusCode != 401 {
		t.Fatal("default credentials must not work")
	}
	if r := post(t, srv, "/api/auth/setup", `{"username":"admin","password":"short"}`, ""); r.StatusCode != 400 {
		t.Fatal("short password accepted")
	}
	r := post(t, srv, "/api/auth/setup", `{"username":"admin","password":"correct horse"}`, "")
	ck := sessionCookie(r)
	if r.StatusCode != 200 || ck == "" {
		t.Fatalf("setup: %d", r.StatusCode)
	}
	sc := r.Header.Get("Set-Cookie")
	if !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "SameSite=Strict") || strings.Contains(sc, "Secure") {
		t.Fatalf("cookie flags: %s", sc)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "correct horse") || !strings.Contains(string(b), "$2a$12$") {
		t.Fatalf("password must be stored only as a bcrypt hash: %s", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("auth file mode %v", st.Mode().Perm())
	}
	if r := post(t, srv, "/api/auth/setup", `{"username":"evil","password":"takeover123"}`, ""); r.StatusCode != 400 {
		t.Fatal("second setup must be refused")
	}
	if r := get(t, srv, "/api/stats", ck); r.StatusCode != 200 {
		t.Fatalf("stats with session: %d", r.StatusCode)
	}
	if r := post(t, srv, "/api/update/upload", "", ck); r.StatusCode != 200 {
		t.Fatalf("update with session: %d", r.StatusCode)
	}
}

func TestAuthLoginLogoutAndWebSocket(t *testing.T) {
	a, srv, _ := authSrv(t)
	if err := a.Setup("admin", "correct horse"); err != nil {
		t.Fatal(err)
	}
	if r := post(t, srv, "/api/auth/login", `{"username":"admin","password":"wrong pass"}`, ""); r.StatusCode != 401 {
		t.Fatal("wrong password accepted")
	}
	r := post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, "")
	ck := sessionCookie(r)
	if r.StatusCode != 200 || ck == "" {
		t.Fatalf("login %d", r.StatusCode)
	}
	ws := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/stats"
	if _, resp, err := websocket.DefaultDialer.Dial(ws, nil); err == nil || resp.StatusCode != 401 {
		t.Fatal("websocket without session must be refused")
	}
	h := http.Header{"Cookie": {ck}}
	c, _, err := websocket.DefaultDialer.Dial(ws, h)
	if err != nil {
		t.Fatalf("websocket with session: %v", err)
	}
	c.Close()
	h.Set("Origin", "http://evil.example")
	if _, _, err := websocket.DefaultDialer.Dial(ws, h); err == nil {
		t.Fatal("cross-site websocket must be refused")
	}
	// cross-site POST with a valid cookie is blocked (CSRF)
	req, _ := http.NewRequest("POST", srv.URL+"/api/update/upload", nil)
	req.Header.Set("Cookie", ck)
	req.Header.Set("Origin", "http://evil.example")
	if r, _ := http.DefaultTransport.RoundTrip(req); r.StatusCode != 403 {
		t.Fatalf("csrf: %d", r.StatusCode)
	}
	r = post(t, srv, "/api/auth/logout", "", ck)
	if !strings.Contains(r.Header.Get("Set-Cookie"), "Max-Age=0") {
		t.Fatal("logout must clear the cookie")
	}
	// forged / tampered cookie
	if r := get(t, srv, "/api/stats", ck+"x"); r.StatusCode != 401 {
		t.Fatal("tampered cookie accepted")
	}
}

func TestAuthLockoutAfterFailedLogins(t *testing.T) {
	a, srv, _ := authSrv(t)
	_ = a.Setup("admin", "correct horse")
	now := time.Now()
	a.now = func() time.Time { return now }
	for i := 0; i < lockAfter; i++ {
		post(t, srv, "/api/auth/login", `{"username":"admin","password":"guess`+string(rune('a'+i))+`"}`, "")
	}
	r := post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, "")
	if r.StatusCode != 429 || r.Header.Get("Retry-After") == "" {
		t.Fatalf("expected lockout even with the right password, got %d", r.StatusCode)
	}
	now = now.Add(lockBase + time.Second)
	if r := post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, ""); r.StatusCode != 200 {
		t.Fatalf("after lockout: %d", r.StatusCode)
	}
}

func TestAuthChangePasswordInvalidatesOldSessions(t *testing.T) {
	a, srv, _ := authSrv(t)
	_ = a.Setup("admin", "correct horse")
	old := sessionCookie(post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, ""))
	other := sessionCookie(post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, ""))
	if r := post(t, srv, "/api/auth/password", `{"current":"nope nope","password":"battery staple"}`, old); r.StatusCode != 400 {
		t.Fatal("wrong current password accepted")
	}
	r := post(t, srv, "/api/auth/password", `{"current":"correct horse","password":"battery staple"}`, old)
	if r.StatusCode != 200 {
		t.Fatalf("change: %d", r.StatusCode)
	}
	if g := get(t, srv, "/api/stats", other); g.StatusCode != 401 {
		t.Fatal("other sessions must be signed out")
	}
	if g := get(t, srv, "/api/stats", sessionCookie(r)); g.StatusCode != 200 {
		t.Fatal("current session must stay")
	}
	if !a.Check("admin", "battery staple") || a.Check("admin", "correct horse") {
		t.Fatal("password not changed")
	}
}

func TestAuthResetPasswordAndSessionSurvivesRestart(t *testing.T) {
	a, srv, path := authSrv(t)
	_ = a.Setup("admin", "correct horse")
	ck := sessionCookie(post(t, srv, "/api/auth/login", `{"username":"admin","password":"correct horse"}`, ""))
	// a new process (update/restart) reads the same file: the session still works
	a2 := NewAuth(path)
	req := httptest.NewRequest("GET", "/api/stats", nil)
	req.Header.Set("Cookie", ck)
	if a2.Session(req) != "admin" {
		t.Fatal("session should survive a restart/update")
	}
	if resetPassword(path) != 0 {
		t.Fatal("reset failed")
	}
	a2.reload(true)
	if a2.Configured() || a2.Session(req) != "" {
		t.Fatal("reset must remove the account and its sessions")
	}
}

func TestAuthLocalStopAndVersionStillWork(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/shutdown", nil)
	r.RemoteAddr = "127.0.0.1:5555"
	if publicPath(r) {
		t.Fatal("shutdown without the -stop header must need a login")
	}
	r.Header.Set("X-GoProxy-Stop", "1")
	if !publicPath(r) {
		t.Fatal("goproxy -stop from this PC must work without a login")
	}
	r.RemoteAddr = "192.168.1.50:5555"
	if publicPath(r) {
		t.Fatal("remote shutdown must not be public")
	}
	v := httptest.NewRequest("GET", "/api/version", nil)
	v.RemoteAddr = "127.0.0.1:1"
	if !publicPath(v) {
		t.Fatal("local version check (updater/-stop) must work")
	}
	v.RemoteAddr = "192.168.1.50:1"
	if publicPath(v) {
		t.Fatal("remote version needs login")
	}
}

func TestAuthCorruptFileFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goproxy-auth.json")
	_ = os.WriteFile(path, []byte("{garbage"), 0o600)
	a := NewAuth(path)
	if !a.Configured() || a.Check("", "") || a.Setup("x", "longenough") == nil {
		t.Fatal("a corrupt auth file must lock the dashboard, not reopen setup")
	}
}
