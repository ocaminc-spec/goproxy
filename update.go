// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxUpdateSize = 150 << 20

// Updater stages a new binary and hands the ports over to it with ~no DNS interruption:
//
//  1. verify (SHA-256 if given), extract from zip, and probe the new exe with -version
//  2. save the cache snapshot, copy goproxy.exe to goproxy.prev.exe, rename the running exe to
//     goproxy.old.exe (Windows allows renaming, not replacing, a running exe), move the new one into place
//  3. start it with -takeover; it preloads the snapshot and prints READY on stdout
//  4. old process closes UDP/TCP 53 and the dashboard port, writes GO on the child's stdin
//  5. child binds (retrying every 20 ms), resolves -health-name through itself, prints OK
//  6. old process exits without saving (the child owns the cache now)
//
// On any failure or timeout the child is killed, the files are put back and the old process
// re-binds and keeps serving.
//
// Windows note: we deliberately do not overlap sockets with SO_REUSEADDR. On Windows that lets a
// second socket steal or share UDP 53 non-deterministically (the reason SO_EXCLUSIVEADDRUSE exists),
// so both processes would answer at random. A UDP socket is released the instant it is closed, and
// a closed TCP listener does not leave TIME_WAIT on the listening port, so close-then-bind with a
// 20 ms retry gives a gap of a few milliseconds with no ambiguity.
type Updater struct {
	app        *App
	dir        string // watched folder
	url        string // manifest URL
	healthName string
	busy       atomic.Bool
	mu         sync.Mutex
	st         UpdateStatus
	prevVer    string
	prevMod    time.Time
	// afterInstall replaces the takeover/service/legacy step (tests only)
	afterInstall func(cur, ver, kind string, restore func()) error
}

type UpdateStatus struct {
	State     string      `json:"state"` // idle, working, done, failed
	Message   string      `json:"message"`
	Log       []string    `json:"log"`
	WatchDir  string      `json:"watch_dir"`
	URL       string      `json:"manifest_url"`
	Available *Manifest   `json:"available,omitempty"`
	Checked   string      `json:"checked,omitempty"`
	Previous  string      `json:"previous_version"`
	Last      *lastUpdate `json:"last_update,omitempty"`
	Container bool        `json:"container,omitempty"` // v2.5.0: in-app updates disabled
}

type Manifest struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
	Sig     string `json:"sig,omitempty"` // base64 ed25519 signature of the exe (optional; zips carry goproxy.exe.sig)
	Notes   string `json:"notes,omitempty"`
}

type lastUpdate struct {
	From  string  `json:"from"`
	To    string  `json:"to"`
	At    string  `json:"at"`
	GapMs float64 `json:"gap_ms"`
	Kind  string  `json:"kind"`
	Error string  `json:"error,omitempty"`
}

func NewUpdater(a *App, dir, url, healthName string) *Updater {
	if dir == "off" || inContainer() {
		dir = "" // container: no update-folder watching (GP-03)
	}
	if inContainer() {
		url = ""
	}
	u := &Updater{app: a, dir: dir, url: url, healthName: healthName}
	u.st = UpdateStatus{State: "idle", WatchDir: dir, URL: url, Container: inContainer()}
	if u.st.Container {
		u.st.Message = containerUpdateMsg
		log.Print("update: running in a container; self-update, rollback and restart are disabled (update the image instead)")
	}
	if b, err := os.ReadFile(u.recordPath()); err == nil {
		var l lastUpdate
		if json.Unmarshal(b, &l) == nil && l.To == Version {
			u.st.Last = &l
		}
	}
	return u
}

func (u *Updater) recordPath() string { return filepath.Join(dataDir, "goproxy-update.json") }

// test hooks (nil in production)
var (
	exePathsHook func() (cur, prev, next string)
	probeHook    func(path string) (string, error)
)

func exePaths() (cur, prev, next string) {
	if exePathsHook != nil {
		return exePathsHook()
	}
	exe, _ := os.Executable()
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	ext := filepath.Ext(exe)
	if ext != ".exe" {
		ext = ""
	}
	base := strings.TrimSuffix(exe, ext)
	return exe, base + ".prev" + ext, base + ".new" + ext
}

func (u *Updater) logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	log.Print("update: " + msg)
	u.mu.Lock()
	u.st.Message = msg
	u.st.Log = append(u.st.Log, time.Now().Format("15:04:05.000")+" "+msg)
	if len(u.st.Log) > 40 {
		u.st.Log = u.st.Log[len(u.st.Log)-40:]
	}
	u.mu.Unlock()
}

func (u *Updater) setState(s string) { u.mu.Lock(); u.st.State = s; u.mu.Unlock() }

func (u *Updater) Status() UpdateStatus {
	if u.st.Last == nil {
		if b, err := os.ReadFile(u.recordPath()); err == nil {
			var l lastUpdate
			if json.Unmarshal(b, &l) == nil && l.To == Version {
				u.mu.Lock()
				u.st.Last = &l
				u.mu.Unlock()
			}
		}
	}
	_, prev, _ := exePaths()
	if fi, err := os.Stat(prev); err == nil {
		if !fi.ModTime().Equal(u.prevMod) {
			v, err := probeVersion(prev)
			if err != nil {
				v = "unknown"
			}
			u.mu.Lock()
			u.prevVer, u.prevMod = v, fi.ModTime()
			u.mu.Unlock()
		}
	} else {
		u.mu.Lock()
		u.prevVer = ""
		u.mu.Unlock()
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.st
	st.Previous = u.prevVer
	st.Log = append([]string(nil), u.st.Log...)
	return st
}

func (u *Updater) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/update/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, u.Status()) })
	mux.HandleFunc("/api/update/upload", u.serveUpload)
	mux.HandleFunc("/api/update/rollback", u.serveRollback)
	mux.HandleFunc("/api/update/check", u.serveCheck)
	mux.HandleFunc("/api/update/install", u.serveInstall)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// updates run code, so only accept them from this PC or the home network (never from a public IP).
func trustedClient(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func (u *Updater) guard(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return false
	}
	if containerRefuse(w) {
		return false
	}
	if !trustedClient(r) {
		http.Error(w, "updates are only accepted from the local network", http.StatusForbidden)
		return false
	}
	if u.busy.Load() {
		http.Error(w, "an update is already in progress", http.StatusConflict)
		return false
	}
	return true
}

// POST /api/update/upload (multipart: file, optional sha256)
func (u *Updater) serveUpload(w http.ResponseWriter, r *http.Request) {
	if !u.guard(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUpdateSize+1<<20)
	f, hdr, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	want := strings.TrimSpace(r.FormValue("sha256"))
	bin, signed, err := u.prepareSigned(data, hdr.Filename, want, r.FormValue("signature"))
	if err != nil {
		u.logf("upload %s rejected: %v", hdr.Filename, err)
		auditf(remoteIP(r), "update rejected", hdr.Filename+": "+err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u.logf("upload %s (%d KB) accepted%s, %s", hdr.Filename, len(data)>>10, map[bool]string{true: ", SHA-256 verified", false: ""}[want != ""], signedMsg(signed))
	u.start(bin, "upload")
	writeJSON(w, map[string]any{"ok": true})
}

func (u *Updater) serveRollback(w http.ResponseWriter, r *http.Request) {
	if !u.guard(w, r) {
		return
	}
	_, prev, _ := exePaths()
	data, err := os.ReadFile(prev)
	if err != nil {
		http.Error(w, "no previous version is saved", http.StatusNotFound)
		return
	}
	u.logf("rollback to the previous version requested")
	u.start(data, "rollback")
	writeJSON(w, map[string]any{"ok": true})
}

func (u *Updater) serveCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if containerRefuse(w) {
		return
	}
	if err := u.checkManifest(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, u.Status())
}

func (u *Updater) serveInstall(w http.ResponseWriter, r *http.Request) {
	if !u.guard(w, r) {
		return
	}
	u.mu.Lock()
	m := u.st.Available
	u.mu.Unlock()
	if m == nil {
		http.Error(w, "no update available", http.StatusNotFound)
		return
	}
	go func() {
		data, err := download(m.URL)
		signed := ""
		if err == nil {
			data, signed, err = u.prepareSigned(data, m.URL, m.SHA256, m.Sig)
		}
		if err != nil {
			u.logf("download v%s failed: %v", m.Version, err)
			u.setState("failed")
			return
		}
		u.logf("downloaded v%s%s, %s", m.Version, map[bool]string{true: ", SHA-256 verified", false: ""}[m.SHA256 != ""], signedMsg(signed))
		u.start(data, "manifest")
	}()
	writeJSON(w, map[string]any{"ok": true})
}

func download(url string) ([]byte, error) {
	c := &http.Client{Timeout: 2 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxUpdateSize))
}

func (u *Updater) checkManifest(ctx context.Context) error {
	if u.url == "" {
		return errors.New("no manifest URL configured (start with -update-url)")
	}
	b, err := download(u.url)
	if err != nil {
		return err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.st.Checked = time.Now().Format(time.RFC3339)
	if m.URL != "" && newerVersion(m.Version, Version) {
		u.st.Available = &m
	} else {
		u.st.Available = nil
	}
	return nil
}

func newerVersion(a, b string) bool {
	p := func(s string) [3]int {
		var v [3]int
		s = strings.TrimPrefix(s, "v")
		s, _, _ = strings.Cut(s, "-")
		for i, f := range strings.SplitN(s, ".", 3) {
			v[i], _ = strconv.Atoi(f)
		}
		return v
	}
	x, y := p(a), p(b)
	for i := range x {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return false
}

// prepare verifies the SHA-256 (of what was uploaded) and pulls the binary out of a zip.
func prepare(data []byte, name, want string) ([]byte, error) {
	if len(data) > maxUpdateSize {
		return nil, errors.New("file too large")
	}
	if want != "" {
		want = strings.ToLower(strings.Fields(want)[0])
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); got != want {
			return nil, fmt.Errorf("SHA-256 mismatch: got %s, expected %s", got, want)
		}
	}
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("zip: %w", err)
		}
		var pick *zip.File
		for _, f := range zr.File {
			b := strings.ToLower(filepath.Base(f.Name))
			if b == "goproxy.exe" || b == "goproxy" {
				pick = f
				break
			}
			if pick == nil && strings.HasSuffix(b, ".exe") {
				pick = f
			}
		}
		if pick == nil {
			return nil, errors.New("zip has no goproxy.exe")
		}
		rc, err := pick.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		data, err = io.ReadAll(io.LimitReader(rc, maxUpdateSize))
		if err != nil {
			return nil, err
		}
	}
	if runtime.GOOS == "windows" && !bytes.HasPrefix(data, []byte("MZ")) {
		return nil, errors.New("not a Windows program (.exe)")
	}
	if len(data) < 1<<20 {
		return nil, errors.New("file is too small to be GoProxy")
	}
	return data, nil
}

func probeVersion(path string) (string, error) {
	if probeHook != nil {
		return probeHook(path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "-version").Output()
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(out))
	if v == "" || len(v) > 40 {
		return "", errors.New("no version output")
	}
	return v, nil
}

func (u *Updater) start(bin []byte, kind string) {
	if inContainer() { // GP-03: never swap the binary inside a container (also covers auto-rollback)
		u.logf("%s ignored: %s", kind, containerUpdateMsg)
		return
	}
	if !u.busy.CompareAndSwap(false, true) {
		return
	}
	u.setState("working")
	go func() {
		err := u.apply(bin, kind)
		if err != nil {
			u.logf("FAILED, still running v%s: %v", Version, err)
			u.setState("failed")
			notifyError("GoProxy update failed", err.Error()+"\n\nThe current version is still running.")
		}
		u.busy.Store(false)
	}()
}

func childArgs() []string { return childArgsFrom(os.Args[1:]) }

func childArgsFrom(args []string) []string {
	return append(filterArgs(args), "-takeover")
}

func (u *Updater) apply(bin []byte, kind string) error {
	a := u.app
	cur, prev, next := exePaths()
	if err := os.WriteFile(next, bin, 0o755); err != nil {
		return fmt.Errorf("write %s: %w", next, err)
	}
	ver, err := probeVersion(next)
	legacy := false
	if err != nil {
		if kind != "rollback" {
			os.Remove(next)
			return fmt.Errorf("the new file does not run (%v)", err)
		}
		// pre-2.3.0 builds have no -version/-takeover: fall back to save, stop, start, verify.
		legacy, ver = true, "2.2.x (older)"
	}
	u.logf("new version v%s staged; saving cache snapshot", ver)
	t0 := time.Now()
	a.SaveAll()
	u.logf("snapshot saved in %v", time.Since(t0).Round(time.Millisecond))

	// Windows allows renaming the running exe but not replacing it: copy it to prev (the
	// rollback copy), move it aside to goproxy.old.exe, then rename the new one into place.
	// A new .exe is typically held by the antivirus for a few seconds after it was written
	// and probed; installExe waits for that instead of failing (the v2.4.1 bug).
	setSwapNotify(func(m string) { u.logf("%s", m) })
	defer setSwapNotify(func(string) {})
	restoreFn, err := installExe(exeFS, cur, prev, next, true)
	if err != nil {
		_ = os.Remove(next)
		return err
	}
	u.logf("v%s is in place (the running v%s was moved to %s)", ver, Version, filepath.Base(oldPath(cur)))
	restore := func() {
		if err := restoreFn(); err != nil {
			u.logf("restore after a failed update: %v", err)
		}
	}

	if u.afterInstall != nil {
		return u.afterInstall(cur, ver, kind, restore)
	}
	if legacy {
		return u.applyLegacy(cur, ver, kind, restore)
	}
	if serviceMode {
		return u.applyService(cur, ver, kind, restore)
	}
	return u.handover(cur, ver, kind, restore)
}

// applyService: under the Windows Service the SCM tracks our process ID, so the
// zero-downtime takeover (which hands the ports to a NEW process and exits) would look like
// the service died. Instead a helper restarts the service with the new exe and rolls back
// if it does not answer DNS. DNS is down for the restart itself (typically 1–3 s); devices
// retry, and Technitium answers meanwhile if it is their second DNS server.
func (u *Updater) applyService(cur, ver, kind string, restore func()) error {
	rec := lastUpdate{From: Version, To: ver, At: time.Now().Format(time.RFC3339), Kind: kind + " (service restart)"}
	if b, err := json.Marshal(rec); err == nil {
		_ = os.WriteFile(u.recordPath(), b, 0o644)
	}
	if err := startServiceRestart(cur, false); err != nil {
		restore()
		return fmt.Errorf("could not start the service restart helper: %w", err)
	}
	u.logf("v%s installed; the service restarts now", ver)
	auditf("local", "update", fmt.Sprintf("v%s -> v%s (%s, service restart)", Version, ver, kind))
	u.app.Stop(true)
	return nil
}

// Restart re-launches the current version (to apply settings that need a restart). Portable:
// the same zero-downtime handover as an update, without touching the files. Service: an SCM
// restart through the helper.
func (u *Updater) Restart(by string) error {
	if inContainer() {
		return errors.New(containerUpdateMsg)
	}
	if !u.busy.CompareAndSwap(false, true) {
		return errors.New("an update or restart is already in progress")
	}
	u.setState("working")
	auditf(by, "restart", "apply settings")
	go func() {
		defer u.busy.Store(false)
		cur, _, _ := exePaths()
		u.logf("restarting v%s to apply settings", Version)
		u.app.SaveAll()
		var err error
		if serviceMode {
			if err = startServiceRestart(cur, true); err == nil {
				u.app.Stop(true)
			}
		} else {
			err = u.handover(cur, Version, "restart", func() {})
		}
		if err != nil {
			u.logf("restart FAILED, still running: %v", err)
			u.setState("failed")
			return
		}
		u.setState("done")
	}()
	return nil
}

// handover starts cur with -takeover and gives it the ports (see the type comment).
func (u *Updater) handover(cur, ver, kind string, restore func()) error {
	a := u.app
	cmd := exec.Command(cur, childArgs()...)
	cmd.Dir = exeDir()
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	hideWindow(cmd)
	if err := cmd.Start(); err != nil {
		restore()
		return fmt.Errorf("start: %w", err)
	}
	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	expect := func(prefix string, d time.Duration) (string, error) {
		select {
		case l, ok := <-lines:
			if !ok {
				return "", errors.New("new process exited (see goproxy.log)")
			}
			if strings.HasPrefix(l, prefix) {
				return l, nil
			}
			return l, errors.New(strings.TrimPrefix(l, "FAIL "))
		case <-time.After(d):
			return "", fmt.Errorf("timed out waiting for %s", prefix)
		}
	}
	abort := func(err error, rebind bool) error {
		_ = cmd.Process.Kill()
		<-exited
		restore()
		if rebind {
			if berr := a.bindAll(10 * time.Second); berr != nil {
				fatal("could not re-bind after a failed update: " + berr.Error())
			}
			u.logf("ports re-bound, v%s is serving again", Version)
		}
		return err
	}
	if _, err := expect("READY", 2*time.Minute); err != nil {
		return abort(err, false)
	}
	u.logf("v%s loaded the snapshot; handing over port 53", ver)
	rec := lastUpdate{From: Version, To: ver, At: time.Now().Format(time.RFC3339), Kind: kind}
	tRelease := time.Now()
	a.unbindDNS()
	a.unbindHTTP()
	if _, err := io.WriteString(stdin, "GO\n"); err != nil {
		return abort(err, true)
	}
	if _, err := expect("OK", 20*time.Second); err != nil {
		return abort(fmt.Errorf("v%s failed its health check: %w", ver, err), true)
	}
	rec.GapMs = float64(time.Since(tRelease).Microseconds()) / 1000
	if b, err := json.Marshal(rec); err == nil {
		_ = os.WriteFile(u.recordPath(), b, 0o644)
	}
	if kind != "restart" {
		_, prev, _ := exePaths()
		_ = os.Remove(prev + ".tmp")
		auditf("local", "update", fmt.Sprintf("v%s -> v%s (%s)", Version, ver, kind))
	}
	log.Printf("update: v%s is serving (handover took %.1f ms); exiting", ver, rec.GapMs)
	a.Stop(false)
	return nil
}

// Run watches the update folder and polls the manifest.
func (u *Updater) Run(ctx context.Context) {
	if u.dir != "" {
		_ = os.MkdirAll(u.dir, 0o755)
		log.Printf("update: watching %s", u.dir)
	}
	if u.url != "" {
		go func() {
			for {
				if err := u.checkManifest(ctx); err != nil {
					log.Printf("update: manifest: %v", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(6 * time.Hour):
				}
			}
		}()
	}
	if u.dir == "" {
		return
	}
	sizes := map[string]int64{}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ents, _ := os.ReadDir(u.dir)
		for _, e := range ents {
			n := strings.ToLower(e.Name())
			if e.IsDir() || !(strings.HasSuffix(n, ".exe") || strings.HasSuffix(n, ".zip") || n == "goproxy") {
				continue
			}
			p := filepath.Join(u.dir, e.Name())
			fi, err := e.Info()
			if err != nil {
				continue
			}
			if sizes[p] != fi.Size() { // wait until the copy has finished
				sizes[p] = fi.Size()
				continue
			}
			delete(sizes, p)
			if u.busy.Load() {
				continue
			}
			u.fromFolder(p)
		}
	}
}

func (u *Updater) fromFolder(p string) {
	done := filepath.Join(u.dir, "processed")
	_ = os.MkdirAll(done, 0o755)
	data, err := os.ReadFile(p)
	if err != nil {
		return
	}
	want := ""
	if b, err := os.ReadFile(p + ".sha256"); err == nil && len(strings.Fields(string(b))) > 0 {
		want = strings.Fields(string(b))[0]
	}
	dst := filepath.Join(done, time.Now().Format("20060102-150405-")+filepath.Base(p))
	_ = os.Rename(p, dst)
	_ = os.Rename(p+".sha256", dst+".sha256")
	sig := ""
	if b, err := os.ReadFile(p + ".sig"); err == nil {
		sig = string(b)
		_ = os.Rename(p+".sig", dst+".sig")
	}
	bin, signed, err := u.prepareSigned(data, p, want, sig)
	if err != nil {
		u.logf("%s rejected: %v", filepath.Base(p), err)
		_ = os.Rename(dst, dst+".rejected")
		u.setState("failed")
		return
	}
	u.logf("found %s in the update folder%s, %s", filepath.Base(p), map[bool]string{true: ", SHA-256 verified", false: ""}[want != ""], signedMsg(signed))
	u.start(bin, "folder")
}

// applyLegacy hands over to an older build that cannot do -takeover: release the ports, start it
// normally (it loads the snapshot we just saved), and keep it only if it answers within 10 s.
func (u *Updater) applyLegacy(cur, ver, kind string, restore func()) error {
	a := u.app
	var args []string
	for _, x := range childArgs() {
		if x != "-takeover" && !strings.HasPrefix(x, "-update-") && !strings.HasPrefix(x, "--update-") && !strings.HasPrefix(x, "-health-name") && !strings.HasPrefix(x, "-bind-retry") {
			args = append(args, x)
		}
	}
	cmd := exec.Command(cur, args...)
	cmd.Dir = exeDir()
	hideWindow(cmd)
	u.logf("older version: stopping DNS and starting it (no seamless handover possible)")
	t0 := time.Now()
	a.unbindDNS()
	a.unbindHTTP()
	if err := cmd.Start(); err != nil {
		restore()
		_ = a.bindAll(10 * time.Second)
		return err
	}
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-exited:
			deadline = time.Now()
			continue
		default:
		}
		if healthCheck(a.dnsAddr, u.healthName) == nil {
			gap := float64(time.Since(t0).Microseconds()) / 1000
			if b, err := json.Marshal(lastUpdate{From: Version, To: ver, At: time.Now().Format(time.RFC3339), GapMs: gap, Kind: kind}); err == nil {
				_ = os.WriteFile(u.recordPath(), b, 0o644)
			}
			log.Printf("update: older version is serving (gap %.0f ms); exiting", gap)
			a.Stop(false)
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	<-exited
	restore()
	if err := a.bindAll(10 * time.Second); err != nil {
		fatal("could not re-bind after a failed rollback: " + err.Error())
	}
	return errors.New("the older version did not start answering within 10 s")
}
