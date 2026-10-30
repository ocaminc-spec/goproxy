// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"fyne.io/systray"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed static/icon.ico
var trayIcon []byte

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const appName = "GoProxy"

func autostartEnabled() bool {
	_, ok := readRunValue()
	return ok
}

// autostartValue is what the Run entry starts: this exe plus the user's own flags, never
// internal ones like -takeover (see args.go).
func autostartValue(extra ...string) string {
	exe, _, _ := exePaths()
	args := append(filterArgs(os.Args[1:]), extra...)
	v := `"` + exe + `"`
	if len(args) > 0 {
		v += " " + quoteArgs(args)
	}
	return v
}

func setAutostart(on bool) error { return writeRunValue(autostartValue(), on) }

// cleanRunValue removes one-shot internal flags (for example -takeover, which v2.3.1 could
// save) from an existing "Start with Windows" entry. Other entries are left alone.
func cleanRunValue() {
	v, ok := readRunValue()
	if !ok {
		return
	}
	if c, changed := cleanedRunValue(v); changed {
		if err := writeRunValue(c, true); err == nil {
			log.Printf("start with Windows: removed internal flags from the startup entry")
		}
	}
}

// toggleAsync runs a registry change off the tray's click loop with a timeout. In v2.3.1
// the write ran inline in the one goroutine that serves every tray click; anything that
// stalled it (an AV product inspecting the Run-key write, a slow registry hive) froze the
// whole menu. The menu now stays live and shows the real state afterwards.
func toggleAsync(item *systray.MenuItem, busy *atomic.Bool, want bool, set func(bool) error, get func() bool) {
	if !busy.CompareAndSwap(false, true) {
		return
	}
	item.Disable()
	go func() {
		defer busy.Store(false)
		res := make(chan error, 1)
		go func() { res <- set(want) }()
		select {
		case err := <-res:
			if err != nil {
				log.Printf("tray: start with Windows: %v", err)
			}
		case <-time.After(5 * time.Second):
			log.Print("tray: start with Windows: the registry did not answer within 5 s")
		}
		if get() {
			item.Check()
		} else {
			item.Uncheck()
		}
		item.Enable()
	}()
}

var trayUp atomic.Bool

// runPlatform shows the tray icon (build with -ldflags -H=windowsgui, so no console).
// Portable mode: the DNS engine and the tray share this process.
func runPlatform(addr string, stop chan struct{}, done <-chan struct{}) {
	if serviceMode {
		<-done
		return
	}
	go cleanRunValue()
	go func() { <-done; systray.Quit() }()
	systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle(appName)
		systray.SetTooltip("GoProxy DNS v" + Version + " — " + dashURL(addr))
		mOpen := systray.AddMenuItem("Open Dashboard", "Open the live dashboard")
		mAuto := systray.AddMenuItemCheckbox("Start with Windows", "Launch at sign-in (HKCU Run)", autostartEnabled())
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit", "Graceful shutdown")
		trayUp.Store(true)
		var busy atomic.Bool
		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", dashURL(addr)).Start()
				case <-mAuto.ClickedCh:
					toggleAsync(mAuto, &busy, !mAuto.Checked(), setAutostart, autostartEnabled)
				case <-mQuit.ClickedCh:
					mQuit.Disable()
					systray.SetTooltip("GoProxy — shutting down…")
					closeOnce(stop)
					return
				}
			}
		}()
	}, func() {})
	<-done
}

// ---------------- tray-only process (service mode) ----------------

type trayStatus struct {
	Version string `json:"version"`
	Service bool   `json:"service"`
	DNSOK   bool   `json:"dns_ok"`
	Alerts  []struct {
		Key     string `json:"key"`
		Level   string `json:"level"`
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"alerts"`
}

// runTray (`goproxy.exe -tray`) is the UI for the service: it only talks to the engine
// over the loopback API, so it can never freeze DNS.
func runTray(httpAddr string) int {
	name, _ := windows.UTF16PtrFromString(`Local\GoProxyDNS-Tray`)
	if _, err := windows.CreateMutex(nil, false, name); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return 0 // already running in this session
	}
	trayValue := func() string {
		exe, _, _ := exePaths()
		return `"` + exe + `" -tray` + map[bool]string{true: "", false: " -http-addr " + httpAddr}[httpAddr == ":8080"]
	}
	trayAuto := func() bool { v, ok := readRunValue(); return ok && strings.Contains(v, "-tray") }
	setTrayAuto := func(on bool) error { return writeRunValue(trayValue(), on) }
	systray.Run(func() {
		systray.SetIcon(trayIcon)
		systray.SetTitle(appName)
		systray.SetTooltip("GoProxy DNS — checking…")
		mStatus := systray.AddMenuItem("Checking DNS…", "")
		mStatus.Disable()
		mOpen := systray.AddMenuItem("Open Dashboard", "Open the live dashboard")
		mAuto := systray.AddMenuItemCheckbox("Show this icon at sign-in", "HKCU Run", trayAuto())
		systray.AddSeparator()
		mStop := systray.AddMenuItem("Stop DNS service…", "Stops DNS for the whole house")
		mQuit := systray.AddMenuItem("Close tray icon", "DNS keeps running")
		trayUp.Store(true)
		var busy atomic.Bool
		go trayPoll(httpAddr, mStatus)
		go func() {
			for {
				select {
				case <-mOpen.ClickedCh:
					_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", dashURL(httpAddr)).Start()
				case <-mAuto.ClickedCh:
					toggleAsync(mAuto, &busy, !mAuto.Checked(), setTrayAuto, trayAuto)
				case <-mStop.ClickedCh:
					go func() {
						if !confirmBox("GoProxy DNS", "Stop the GoProxy DNS service?\n\nDNS for every device in the house stops until the service is started again (restart the PC, or start \"GoProxy DNS\" in the Services app). Devices with Technitium as their second DNS server fall back to it.") {
							return
						}
						c := &http.Client{Timeout: 5 * time.Second}
						req, _ := http.NewRequest(http.MethodPost, localURL(httpAddr, "/api/shutdown"), nil)
						req.Header.Set("X-GoProxy-Stop", "1")
						if resp, err := c.Do(req); err == nil {
							resp.Body.Close()
						}
					}()
				case <-mQuit.ClickedCh:
					systray.Quit()
					return
				}
			}
		}()
	}, func() {})
	return 0
}

func trayPoll(httpAddr string, mStatus *systray.MenuItem) {
	c := &http.Client{Timeout: 3 * time.Second}
	seen := map[string]bool{}
	fails := 0
	warned := false
	for {
		var st trayStatus
		resp, err := c.Get(localURL(httpAddr, "/api/tray/status"))
		if err == nil {
			err = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&st)
			resp.Body.Close()
		}
		if err != nil {
			fails++
			if fails >= 2 {
				mStatus.SetTitle("DNS: not responding")
				systray.SetTooltip("GoProxy DNS is not responding")
				if !warned {
					notifyToast("GoProxy DNS is not responding", "The DNS service did not answer on this PC. Windows restarts it automatically if it crashed.")
					warned = true
				}
			}
		} else {
			fails, warned = 0, false
			if !st.Service && !serviceInstalled() {
				// a portable GoProxy (with its own tray) is serving now: don't show two icons
				systray.Quit()
				return
			}
			state := "OK"
			if !st.DNSOK {
				state = "self-test failing"
			}
			mStatus.SetTitle(fmt.Sprintf("DNS: %s · v%s · %d alert(s)", state, st.Version, len(st.Alerts)))
			systray.SetTooltip(fmt.Sprintf("GoProxy DNS v%s — %s", st.Version, state))
			now := map[string]bool{}
			for _, a := range st.Alerts {
				now[a.Key] = true
				if !seen[a.Key] {
					notifyToast(a.Title, a.Message)
				}
			}
			seen = now
		}
		time.Sleep(10 * time.Second)
	}
}

func confirmBox(title, msg string) bool {
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(msg)
	const mbYesNo, mbIconWarning, mbTopmost, idYes = 0x4, 0x30, 0x40000, 6
	r, _, _ := pMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbYesNo|mbIconWarning|mbTopmost)
	return r == idYes
}

// ---------------- balloon notifications ----------------

type notifyIconData struct {
	Size                       uint32
	Wnd                        windows.Handle
	ID, Flags, CallbackMessage uint32
	Icon                       windows.Handle
	Tip                        [128]uint16
	State, StateMask           uint32
	Info                       [256]uint16
	Timeout, Version           uint32
	InfoTitle                  [64]uint16
	InfoFlags                  uint32
	GuidItem                   windows.GUID
	BalloonIcon                windows.Handle
}

var (
	shell32           = windows.NewLazySystemDLL("shell32.dll")
	pShellNotifyIcon  = shell32.NewProc("Shell_NotifyIconW")
	pFindWindowEx     = user32.NewProc("FindWindowExW")
	pGetWindowThreadP = user32.NewProc("GetWindowThreadProcessId")
	toastMu           sync.Mutex
)

// trayWindow finds the hidden window fyne/systray created for our icon (class
// "SystrayClass", icon id 100) in this process.
func trayWindow() uintptr {
	cls, _ := windows.UTF16PtrFromString("SystrayClass")
	pid := uint32(os.Getpid())
	var after uintptr
	for i := 0; i < 64; i++ {
		h, _, _ := pFindWindowEx.Call(0, after, uintptr(unsafe.Pointer(cls)), 0)
		if h == 0 {
			return 0
		}
		var p uint32
		pGetWindowThreadP.Call(h, uintptr(unsafe.Pointer(&p)))
		if p == pid {
			return h
		}
		after = h
	}
	return 0
}

// notifyToast shows a tray balloon / Windows notification. It never blocks and does
// nothing when there is no tray (service mode, or before the icon exists).
func notifyToast(title, msg string) {
	if !trayUp.Load() {
		return
	}
	go func() {
		toastMu.Lock()
		defer toastMu.Unlock()
		h := trayWindow()
		if h == 0 {
			return
		}
		const nimModify, nifInfo, niifWarning = 1, 0x10, 2
		nid := notifyIconData{Wnd: windows.Handle(h), ID: 100, Flags: nifInfo, InfoFlags: niifWarning}
		nid.Size = uint32(unsafe.Sizeof(nid))
		t, _ := windows.UTF16FromString(title)
		m, _ := windows.UTF16FromString(msg)
		copy(nid.InfoTitle[:len(nid.InfoTitle)-1], t)
		copy(nid.Info[:len(nid.Info)-1], m)
		pShellNotifyIcon.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
	}()
}

const defaultUpdateDir = `C:\GoProxyDNS\updates`

const stopEventName = `Local\GoProxyDNS-Stop`

var (
	user32      = windows.NewLazySystemDLL("user32.dll")
	pMessageBox = user32.NewProc("MessageBoxW")
)

// notifyError pops a topmost error box so a failed start is never silent (the exe has no
// console). Callers must not hold locks or wait on it (see fatal).
func notifyError(title, msg string) {
	if serviceMode {
		eventLogError(title + ": " + msg)
		return
	}
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(msg)
	const mbIconError, mbTopmost, mbSetForeground = 0x10, 0x40000, 0x10000
	pMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), mbIconError|mbTopmost|mbSetForeground)
}

// watchStopEvent waits on a named event; `goproxy.exe -stop` sets it.
func watchStopEvent(fn func()) {
	name, _ := windows.UTF16PtrFromString(stopEventName)
	h, err := windows.CreateEvent(nil, 0, 0, name)
	if err != nil && h == 0 {
		return
	}
	go func() {
		if ev, _ := windows.WaitForSingleObject(h, windows.INFINITE); ev == windows.WAIT_OBJECT_0 {
			fn()
		}
	}()
}

func signalStopEvent() bool {
	name, _ := windows.UTF16PtrFromString(stopEventName)
	h, err := windows.OpenEvent(windows.EVENT_MODIFY_STATE, false, name)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.SetEvent(h) == nil
}

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

var _ = registry.CURRENT_USER
