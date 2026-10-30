// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
//go:build windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceMode is true when the Windows Service Control Manager started this process.
var serviceMode = false

const serviceName = "GoProxyDNS"

func isWindowsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

var elog *eventlog.Log

func eventLogError(msg string) {
	if elog != nil {
		_ = elog.Error(1, msg)
	}
}

func eventLogInfo(msg string) {
	if elog != nil {
		_ = elog.Info(1, msg)
	}
}

// svcHandler maps SCM requests onto the same graceful path as Quit / -stop / SIGTERM.
type svcHandler struct {
	ready, done <-chan struct{}
	stop        func()
}

func (h *svcHandler) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	return serviceLoop(h.ready, h.done, h.stop, r, s)
}

// serviceLoop is the SCM state machine (separate from svc.Run so it can be unit tested on
// Windows with fake channels).
func serviceLoop(ready, done <-chan struct{}, stop func(), r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending, WaitHint: 60000}
	stopping := false
	var tick <-chan time.Time
	cp := uint32(0)
	startStop := func() {
		if stopping {
			return
		}
		stopping = true
		s <- svc.Status{State: svc.StopPending, WaitHint: 30000}
		t := time.NewTicker(3 * time.Second)
		tick = t.C
		go stop()
	}
	readyCh := ready
	for {
		select {
		case <-readyCh:
			readyCh = nil
			if !stopping {
				s <- svc.Status{State: svc.Running, Accepts: accepts}
			}
		case <-done:
			s <- svc.Status{State: svc.StopPending, WaitHint: 5000}
			return false, 0
		case <-tick:
			cp++
			s <- svc.Status{State: svc.StopPending, WaitHint: 30000, CheckPoint: cp}
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				s <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Printf("service: %v requested by Windows", map[svc.Cmd]string{svc.Stop: "stop", svc.Shutdown: "shutdown"}[c.Cmd])
				startStop()
			}
		}
	}
}

// beginService connects to the SCM. It must be called early: Windows gives a service about
// 30 s to connect. wait() blocks until the SCM has been told the service stopped.
func beginService(ready, done <-chan struct{}, stop func()) (wait func()) {
	if l, err := eventlog.Open(serviceName); err == nil {
		elog = l
	}
	fin := make(chan struct{})
	go func() {
		defer close(fin)
		if err := svc.Run(serviceName, &svcHandler{ready: ready, done: done, stop: stop}); err != nil {
			log.Printf("service: %v", err)
		}
	}()
	return func() {
		select {
		case <-fin:
		case <-time.After(10 * time.Second):
		}
	}
}

// ---- SCM helpers that work without admin rights where possible ----

func openService(access uint32) (*mgr.Service, func(), error) {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return nil, nil, err
	}
	n, _ := windows.UTF16PtrFromString(serviceName)
	sh, err := windows.OpenService(h, n, access)
	if err != nil {
		windows.CloseServiceHandle(h)
		return nil, nil, err
	}
	s := &mgr.Service{Name: serviceName, Handle: sh}
	return s, func() { windows.CloseServiceHandle(sh); windows.CloseServiceHandle(h) }, nil
}

func serviceInstalled() bool {
	s, closeFn, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer closeFn()
	_ = s
	return true
}

func serviceState() (svc.State, error) {
	s, closeFn, err := openService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return 0, err
	}
	defer closeFn()
	st, err := s.Query()
	return st.State, err
}

func waitState(s *mgr.Service, want svc.State, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("service did not reach state %d within %v", want, d)
}

// stopViaSCM stops the service when it is installed and we are allowed to (admin).
func stopViaSCM() bool {
	s, closeFn, err := openService(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	defer closeFn()
	if st, err := s.Query(); err != nil || st.State == svc.Stopped {
		return false
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return false
	}
	return waitState(s, svc.Stopped, 40*time.Second) == nil
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
}

// startServiceRestart launches the helper that restarts the service after the exe was
// swapped by the updater. The helper inherits the service account (it needs to start the
// service) and outlives this process.
func startServiceRestart(cur string, restartOnly bool) error {
	a := theApp
	args := []string{"-service-restart", "-dns-addr", a.dnsAddr, "-data-dir", dataDir}
	if restartOnly {
		args = append(args, "-restart-only")
	}
	if a.upd != nil && a.upd.healthName != "" {
		args = append(args, "-health-name", a.upd.healthName)
	}
	cmd := exec.Command(cur, args...)
	cmd.Dir = exeDir()
	detach(cmd)
	return cmd.Start()
}

// serviceRestartHelper (`-service-restart`, internal): wait for the service to stop, start
// it with the new exe, and require a working DNS answer within 30 s; otherwise put the
// previous exe back and start that.
func serviceRestartHelper(dnsAddr, healthName string, restartOnly bool) int {
	t0 := time.Now()
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		log.Printf("service-restart: %v", err)
		return 1
	}
	defer windows.CloseServiceHandle(h)
	n, _ := windows.UTF16PtrFromString(serviceName)
	sh, err := windows.OpenService(h, n, windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		log.Printf("service-restart: open: %v", err)
		return 1
	}
	s := &mgr.Service{Name: serviceName, Handle: sh}
	defer s.Close()
	if err := waitState(s, svc.Stopped, 90*time.Second); err != nil {
		log.Printf("service-restart: old process did not stop: %v", err)
	}
	try := func() error {
		if err := s.Start(); err != nil {
			return err
		}
		if err := waitState(s, svc.Running, 60*time.Second); err != nil {
			return err
		}
		var last error
		for i := 0; i < 15; i++ {
			if last = healthCheck(dnsAddr, healthName); last == nil {
				return nil
			}
			time.Sleep(time.Second)
		}
		return last
	}
	if err := try(); err == nil {
		log.Printf("service-restart: new version is serving (DNS gap about %v)", time.Since(t0).Round(100*time.Millisecond))
		recordServiceUpdate(float64(time.Since(t0).Milliseconds()), "")
		return 0
	} else if restartOnly {
		log.Printf("service-restart: restart did not come back healthy: %v (Windows recovery actions apply)", err)
		return 1
	} else {
		log.Printf("service-restart: new version failed (%v); rolling back", err)
		_, _ = s.Control(svc.Stop)
		_ = waitState(s, svc.Stopped, 60*time.Second)
		cur, prev, _ := exePaths()
		if err := restoreExe(exeFS, cur, oldPath(cur), prev); err != nil {
			log.Printf("service-restart: restore: %v", err)
		}
		if err2 := s.Start(); err2 != nil {
			log.Printf("service-restart: could not start the previous version: %v", err2)
		}
		recordServiceUpdate(float64(time.Since(t0).Milliseconds()), err.Error())
		return 1
	}
}

func recordServiceUpdate(gapMs float64, failure string) {
	p := filepath.Join(dataDir, "goproxy-update.json")
	var l lastUpdate
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &l)
	}
	l.GapMs, l.Error = gapMs, failure
	if failure != "" {
		l.Kind = "service-rolled-back"
	}
	if b, err := json.Marshal(l); err == nil {
		_ = os.WriteFile(p, b, 0o644)
	}
}

// ---- install / migrate / uninstall (run from an Administrator prompt) ----

type migrationRecord struct {
	RunValue    string   `json:"run_value"`
	HadRun      bool     `json:"had_run"`
	InstalledAt string   `json:"installed_at"`
	Version     string   `json:"version"`
	ServiceArgs []string `json:"service_args"`
}

func migrationPath() string { return filepath.Join(dataDir, "goproxy-service-migration.json") }

func elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func readRunValue() (string, bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return "", false
	}
	defer k.Close()
	v, _, err := k.GetStringValue(appName)
	return v, err == nil
}

func writeRunValue(v string, on bool) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if !on {
		if err := k.DeleteValue(appName); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	return k.SetStringValue(appName, v)
}

// argsFromRunValue extracts the user's flags from an old Run entry ("C:\..\goproxy.exe" -cache-gb 8).
func argsFromRunValue(v string) []string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, `"`) {
		if i := strings.Index(v[1:], `"`); i >= 0 {
			v = v[i+2:]
		}
	} else if i := strings.Index(v, " "); i >= 0 {
		v = v[i:]
	} else {
		v = ""
	}
	return filterArgs(strings.Fields(v))
}

func say(title, msg string, isErr bool) {
	log.Print(title + ": " + msg)
	fmt.Println(title + ": " + msg)
	flags := uintptr(0x40) // MB_ICONINFORMATION
	if isErr {
		flags = 0x10
	}
	t, _ := windows.UTF16PtrFromString(title)
	m, _ := windows.UTF16PtrFromString(msg)
	pMessageBox.Call(0, uintptr(unsafe.Pointer(m)), uintptr(unsafe.Pointer(t)), flags|0x40000)
}

func installService(extra []string) int {
	if !elevated() {
		say("GoProxy DNS", "Installing the service needs an Administrator prompt.\n\nRight-click install-service.cmd > Run as administrator.", true)
		return 1
	}
	exe, _, _ := exePaths()
	oldRun, hadRun := readRunValue()
	svcArgs := []string{"-service", "-data-dir", dataDir}
	seen := map[string]bool{"data-dir": true}
	for _, a := range append(append([]string{}, extra...), argsFromRunValue(oldRun)...) {
		if n, _ := flagName(a); n != "" && seen[n] {
			continue
		} else if n != "" {
			seen[n] = true
		}
		svcArgs = append(svcArgs, a)
	}
	rec := migrationRecord{RunValue: oldRun, HadRun: hadRun, InstalledAt: time.Now().Format(time.RFC3339), Version: Version, ServiceArgs: svcArgs}
	if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
		_ = os.WriteFile(migrationPath(), b, 0o644)
	}
	httpAddr, dnsAddr := ":8080", ":53"
	for i, a := range svcArgs {
		if n, _ := flagName(a); i+1 < len(svcArgs) {
			if n == "http-addr" {
				httpAddr = svcArgs[i+1]
			} else if n == "dns-addr" {
				dnsAddr = svcArgs[i+1]
			}
		}
	}
	// 1. stop the portable copy (saves the cache)
	log.Print("install-service: stopping the running GoProxy (if any)")
	runStopCmd(httpAddr)
	// 2. create or update the service
	m, err := mgr.Connect()
	if err != nil {
		say("GoProxy DNS", "Could not open the Service Control Manager: "+err.Error(), true)
		return 1
	}
	defer m.Disconnect()
	cfg := mgr.Config{DisplayName: "GoProxy DNS", Description: "GoProxy caching DNS server for the home network (dashboard on port 8080).",
		StartType: mgr.StartAutomatic, DelayedAutoStart: true, ErrorControl: mgr.ErrorNormal}
	s, err := m.OpenService(serviceName)
	if err == nil {
		cfg.BinaryPathName = `"` + exe + `" ` + quoteArgs(svcArgs)
		err = s.UpdateConfig(cfg)
	} else {
		s, err = m.CreateService(serviceName, exe, cfg, svcArgs...)
	}
	if err != nil {
		say("GoProxy DNS", "Could not create the service: "+err.Error()+"\n\nStarting the normal (portable) GoProxy again.", true)
		restartPortable(exe, oldRun)
		return 1
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	// 3. start it and require a DNS answer
	if err := s.Start(); err == nil {
		err = waitState(s, svc.Running, 60*time.Second)
	}
	var herr error
	for i := 0; i < 20; i++ {
		if herr = healthCheck(dnsAddr, "www.google.com"); herr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if herr != nil {
		_, _ = s.Control(svc.Stop)
		_ = waitState(s, svc.Stopped, 30*time.Second)
		_ = s.Delete()
		restartPortable(exe, oldRun)
		say("GoProxy DNS", "The service started but did not answer DNS ("+herr.Error()+"). It was removed and the normal GoProxy was started again. Details: "+logPath, true)
		return 1
	}
	// 4. the old Run entry now starts the tray only
	trayCmd := `"` + exe + `" -tray`
	if httpAddr != ":8080" {
		trayCmd += " -http-addr " + httpAddr
	}
	_ = writeRunValue(trayCmd, true)
	tray := exec.Command(exe, "-tray", "-http-addr", httpAddr)
	detach(tray)
	_ = tray.Start()
	say("GoProxy DNS", "GoProxy DNS now runs as a Windows service ("+serviceName+"). It starts with Windows before anyone signs in and is restarted automatically if it stops.\n\nThe tray icon is now only the status/menu. To undo: run uninstall-service.cmd as administrator.", false)
	return 0
}

func restartPortable(exe, runValue string) {
	cmd := exec.Command(exe, argsFromRunValue(runValue)...)
	cmd.Dir = filepath.Dir(exe)
	detach(cmd)
	_ = cmd.Start()
}

func uninstallService() int {
	if !elevated() {
		say("GoProxy DNS", "Removing the service needs an Administrator prompt.\n\nRight-click uninstall-service.cmd > Run as administrator.", true)
		return 1
	}
	exe, _, _ := exePaths()
	m, err := mgr.Connect()
	if err != nil {
		say("GoProxy DNS", "Could not open the Service Control Manager: "+err.Error(), true)
		return 1
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		say("GoProxy DNS", "The GoProxyDNS service is not installed.", true)
		return 1
	}
	_, _ = s.Control(svc.Stop)
	_ = waitState(s, svc.Stopped, 40*time.Second)
	if err := s.Delete(); err != nil {
		s.Close()
		say("GoProxy DNS", "Could not remove the service: "+err.Error(), true)
		return 1
	}
	s.Close()
	_ = eventlog.Remove(serviceName)
	var rec migrationRecord
	if b, err := os.ReadFile(migrationPath()); err == nil {
		_ = json.Unmarshal(b, &rec)
	}
	run := rec.RunValue
	if !rec.HadRun || run == "" || strings.Contains(run, "-tray") {
		run = `"` + exe + `"`
	}
	_ = writeRunValue(run, rec.HadRun || rec.RunValue == "")
	time.Sleep(time.Second)
	restartPortable(exe, run)
	say("GoProxy DNS", "The service was removed and GoProxy runs in the normal (portable) way again, with the tray icon and \"Start with Windows\".", false)
	return 0
}

var (
	kernel32        = windows.NewLazySystemDLL("kernel32.dll")
	pAttachConsole  = kernel32.NewProc("AttachConsole")
	consoleAttached bool
)

// attachConsole lets command-line modes (-version, -install-service, ...) print to the
// console they were started from, even though the exe is a windowsgui build.
func attachConsole() {
	const attachParent = ^uintptr(0)
	if r, _, _ := pAttachConsole.Call(attachParent); r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout, os.Stderr = f, f
		consoleAttached = true
	}
}
