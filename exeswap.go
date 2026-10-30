// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Windows lets a running .exe be RENAMED but not replaced or deleted. So installing never
// overwrites the running file: the running goproxy.exe is first moved aside to
// goproxy.old.exe, then goproxy.new.exe is renamed into place. goproxy.prev.exe (the
// rollback copy) is always a plain COPY, never the image of a running process, so it can
// always be replaced later. goproxy.old.exe is deleted at the next start (retried while the
// old process still holds it).

//
// v2.4.3: a freshly written (and just probed with -version) goproxy.new.exe is usually opened
// for a few seconds by the antivirus (Windows Defender scans new executables on write and on
// first run) WITHOUT sharing delete access. Renaming it then fails with "The process cannot
// access the file because it is being used by another process" (ERROR_SHARING_VIOLATION),
// which is exactly how the v2.4.1 -> v2.4.2 dashboard update failed. So now:
//   1. the staged file is first renamed to goproxy.ready.exe, retrying while it is locked
//      (up to swapSettle). The running exe is untouched until this succeeds;
//   2. the running exe is moved aside (retried briefly);
//   3. goproxy.ready.exe is renamed into place (retried briefly); if it is still locked, its
//      bytes are copied into place instead (a scanner only blocks delete/rename, not reading).

// swapFS is the filesystem used by the swap; tests replace it to simulate Windows locks.
type swapFS interface {
	Rename(from, to string) error
	Remove(name string) error
	Stat(name string) (os.FileInfo, error)
	Copy(from, to string) error       // via to+".tmp" and a rename (atomic)
	CopyDirect(from, to string) error // straight into to (to must not exist); no rename involved
	Locked(err error) bool            // a transient "in use by another process" error
}

type osFS struct{}

func (osFS) Rename(a, b string) error           { return os.Rename(a, b) }
func (osFS) Remove(n string) error              { return os.Remove(n) }
func (osFS) Stat(n string) (os.FileInfo, error) { return os.Stat(n) }
func (osFS) Copy(from, to string) error         { return copyFile(from, to) }
func (osFS) CopyDirect(from, to string) error   { return copyDirect(from, to) }
func (osFS) Locked(err error) bool              { return isFileLockErr(err) }

// how long to wait for another process (antivirus, indexer) to let go of a file.
var (
	swapSettle = 45 * time.Second // staged file, before anything is touched
	swapStep   = 8 * time.Second  // each rename once the running exe has been moved
	swapPoll   = 50 * time.Millisecond
)

// progress messages during a swap (the updater logs them)
var swapNotifyMu sync.Mutex
var swapNotifyFn = func(string) {}

func setSwapNotify(f func(string)) {
	swapNotifyMu.Lock()
	swapNotifyFn = f
	swapNotifyMu.Unlock()
}

func swapNotify(m string) {
	swapNotifyMu.Lock()
	f := swapNotifyFn
	swapNotifyMu.Unlock()
	f(m)
}

// renameRetry renames, retrying while the error is a transient lock, for up to wait.
func renameRetry(fs swapFS, from, to string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	d, said := swapPoll, false
	for {
		err := fs.Rename(from, to)
		if err == nil || !fs.Locked(err) || time.Now().After(deadline) {
			return err
		}
		if !said {
			said = true
			swapNotify(fmt.Sprintf("%s is in use by another program (usually the antivirus checking the new file); waiting", filepath.Base(from)))
		}
		time.Sleep(d)
		if d < 20*swapPoll { // 50 ms .. 1 s
			d *= 2
		}
	}
}

func copyDirect(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(to)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(to)
		return err
	}
	return out.Close()
}

var exeFS swapFS = osFS{}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := to + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, to)
}

func oldPath(cur string) string   { return sibling(cur, ".old") }
func failPath(cur string) string  { return sibling(cur, ".failed") }
func readyPath(cur string) string { return sibling(cur, ".ready") }

func sibling(cur, tag string) string {
	ext := ""
	if strings.HasSuffix(strings.ToLower(cur), ".exe") {
		ext = cur[len(cur)-4:]
	}
	return strings.TrimSuffix(cur, ext) + tag + ext
}

// installExe puts next in place of the (possibly running) cur. When keepPrev is true the
// current exe is first copied to prev for a later rollback (a rollback itself keeps prev as
// it is, so you can switch back and forth). It returns a restore func that puts the
// original exe back. On error cur is the original exe again.
func installExe(fs swapFS, cur, prev, next string, keepPrev bool) (restore func() error, err error) {
	old := oldPath(cur)
	ready := readyPath(cur)
	// 1. settle: prove we may rename the new file (nobody holds it without delete sharing)
	//    before the running exe is touched.
	_ = fs.Remove(ready)
	if _, err := fs.Stat(ready); err == nil {
		ready = sibling(cur, fmt.Sprintf(".ready-%d", time.Now().UnixNano()))
	}
	if err := renameRetry(fs, next, ready, swapSettle); err != nil {
		if fs.Locked(err) {
			return nil, fmt.Errorf("the new file is still in use by another program (antivirus?) after %v: %w", swapSettle, err)
		}
		return nil, fmt.Errorf("stage: %w", err)
	}
	unstage := func() { _ = renameRetry(fs, ready, next, swapStep) }
	if keepPrev {
		if err := fs.Copy(cur, prev); err != nil {
			unstage()
			return nil, fmt.Errorf("backup copy: %w", err)
		}
	}
	_ = fs.Remove(old) // stale from an earlier update; may still be locked (ignored)
	aside := old
	if _, err := fs.Stat(old); err == nil {
		// still locked by an old process: use a unique name instead
		aside = sibling(cur, fmt.Sprintf(".old-%d", time.Now().UnixNano()))
	}
	// 2. move the running exe aside (Windows allows renaming a running exe)
	if err := renameRetry(fs, cur, aside, swapStep); err != nil {
		unstage()
		return nil, fmt.Errorf("move running exe aside: %w", err)
	}
	// 3. new exe into place: rename, or copy its bytes if it got locked again meanwhile
	if err := renameRetry(fs, ready, cur, swapStep); err != nil {
		cerr := fs.CopyDirect(ready, cur)
		if cerr == nil {
			swapNotify("the new file was copied into place (it was still locked for renaming)")
			_ = fs.Remove(ready) // may fail while locked; cleaned up at the next start
		} else {
			_ = fs.Remove(cur) // a partial copy, if any
			if e2 := renameRetry(fs, aside, cur, swapStep); e2 != nil {
				return nil, fmt.Errorf("install: %w; copy: %v (and restore failed: %v)", err, cerr, e2)
			}
			unstage()
			return nil, fmt.Errorf("install: %w; copy: %v", err, cerr)
		}
	}
	return func() error { return restoreExe(fs, cur, aside, prev) }, nil
}

// restoreExe puts the moved-aside exe back (or, if it is gone, a copy of prev). The failed
// new exe may be running, so it is renamed (never deleted) out of the way.
func restoreExe(fs swapFS, cur, aside, prev string) error {
	failed := failPath(cur)
	_ = fs.Remove(failed)
	if _, err := fs.Stat(failed); err == nil {
		failed = sibling(cur, fmt.Sprintf(".failed-%d", time.Now().UnixNano()))
	}
	if _, err := fs.Stat(cur); err == nil {
		if err := renameRetry(fs, cur, failed, swapStep); err != nil {
			return fmt.Errorf("move failed exe aside: %w", err)
		}
	}
	if aside != "" {
		if err := renameRetry(fs, aside, cur, swapStep); err == nil {
			return nil
		}
	}
	if prev != "" {
		if err := fs.Copy(prev, cur); err == nil {
			return nil
		}
	}
	_ = fs.Rename(failed, cur) // nothing to restore: keep at least something in place
	return errors.New("no previous exe to restore")
}

// cleanupOldExes deletes leftover goproxy.old*.exe / .failed*.exe / .prev.exe.tmp files.
// Files still held by an exiting process are retried every 30 s for up to 10 minutes.
func cleanupOldExes(cur, prev string) {
	if cur == "" {
		return
	}
	try := func() (left int) {
		for _, p := range leftoverExes(cur, prev) {
			if fi, err := os.Stat(p); err == nil && strings.Contains(filepath.Base(p), ".ready") && time.Since(fi.ModTime()) < 2*time.Minute {
				continue // may belong to an update that is running right now
			}
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				left++
			}
		}
		return
	}
	if try() == 0 {
		return
	}
	go func() {
		for i := 0; i < 20; i++ {
			time.Sleep(30 * time.Second)
			if try() == 0 {
				return
			}
		}
		log.Printf("update: could not delete old exe files next to %s (still in use)", cur)
	}()
}

func leftoverExes(cur, prev string) []string {
	var out []string
	for _, pat := range []string{oldPath(cur), sibling(cur, ".old-*"), failPath(cur), sibling(cur, ".failed-*"), readyPath(cur), sibling(cur, ".ready-*")} {
		m, _ := globSafe(pat)
		out = append(out, m...)
	}
	if prev != "" {
		if _, err := os.Stat(prev + ".tmp"); err == nil {
			out = append(out, prev+".tmp")
		}
	}
	return out
}

func globSafe(p string) ([]string, error) { return filepathGlob(p) }

var filepathGlob = filepath.Glob
