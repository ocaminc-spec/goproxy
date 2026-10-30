// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fastSwap(t *testing.T) {
	s, st, p := swapSettle, swapStep, swapPoll
	swapSettle, swapStep, swapPoll = 2*time.Second, 300*time.Millisecond, time.Millisecond
	t.Cleanup(func() { swapSettle, swapStep, swapPoll = s, st, p })
}

// winFS simulates Windows: a running exe can be renamed (the lock follows the file) but
// not deleted or replaced; renaming onto an existing locked file fails.
//
// scan simulates an antivirus/indexer handle on a file opened WITHOUT delete sharing:
// renaming or deleting that path fails with a sharing violation for the next scan[path]
// attempts (-1 = forever); reading it (copying from it) still works. afterRename lets a test
// make the scanner pick a file up again under its new name.
type winFS struct {
	osFS
	locked      map[string]bool
	mu          sync.Mutex
	scan        map[string]int
	afterRename func(from, to string)
	renames     []string
}

func (w *winFS) scanned(p string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, ok := w.scan[p]
	if !ok || n == 0 {
		return false
	}
	if n > 0 {
		w.scan[p] = n - 1
	}
	return true
}

func (w *winFS) setScan(p string, n int) {
	w.mu.Lock()
	if w.scan == nil {
		w.scan = map[string]int{}
	}
	w.scan[p] = n
	w.mu.Unlock()
}

func (w *winFS) Locked(err error) bool { return errors.Is(err, errInUse) }

var errInUse = errors.New("The process cannot access the file because it is being used by another process.")

func (w *winFS) Rename(a, b string) error {
	if w.locked[b] {
		return &os.LinkError{Op: "rename", Old: a, New: b, Err: errInUse}
	}
	if w.scanned(a) {
		return &os.LinkError{Op: "rename", Old: a, New: b, Err: errInUse}
	}
	if err := os.Rename(a, b); err != nil {
		return err
	}
	w.mu.Lock()
	w.renames = append(w.renames, filepath.Base(a)+">"+filepath.Base(b))
	w.mu.Unlock()
	if w.locked[a] {
		delete(w.locked, a)
		w.locked[b] = true
	}
	if w.afterRename != nil {
		w.afterRename(a, b)
	}
	return nil
}
func (w *winFS) Remove(n string) error {
	if w.locked[n] || w.scanned(n) {
		return errInUse
	}
	return os.Remove(n)
}
func (w *winFS) CopyDirect(a, b string) error {
	if w.locked[b] {
		return errInUse
	}
	return copyDirect(a, b)
}
func (w *winFS) Copy(a, b string) error {
	if w.locked[b] {
		return errInUse
	}
	return copyFile(a, b)
}

func setupExes(t *testing.T) (dir, cur, prev, next string) {
	dir = t.TempDir()
	cur, prev, next = filepath.Join(dir, "goproxy.exe"), filepath.Join(dir, "goproxy.prev.exe"), filepath.Join(dir, "goproxy.new.exe")
	os.WriteFile(cur, []byte("v1"), 0o755)
	os.WriteFile(next, []byte("v2"), 0o755)
	return
}

func content(t *testing.T, p string) string { b, _ := os.ReadFile(p); return string(b) }

func TestOldSchemeFailsOnWindows(t *testing.T) {
	// documents the original bug: replacing a running exe is refused
	_, cur, _, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	if err := fs.Rename(next, cur); err == nil {
		t.Fatal("simulator should refuse replacing a running exe")
	}
}

func TestInstallExeWhileRunning(t *testing.T) {
	_, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	if content(t, cur) != "v2" || content(t, prev) != "v1" || content(t, oldPath(cur)) != "v1" {
		t.Fatalf("cur=%q prev=%q old=%q", content(t, cur), content(t, prev), content(t, oldPath(cur)))
	}
	if !fs.locked[oldPath(cur)] || fs.locked[prev] {
		t.Fatal("running image should be .old, prev must be an unlocked copy")
	}
}

func TestInstallWithStaleLockedOld(t *testing.T) {
	_, cur, prev, next := setupExes(t)
	old := oldPath(cur)
	os.WriteFile(old, []byte("v0"), 0o755)
	fs := &winFS{locked: map[string]bool{cur: true, old: true}}
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	if content(t, cur) != "v2" {
		t.Fatal("not installed")
	}
}

func TestRestoreAfterFailedStart(t *testing.T) {
	_, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	restore, err := installExe(fs, cur, prev, next, true)
	if err != nil {
		t.Fatal(err)
	}
	fs.locked[cur] = true // the new version is running (and failing)
	if err := restore(); err != nil {
		t.Fatal(err)
	}
	if content(t, cur) != "v1" || content(t, failPath(cur)) != "v2" {
		t.Fatalf("cur=%q failed=%q", content(t, cur), content(t, failPath(cur)))
	}
}

func TestRestoreFallsBackToPrev(t *testing.T) {
	_, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{}}
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	os.Remove(oldPath(cur)) // e.g. cleaned up already
	if err := restoreExe(fs, cur, oldPath(cur), prev); err != nil || content(t, cur) != "v1" {
		t.Fatalf("err=%v cur=%q", err, content(t, cur))
	}
}

func TestInstallFailureRestores(t *testing.T) {
	_, cur, prev, next := setupExes(t)
	os.Remove(next) // install rename will fail
	fs := &winFS{locked: map[string]bool{cur: true}}
	if _, err := installExe(fs, cur, prev, next, true); err == nil {
		t.Fatal("expected error")
	}
	if content(t, cur) != "v1" || !fs.locked[cur] {
		t.Fatal("original exe not restored")
	}
}

func TestRollbackRoundTrip(t *testing.T) {
	dir, cur, prev, next := setupExes(t)
	fs := &winFS{locked: map[string]bool{cur: true}}
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	// v2 now runs from cur; old v1 process exited: unlock .old, lock cur
	fs.locked = map[string]bool{cur: true}
	// rollback: prev's bytes are staged as next
	b, _ := os.ReadFile(prev)
	os.WriteFile(filepath.Join(dir, "goproxy.new.exe"), b, 0o755)
	if _, err := installExe(fs, cur, prev, next, true); err != nil {
		t.Fatal(err)
	}
	if content(t, cur) != "v1" || content(t, prev) != "v2" {
		t.Fatalf("cur=%q prev=%q", content(t, cur), content(t, prev))
	}
}

func TestCleanupOldExes(t *testing.T) {
	dir, cur, prev, _ := setupExes(t)
	for _, n := range []string{"goproxy.old.exe", "goproxy.old-123.exe", "goproxy.failed.exe", "goproxy.prev.exe.tmp"} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o755)
	}
	cleanupOldExes(cur, prev)
	m, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(m) != 2 { // goproxy.exe + goproxy.new.exe
		t.Fatalf("left: %v", m)
	}
}
