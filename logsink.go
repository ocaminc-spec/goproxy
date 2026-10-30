// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"io"
	"os"
	"sync"
)

// safeLogWriter fixes two v2.3.1 logging hazards (see the v2.4.0 changelog, "hang"):
//
//  1. io.MultiWriter(os.Stderr, file) stops at the FIRST writer that fails. A windowsgui
//     build started from Explorer or the Run key has no stderr, so every write failed on
//     stderr and nothing ever reached goproxy.log.
//  2. When GoProxy is started by another program (a remote shell, an installer, the
//     updater) its stderr can be a pipe that nobody reads. Once the pipe buffer fills,
//     every log.Printf blocks forever while holding the log package's mutex, and any
//     goroutine that logs (the tray, the updater, auth, the HTTP server's error log)
//     freezes with it.
//
// The file is written first and synchronously (it is a local disk). The console copy goes
// through a small buffered queue drained by one goroutine and is dropped when full, so a
// stuck pipe can never block the program.
type safeLogWriter struct {
	mu   sync.Mutex
	file io.Writer
	q    chan []byte
}

func newSafeLogWriter(file io.Writer, console io.Writer) *safeLogWriter {
	w := &safeLogWriter{file: file}
	if console != nil {
		w.q = make(chan []byte, 256)
		go func() {
			for b := range w.q {
				_, _ = console.Write(b)
			}
		}()
	}
	return w
}

func (w *safeLogWriter) Write(p []byte) (int, error) {
	if w.file != nil {
		w.mu.Lock()
		_, _ = w.file.Write(p)
		w.mu.Unlock()
	}
	if w.q != nil {
		b := append([]byte(nil), p...)
		select {
		case w.q <- b:
		default: // console not being read: drop rather than block
		}
	}
	return len(p), nil
}

// consoleWriter returns os.Stderr when it is usable, else nil.
func consoleWriter() io.Writer {
	if os.Stderr == nil {
		return nil
	}
	if _, err := os.Stderr.Stat(); err != nil {
		return nil
	}
	return os.Stderr
}
