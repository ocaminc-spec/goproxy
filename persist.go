// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/miekg/dns"
)

// persistedEntry is the on-disk form of a cache entry (gob, wire-format message).
type persistedEntry struct {
	Key      string
	Wire     []byte
	Stored   time.Time
	Expires  time.Time
	OrigTTL  uint32
	Hits     int64
	Negative bool
}

const persistMagic = "goproxy-cache-v1"

// Save writes every still-servable entry to path atomically (tmp + rename).
func (c *DNSCache) Save(path string) (int, error) {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	enc := gob.NewEncoder(bw)
	if err := enc.Encode(persistMagic); err != nil {
		f.Close()
		return 0, err
	}
	now, n := c.now(), 0
	for _, s := range c.shards {
		s.mu.RLock()
		var batch []persistedEntry
		for k, e := range s.m {
			if now.After(e.Expires.Add(c.staleFor)) {
				continue
			}
			w, err := e.Msg.Pack()
			if err != nil {
				continue
			}
			batch = append(batch, persistedEntry{k, w, e.Stored, e.Expires, e.OrigTTL, e.Hits.Load(), e.Negative})
		}
		s.mu.RUnlock()
		for i := range batch {
			if err := enc.Encode(&batch[i]); err != nil {
				f.Close()
				return n, err
			}
			n++
		}
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return n, err
	}
	if err := f.Sync(); err != nil { // the rename must never expose a half-written file after a crash
		f.Close()
		return n, err
	}
	if err := f.Close(); err != nil {
		return n, err
	}
	return n, os.Rename(tmp, path)
}

// LoadFile restores entries saved by Save, skipping anything past its stale window.
func (c *DNSCache) LoadFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dec := gob.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	var magic string
	if err := dec.Decode(&magic); err != nil || magic != persistMagic {
		return 0, fmt.Errorf("%s: not a GoProxy cache snapshot (corrupt or wrong version), skipped", path)
	}
	now, n := c.now(), 0
	per := c.budget / int64(len(c.shards))
	var derr error
	for {
		var p persistedEntry
		if err := dec.Decode(&p); err != nil {
			if !errors.Is(err, io.EOF) {
				derr = fmt.Errorf("%s: truncated/corrupt after %d entries, rest skipped: %w", path, n, err)
			}
			break
		}
		if now.After(p.Expires.Add(c.staleFor)) {
			continue
		}
		m := new(dns.Msg)
		if m.Unpack(p.Wire) != nil {
			continue
		}
		e := &CacheEntry{Msg: m, Stored: p.Stored, Expires: p.Expires, OrigTTL: p.OrigTTL, Negative: p.Negative}
		e.Hits.Store(p.Hits)
		e.size = int64(len(p.Wire)) + int64(len(p.Key)) + 256
		s := c.shard(p.Key)
		s.mu.Lock()
		if _, exists := s.m[p.Key]; !exists { // never overwrite a live answer
			s.m[p.Key] = e
			s.bytes += e.size
			c.entries.Add(1)
			c.evictLocked(s, per, p.Key)
			n++
		}
		s.mu.Unlock()
	}
	return n, derr
}
