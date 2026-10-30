// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

// v2.6.0: secrets at rest. Settings fields that hold a secret (the ntfy access token) are
// stored AES-256-GCM encrypted ("enc:v1:<base64 nonce|ciphertext>") with a random key kept in
// goproxy-secret.key (0600) next to the settings file. Plain values from older versions are
// still read and are encrypted on the next save. Passwords are never stored (bcrypt only).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const secretPrefix = "enc:v1:"

var secretKeyMu sync.Mutex

func secretKeyPath(settingsPath string) string {
	return filepath.Join(filepath.Dir(settingsPath), "goproxy-secret.key")
}

// secretKey loads (or creates, 0600) the 32-byte key.
func secretKey(settingsPath string) ([]byte, error) {
	secretKeyMu.Lock()
	defer secretKeyMu.Unlock()
	p := secretKeyPath(settingsPath)
	if b, err := os.ReadFile(p); err == nil {
		if len(b) != 32 {
			return nil, errors.New("goproxy-secret.key: wrong size")
		}
		return b, nil
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.WriteFile(p+".tmp", k, 0o600); err != nil {
		return nil, err
	}
	return k, os.Rename(p+".tmp", p)
}

func sealSecret(key []byte, plain string) (string, error) {
	if plain == "" || strings.HasPrefix(plain, secretPrefix) {
		return plain, nil
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, _ := cipher.NewGCM(blk)
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	return secretPrefix + base64.StdEncoding.EncodeToString(g.Seal(n, n, []byte(plain), []byte("goproxy-secret"))), nil
}

func openSecret(key []byte, v string) (string, error) {
	if !strings.HasPrefix(v, secretPrefix) {
		return v, nil // legacy plain value
	}
	raw, err := base64.StdEncoding.DecodeString(v[len(secretPrefix):])
	if err != nil {
		return "", err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, _ := cipher.NewGCM(blk)
	if len(raw) < g.NonceSize() {
		return "", errors.New("secret too short")
	}
	p, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], []byte("goproxy-secret"))
	return string(p), err
}

// secretFields: every secret in Settings (v2.7.0 adds the webhook URL and token).
func secretFields(s *Settings) []*string {
	return []*string{&s.NtfyToken, &s.PeerToken, &s.V27.WebhookURL, &s.V27.WebhookToken}
}

// sealSettings / openSettings convert every secret field of s for disk / memory.
func (st *settingsStore) sealSettings(s *Settings) error {
	fs := secretFields(s)
	any := false
	for _, f := range fs {
		any = any || *f != ""
	}
	if !any {
		return nil
	}
	k, err := secretKey(st.path)
	if err != nil {
		return err
	}
	for _, f := range fs {
		if *f, err = sealSecret(k, *f); err != nil {
			return err
		}
	}
	return nil
}

func (st *settingsStore) openSettings(s *Settings) {
	sealed := false
	for _, f := range secretFields(s) {
		sealed = sealed || strings.HasPrefix(*f, secretPrefix)
	}
	if !sealed {
		return
	}
	k, kerr := secretKey(st.path)
	for _, f := range secretFields(s) {
		if !strings.HasPrefix(*f, secretPrefix) {
			continue
		}
		v, err := "", kerr
		if err == nil {
			v, err = openSecret(k, *f)
		}
		if err != nil {
			v = "" // unreadable (key lost): treat as not set, never crash
		}
		*f = v
	}
}
