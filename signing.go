// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

// Signed releases (v2.4.2). Release zips carry goproxy.exe.sig: an ed25519 signature of
// goproxy.exe made with the release key (kept off this PC). A signature that does not match
// is ALWAYS rejected. Unsigned files are accepted unless "Require signed updates" is on
// (Advanced · Updates, off by default), then they are rejected with a clear message.
// Rollback to goproxy.prev.exe is not checked (it was already running here).

// releasePubKey is the public half of the release key (hex).
const releasePubKey = "8e81f5df57104aee483ab9a72198d512ef5f6b33a9b005ef7e2086b6771301a6"

var errUnsigned = errors.New("this update is not signed. \"Require signed updates\" is on (Advanced · Updates), so only official GoProxy release zips (with goproxy.exe.sig inside) are accepted")

func releaseKey() ed25519.PublicKey {
	b, _ := hex.DecodeString(releasePubKey)
	return ed25519.PublicKey(b)
}

// zipSignature returns the base64 signature stored next to the exe in a release zip.
func zipSignature(data []byte) string {
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return ""
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return ""
	}
	for _, f := range zr.File {
		b := strings.ToLower(filepath.Base(f.Name))
		if b == "goproxy.exe.sig" || b == "goproxy.sig" {
			rc, err := f.Open()
			if err != nil {
				return ""
			}
			s, _ := io.ReadAll(io.LimitReader(rc, 4096))
			rc.Close()
			return strings.TrimSpace(string(s))
		}
	}
	return ""
}

// verifyRelease checks bin against sig (base64). Returns "signed" / "unsigned".
func verifyRelease(bin []byte, sig string, require bool, key ed25519.PublicKey) (string, error) {
	sig = strings.TrimSpace(sig)
	if sig == "" {
		if require {
			return "unsigned", errUnsigned
		}
		return "unsigned", nil
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", errors.New("the update's signature is damaged (goproxy.exe.sig); it was not installed")
	}
	if !ed25519.Verify(key, bin, raw) {
		return "", errors.New("the update's signature does NOT match the GoProxy release key: the file was changed or is not an official build; it was not installed")
	}
	return "signed", nil
}

// prepareSigned = prepare + signature check. sig overrides the zip's .sig (manifest / form).
func (u *Updater) prepareSigned(data []byte, name, want, sig string) ([]byte, string, error) {
	if sig == "" {
		sig = zipSignature(data)
	}
	bin, err := prepare(data, name, want)
	if err != nil {
		return nil, "", err
	}
	require := false
	if u.app != nil && u.app.s != nil {
		require = u.app.s.settings.Get().RequireSigned
	}
	state, err := verifyRelease(bin, sig, require, releaseKey())
	return bin, state, err
}

func signedMsg(state string) string {
	if state == "signed" {
		return "release signature verified"
	}
	return "NOT signed (accepted because \"Require signed updates\" is off)"
}
