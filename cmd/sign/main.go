// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
// Command sign creates and uses the GoProxy release signing key (ed25519).
//
//	go run ./cmd/sign -genkey -key keys/release-ed25519.key   (writes the private key 0600, prints only the PUBLIC key)
//	go run ./cmd/sign -key keys/release-ed25519.key dist/goproxy.exe   (writes dist/goproxy.exe.sig)
//
// The private key is never printed.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	key := flag.String("key", "keys/release-ed25519.key", "private key file (hex seed)")
	gen := flag.Bool("genkey", false, "generate a new key pair")
	pub := flag.Bool("pub", false, "print the public key (hex)")
	flag.Parse()
	if *gen {
		if _, err := os.Stat(*key); err == nil {
			fail("key already exists: " + *key)
		}
		p, s, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fail(err.Error())
		}
		_ = os.MkdirAll(filepath.Dir(*key), 0o700)
		if err := os.WriteFile(*key, []byte(hex.EncodeToString(s.Seed())+"\n"), 0o600); err != nil {
			fail(err.Error())
		}
		fmt.Println("public key:", hex.EncodeToString(p))
		return
	}
	b, err := os.ReadFile(*key)
	if err != nil {
		fail(err.Error())
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail("bad key file")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if *pub {
		fmt.Println(hex.EncodeToString(priv.Public().(ed25519.PublicKey)))
		return
	}
	for _, f := range flag.Args() {
		data, err := os.ReadFile(f)
		if err != nil {
			fail(err.Error())
		}
		sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
		if err := os.WriteFile(f+".sig", []byte(sig+"\n"), 0o644); err != nil {
			fail(err.Error())
		}
		fmt.Println("signed", f)
	}
}

func fail(m string) { fmt.Fprintln(os.Stderr, "sign:", m); os.Exit(1) }
