// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ClientNames resolves client IPs to device names via PTR lookups to the router, in the
// background (never on the query path). Results are cached for an hour.
type ClientNames struct {
	server string
	mu     sync.Mutex
	m      map[string]clientName
	sem    chan struct{}
	c      *dns.Client
}

type clientName struct {
	name string
	at   time.Time
	busy bool
}

func NewClientNames(server string) *ClientNames {
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &ClientNames{server: server, m: map[string]clientName{}, sem: make(chan struct{}, 2), c: &dns.Client{Timeout: 2 * time.Second}}
}

func (c *ClientNames) Seen(ip string) {
	c.mu.Lock()
	e, ok := c.m[ip]
	if (ok && (e.busy || time.Since(e.at) < time.Hour)) || len(c.m) > 4096 {
		c.mu.Unlock()
		return
	}
	e.busy = true
	c.m[ip] = e
	c.mu.Unlock()
	go c.lookup(ip)
}

func (c *ClientNames) lookup(ip string) {
	c.sem <- struct{}{}
	defer func() { <-c.sem }()
	name := ""
	if arpa, err := dns.ReverseAddr(ip); err == nil {
		m := new(dns.Msg)
		m.SetQuestion(arpa, dns.TypePTR)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if r, _, err := c.c.ExchangeContext(ctx, m, c.server); err == nil {
			for _, rr := range r.Answer {
				if p, ok := rr.(*dns.PTR); ok {
					name = strings.TrimSuffix(p.Ptr, ".")
					break
				}
			}
		}
		cancel()
	}
	if name == "" && (ip == "127.0.0.1" || ip == "::1") {
		name = "this PC"
	}
	c.mu.Lock()
	c.m[ip] = clientName{name: name, at: time.Now()}
	c.mu.Unlock()
}

func (c *ClientNames) Name(ip string) string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[ip].name
}
