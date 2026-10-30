// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
)

// localZone: names GoProxy answers itself (Settings · Local names), e.g. nas.home.
type localZone map[string][]net.IP

func parseLocalNames(m map[string]string) (localZone, error) {
	z := localZone{}
	for name, val := range m {
		n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
		if err := validHostname(n); err != nil {
			return nil, fmt.Errorf("local name %q: %v", name, err)
		}
		for _, f := range splitList(val) {
			ip := net.ParseIP(f)
			if ip == nil {
				return nil, fmt.Errorf("local name %q: %q is not an IP address", name, f)
			}
			z[n] = append(z[n], ip)
		}
		if len(z[n]) == 0 {
			return nil, fmt.Errorf("local name %q: no IP address", name)
		}
	}
	return z, nil
}

func validHostname(n string) error {
	if n == "" || len(n) > 253 {
		return fmt.Errorf("bad length")
	}
	if isSelfTest(n + ".") {
		return fmt.Errorf("reserved")
	}
	for _, l := range strings.Split(n, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("bad label %q", l)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("bad character %q", c)
			}
		}
	}
	return nil
}

// applyLocalNames swaps the zone in atomically (the query path never locks).
func (s *DNSServer) applyLocalNames(st Settings) error {
	if !st.Feature("local_names") || len(st.LocalNames) == 0 {
		s.local.Store(nil)
		return nil
	}
	z, err := parseLocalNames(st.LocalNames)
	if err != nil {
		return err
	}
	s.local.Store(&z)
	return nil
}

// localAnswer answers A/AAAA (NODATA for other types) for a local name, or returns nil.
func (s *DNSServer) localAnswer(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	key := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	var ips []net.IP
	ok := false
	if zp := s.local.Load(); zp != nil {
		ips, ok = (*zp)[key]
	}
	if !ok && s.v282 != nil { // v2.8.2: automatic .home names learned from the router
		ips, ok = s.v282.autoName(key)
	}
	if !ok || q.Qclass != dns.ClassINET {
		return nil
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative, m.RecursionAvailable = true, true
	if req.IsEdns0() != nil {
		m.SetEdns0(ednsUDPSize, false)
	}
	hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: 60, Rrtype: q.Qtype}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && q.Qtype == dns.TypeA {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: v4})
		} else if v4 == nil && q.Qtype == dns.TypeAAAA {
			m.Answer = append(m.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
		}
	}
	return m
}

func (z localZone) names() []string {
	var out []string
	for n := range z {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
