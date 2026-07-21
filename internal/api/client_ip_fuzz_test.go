package api

import (
	"net/netip"
	"strings"
	"testing"
)

// Native Go fuzz targets for the untrusted client-IP parsing that feeds the
// rate-limiter key. These functions read attacker-controlled RemoteAddr,
// X-Forwarded-For, and X-Real-IP values, so they must never panic and must
// produce a canonical, stable key. Each target asserts a behavioral oracle, not
// merely "does not panic". Under `go test` the seed corpus runs as ordinary
// regression tests; run e.g.
//
//	go test ./internal/api -run x -fuzz FuzzParseClientIP -fuzztime 30s
//
// to actively fuzz a single target.

// FuzzParseClientIP checks that parsing an arbitrary host[:port] value never
// panics and that an accepted address is valid, canonical, and IPv4-unmapped —
// the last property is what stops `::ffff:1.2.3.4` and `1.2.3.4` from minting
// two different rate-limit buckets for the same client.
func FuzzParseClientIP(f *testing.F) {
	for _, seed := range []string{
		"", "   ", "1.2.3.4", "1.2.3.4:443", "[2001:db8::1]:443", "2001:db8::1",
		"[2001:db8::1]", "::ffff:1.2.3.4", "[::ffff:1.2.3.4]:80", "fe80::1%eth0",
		"999.999.999.999", "1.2.3.4:notaport", "[malformed", "0:0:0:0:0:0:0:1",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		addr, ok := parseClientIP(raw)
		if !ok {
			// A rejected input must return the zero Addr so callers that
			// ignore ok never key on a half-parsed value.
			if addr.IsValid() {
				t.Fatalf("parseClientIP(%q) returned ok=false but a valid addr %v", raw, addr)
			}
			return
		}
		if !addr.IsValid() {
			t.Fatalf("parseClientIP(%q) returned ok=true but an invalid addr", raw)
		}
		if addr.Is4In6() {
			t.Fatalf("parseClientIP(%q) leaked an IPv4-mapped IPv6 addr %v; it must be unmapped so one client cannot occupy two rate-limit buckets", raw, addr)
		}
		if addr.Zone() != "" {
			t.Fatalf("parseClientIP(%q) kept an IPv6 zone %q; a client IP must not carry a zone or one address could mint several rate-limit buckets", raw, addr.Zone())
		}
		// The rate-limit key is addr.String(); re-parsing that key must be a
		// fixed point, or the same client could drift between buckets.
		again, ok := parseClientIP(addr.String())
		if !ok || again != addr {
			t.Fatalf("parseClientIP not idempotent on its own String(): %q -> %v -> (%v, %v)", raw, addr, again, ok)
		}
	})
}

// FuzzForwardedClientIP checks that splitting an arbitrary X-Forwarded-For
// header never panics and that whatever address it selects is one parseClientIP
// itself would have accepted from some comma-separated element — the header
// parser must not invent or mangle an address.
func FuzzForwardedClientIP(f *testing.F) {
	for _, seed := range []string{
		"", ",", " , , ", "203.0.113.10", "203.0.113.10, 70.41.3.18, 150.172.238.178",
		"unknown, 203.0.113.10", "  , 2001:db8::1 ,", "junk,also junk",
		"::ffff:203.0.113.10, 1.2.3.4", "[2001:db8::1]:443, 9.9.9.9",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, header string) {
		addr, ok := forwardedClientIP(header)
		if !ok {
			if addr.IsValid() {
				t.Fatalf("forwardedClientIP(%q) returned ok=false but a valid addr %v", header, addr)
			}
			return
		}
		if !addr.IsValid() || addr.Is4In6() {
			t.Fatalf("forwardedClientIP(%q) selected a non-canonical addr %v", header, addr)
		}
		// The selected address must correspond to one of the header's own
		// comma-separated tokens, parsed the same way parseClientIP would.
		matched := false
		for _, part := range strings.Split(header, ",") {
			if candidate, candidateOK := parseClientIP(part); candidateOK && candidate == addr {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("forwardedClientIP(%q) returned %v, which no element parses to", header, addr)
		}
		// It must specifically be the FIRST parseable token (leftmost), the
		// documented selection rule.
		var firstParseable netip.Addr
		found := false
		for _, part := range strings.Split(header, ",") {
			if candidate, candidateOK := parseClientIP(part); candidateOK {
				firstParseable = candidate
				found = true
				break
			}
		}
		if !found || firstParseable != addr {
			t.Fatalf("forwardedClientIP(%q) did not select the leftmost parseable token: got %v, leftmost %v", header, addr, firstParseable)
		}
	})
}
