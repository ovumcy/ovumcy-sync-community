package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newClientIPTestRequest(remoteAddr string, headers http.Header) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	request.RemoteAddr = remoteAddr
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	return request
}

func TestClientIPIgnoresXRealIPFromTrustedProxy(t *testing.T) {
	server := &Server{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"172.30.99.0/24"})}

	cases := map[string]http.Header{
		"no forwarded header": {"X-Real-Ip": {"203.0.113.77"}},
		// A NAT gateway inside the trusted range: every hop is trusted, so
		// nothing vouches for the client-supplied X-Real-IP.
		"every forwarded hop trusted": {
			"X-Forwarded-For": {"172.30.99.1"},
			"X-Real-Ip":       {"203.0.113.77"},
		},
	}
	for name, headers := range cases {
		t.Run(name, func(t *testing.T) {
			got := server.clientIPForRateLimit(newClientIPTestRequest("172.30.99.10:4000", headers))
			if got != "172.30.99.10" {
				t.Fatalf("expected the direct peer 172.30.99.10, got %q", got)
			}
		})
	}
}

func TestClientIPConsidersEveryForwardedForHeaderLine(t *testing.T) {
	server := &Server{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"10.0.0.0/24"})}

	// The client sends its own X-Forwarded-For line; the proxy appends the
	// real peer as a second line instead of extending the first.
	request := newClientIPTestRequest("10.0.0.2:4000", http.Header{
		"X-Forwarded-For": {"198.51.100.1", "203.0.113.10"},
	})
	if got := server.clientIPForRateLimit(request); got != "203.0.113.10" {
		t.Fatalf("expected the proxy-appended 203.0.113.10, got %q", got)
	}
}

func TestClientIPStopsAtUnparseableForwardedHop(t *testing.T) {
	server := &Server{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"10.0.0.0/24"})}

	// The proxy recorded its peer as "unknown"; the address left of it is the
	// client's own claim and must not become the key.
	request := newClientIPTestRequest("10.0.0.2:4000", http.Header{
		"X-Forwarded-For": {"198.51.100.1, unknown"},
	})
	if got := server.clientIPForRateLimit(request); got != "10.0.0.2" {
		t.Fatalf("expected the direct peer 10.0.0.2, got %q", got)
	}
}

func TestClientIPMatchesIPv4MappedTrustedEntry(t *testing.T) {
	server := &Server{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"::ffff:10.0.0.0/120"})}

	request := newClientIPTestRequest("10.0.0.2:4000", http.Header{
		"X-Forwarded-For": {"203.0.113.10"},
	})
	if got := server.clientIPForRateLimit(request); got != "203.0.113.10" {
		t.Fatalf("expected the mapped entry to trust 10.0.0.2 and key on 203.0.113.10, got %q", got)
	}
}

func TestClientIPKeysIPv6ByNetwork64(t *testing.T) {
	server := &Server{trustedProxyCIDRs: parseTrustedProxyCIDRs([]string{"10.0.0.0/24"})}

	first := server.clientIPForRateLimit(newClientIPTestRequest("[2001:db8:1:2::1]:4000", nil))
	second := server.clientIPForRateLimit(newClientIPTestRequest("[2001:db8:1:2:ffff::9]:4000", nil))
	if first != "2001:db8:1:2::/64" || first != second {
		t.Fatalf("expected one /64 bucket for one subscriber, got %q and %q", first, second)
	}

	other := server.clientIPForRateLimit(newClientIPTestRequest("[2001:db8:1:3::1]:4000", nil))
	if other == first {
		t.Fatalf("expected a neighbouring /64 to get its own bucket, got %q", other)
	}

	forwarded := server.clientIPForRateLimit(newClientIPTestRequest("10.0.0.2:4000", http.Header{
		"X-Forwarded-For": {"2001:db8:1:2::abcd"},
	}))
	if forwarded != first {
		t.Fatalf("expected a forwarded IPv6 client to key by its /64, got %q", forwarded)
	}

	if got := server.clientIPForRateLimit(newClientIPTestRequest("[::ffff:203.0.113.5]:4000", nil)); got != "203.0.113.5" {
		t.Fatalf("expected an IPv4-mapped peer to key as plain IPv4, got %q", got)
	}
}
