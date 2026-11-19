package main

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthcheckTargetsFollowBindAddr(t *testing.T) {
	cases := map[string]string{
		"":                      defaultHealthcheckHost + " " + defaultHealthcheckPort,
		"   ":                   defaultHealthcheckHost + " " + defaultHealthcheckPort,
		"no-port":               defaultHealthcheckHost + " " + defaultHealthcheckPort,
		":":                     defaultHealthcheckHost + " " + defaultHealthcheckPort,
		":8080":                 defaultHealthcheckHost + " 8080",
		"0.0.0.0:9000":          defaultHealthcheckHost + " 9000",
		"[::]:8080":             defaultHealthcheckHost + ",::1 8080",
		"[::ffff:0.0.0.0]:8080": defaultHealthcheckHost + " 8080",
		"127.0.0.1:8443":        "127.0.0.1 8443",
		"10.1.2.3:8080":         "10.1.2.3 8080",
		"[fd00::5]:8080":        "fd00::5 8080",
		"sync.local:8080":       "sync.local 8080",
		" 10.1.2.3:8080  ":      "10.1.2.3 8080",
	}
	for bindAddr, want := range cases {
		hosts, port := healthcheckTargets(bindAddr)
		if got := strings.Join(hosts, ",") + " " + port; got != want {
			t.Fatalf("healthcheckTargets(%q) = %q, want %q", bindAddr, got, want)
		}
	}
}

// TestRunHealthcheckProbesIPv6LoopbackForAnIPv6WildcardBind: under
// bindv6only=1 a "[::]" bind answers only on IPv6, so the probe must go to ::1.
func TestRunHealthcheckProbesIPv6LoopbackForAnIPv6WildcardBind(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	if err := runHealthcheck(net.JoinHostPort("::", port), time.Second); err != nil {
		t.Fatalf("expected the [::] bind to be probed on ::1, got %v", err)
	}
}

// TestRunHealthcheckProbesTheBoundAddress pins that a server bound to one
// non-loopback address is probed there, not on 127.0.0.1 where it does not
// listen. The stand-in binds the IPv6 loopback, so a probe that still went
// to 127.0.0.1 would be refused.
func TestRunHealthcheckProbesTheBoundAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Listener = listener
	server.Start()
	defer server.Close()

	if err := runHealthcheck(listener.Addr().String(), time.Second); err != nil {
		t.Fatalf("expected the probe to reach the bound address, got %v", err)
	}
}

// A BIND_ADDR name need not be in ALLOWED_HOSTS; the probe sends a Host the
// server's host check always accepts.
func TestRunHealthcheckSendsLocalhostForANamedBindAddr(t *testing.T) {
	hosts := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())

	if err := runHealthcheck(net.JoinHostPort("localhost", port), time.Second); err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if gotHost := <-hosts; gotHost != "localhost" {
		t.Fatalf("Host = %q, want localhost", gotHost)
	}
	if got := healthcheckHostHeader("127.0.0.1"); got != "" {
		t.Fatalf("an IP target must keep its own Host, got %q", got)
	}
}

func TestRunHealthcheckAcceptsZonedIPv6Host(t *testing.T) {
	err := runHealthcheck("[fe80::1%nonexistent0]:1", 200*time.Millisecond)
	if err != nil && strings.Contains(err.Error(), "invalid URL") {
		t.Fatalf("zoned host produced an unparseable URL: %v", err)
	}
}

func TestRunHealthcheckSucceedsOnHealthyServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != healthcheckPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	bindAddr := strings.TrimPrefix(server.URL, "http://")
	if err := runHealthcheck(bindAddr, time.Second); err != nil {
		t.Fatalf("expected healthy probe to succeed, got %v", err)
	}
}

// TestRunHealthcheckProbesReadinessNotLiveness pins which endpoint backs the
// container HEALTHCHECK. /healthz answers from a constant and consults
// nothing, so a container whose database has become unusable answers it
// forever; only readiness touches the store. The stand-in server below
// answers 200 on /healthz and 503 on /readyz — exactly the split a wedged
// database produces — and the probe must fail.
func TestRunHealthcheckProbesReadinessNotLiveness(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	bindAddr := strings.TrimPrefix(server.URL, "http://")
	if err := runHealthcheck(bindAddr, time.Second); err == nil {
		t.Fatal("expected the container probe to fail while readiness is unavailable")
	}
}

func TestRunHealthcheckFailsOnNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	bindAddr := strings.TrimPrefix(server.URL, "http://")
	err := runHealthcheck(bindAddr, time.Second)
	if err == nil {
		t.Fatal("expected non-2xx probe to fail")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status code in probe error, got %v", err)
	}
}

// A server that accepts and drops the connection is reachable but broken: the
// probe reports that failure instead of falling back to ::1.
func TestRunHealthcheckStopsOnAFailureAfterTheDial(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())

	err = runHealthcheck(net.JoinHostPort("::", port), time.Second)
	if err == nil {
		t.Fatal("expected a dropped connection to fail the probe")
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		t.Fatalf("expected the 127.0.0.1 failure, got the ::1 dial error %v", err)
	}
}

func TestRunHealthcheckFailsOnUnreachableServer(t *testing.T) {
	if err := runHealthcheck("127.0.0.1:1", 200*time.Millisecond); err == nil {
		t.Fatal("expected probe against unreachable port to fail")
	}
}
