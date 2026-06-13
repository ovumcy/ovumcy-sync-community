package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHealthcheckPortFallsBackToDefault(t *testing.T) {
	for _, bindAddr := range []string{"", "   ", "no-port", ":"} {
		if got := healthcheckPort(bindAddr); got != defaultHealthcheckPort {
			t.Fatalf("healthcheckPort(%q) = %q, want %q", bindAddr, got, defaultHealthcheckPort)
		}
	}
}

func TestHealthcheckPortExtractsPort(t *testing.T) {
	cases := map[string]string{
		":8080":          "8080",
		"0.0.0.0:9000":   "9000",
		"127.0.0.1:8443": "8443",
	}
	for bindAddr, want := range cases {
		if got := healthcheckPort(bindAddr); got != want {
			t.Fatalf("healthcheckPort(%q) = %q, want %q", bindAddr, got, want)
		}
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

func TestRunHealthcheckFailsOnUnreachableServer(t *testing.T) {
	if err := runHealthcheck("127.0.0.1:1", 200*time.Millisecond); err == nil {
		t.Fatal("expected probe against unreachable port to fail")
	}
}
