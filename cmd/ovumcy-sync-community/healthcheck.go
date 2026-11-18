package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultHealthcheckHost    = "127.0.0.1"
	defaultHealthcheckPort    = "8080"
	defaultHealthcheckTimeout = 5 * time.Second
	healthcheckPath           = "/readyz"
)

// runHealthcheck probes the local server's /readyz endpoint and returns nil
// on a 2xx response. It backs the container HEALTHCHECK so the distroless
// runtime image does not need curl or wget.
//
// It deliberately probes readiness rather than /healthz. /healthz is a
// constant answer that consults nothing, so a container whose database has
// become unusable — deleted, corrupt, permission-locked, or migrated past
// this build by a newer image — reported healthy to the runtime forever. The
// container health signal is worth having only if it can go red for the most
// likely failure, and readiness is the probe that touches the store.
// /healthz stays as the constant liveness answer for a proxy or uptime check
// that wants to know the HTTP loop is alive and nothing more.
func runHealthcheck(bindAddr string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultHealthcheckTimeout
	}
	host, port := healthcheckTarget(bindAddr)
	// url.URL escapes an IPv6 zone ("fe80::1%eth0") that a concatenated string would leave unparseable.
	target := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(host, port),
		Path:   healthcheckPath,
	}
	// No proxy: HTTP_PROXY exempts loopback only, and the probe must reach the bound address directly.
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
	resp, err := client.Get(target.String())
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("healthcheck: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// healthcheckTarget returns the host and port the server listens on per
// BIND_ADDR, from one parse. A server bound to one address does not answer on
// loopback, so that address is probed. Every-interface binds probe the
// loopback of their own family: "[::]:8080" listens IPv6-only where
// net.ipv6.bindv6only=1, so 127.0.0.1 would be refused there, while ::1
// answers either way; ":8080" and "0.0.0.0:8080" probe 127.0.0.1. An unset
// or unparseable BIND_ADDR falls back to the image default.
func healthcheckTarget(bindAddr string) (host string, port string) {
	host, port, err := net.SplitHostPort(strings.TrimSpace(bindAddr))
	if err != nil {
		return defaultHealthcheckHost, defaultHealthcheckPort
	}
	if port = strings.TrimSpace(port); port == "" {
		port = defaultHealthcheckPort
	}
	host = strings.TrimSpace(host)
	ip := net.ParseIP(host)
	switch {
	case host == "":
		host = defaultHealthcheckHost
	case ip != nil && ip.IsUnspecified() && ip.To4() == nil:
		host = net.IPv6loopback.String()
	case ip != nil && ip.IsUnspecified():
		host = defaultHealthcheckHost
	}
	return host, port
}
