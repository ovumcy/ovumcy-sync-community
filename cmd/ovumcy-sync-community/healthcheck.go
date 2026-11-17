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
	// url.URL escapes an IPv6 zone ("fe80::1%eth0") that a concatenated string would leave unparseable.
	target := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(healthcheckHost(bindAddr), healthcheckPort(bindAddr)),
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

// healthcheckHost returns the host the server listens on per BIND_ADDR, or
// loopback when BIND_ADDR names every interface (":8080", "0.0.0.0:8080",
// "[::]:8080") or cannot be parsed. A server bound to one address does not
// answer on 127.0.0.1, so probing loopback there marks a working container
// unhealthy.
func healthcheckHost(bindAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(bindAddr))
	if err != nil {
		return defaultHealthcheckHost
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return defaultHealthcheckHost
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		return defaultHealthcheckHost
	}
	return host
}

// healthcheckPort extracts the port from a BIND_ADDR value such as ":8080" or
// "0.0.0.0:8080", falling back to the image default when unset or malformed.
func healthcheckPort(bindAddr string) string {
	bindAddr = strings.TrimSpace(bindAddr)
	if bindAddr == "" {
		return defaultHealthcheckPort
	}
	_, port, err := net.SplitHostPort(bindAddr)
	if err != nil || strings.TrimSpace(port) == "" {
		return defaultHealthcheckPort
	}
	return port
}
