package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	defaultHealthcheckPort    = "8080"
	defaultHealthcheckTimeout = 5 * time.Second
	healthcheckPath           = "/healthz"
)

// runHealthcheck probes the local server's /healthz endpoint and returns nil
// on a 2xx response. It backs the container HEALTHCHECK so the distroless
// runtime image does not need curl or wget.
func runHealthcheck(bindAddr string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultHealthcheckTimeout
	}
	url := fmt.Sprintf("http://127.0.0.1:%s%s", healthcheckPort(bindAddr), healthcheckPath)
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
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
