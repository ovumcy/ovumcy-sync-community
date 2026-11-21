package main

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/config"
)

func TestNewHTTPServerSetsTimeoutsAndHeaderCap(t *testing.T) {
	cfg := config.Config{BindAddr: ":8080", HTTPReadTimeout: 7 * time.Second, HTTPWriteTimeout: 9 * time.Second}
	server := newHTTPServer(cfg, http.NotFoundHandler())
	if server.Addr != ":8080" || server.ReadTimeout != 7*time.Second || server.WriteTimeout != 9*time.Second {
		t.Fatalf("server = addr %q read %v write %v", server.Addr, server.ReadTimeout, server.WriteTimeout)
	}
	if server.ReadHeaderTimeout != 5*time.Second || server.IdleTimeout != 60*time.Second {
		t.Fatalf("server = read-header %v idle %v", server.ReadHeaderTimeout, server.IdleTimeout)
	}
	if server.MaxHeaderBytes != 64<<10 {
		t.Fatalf("MaxHeaderBytes = %d, want %d", server.MaxHeaderBytes, 64<<10)
	}
}

func TestNewHTTPServerRefusesAnOversizedHeaderBlock(t *testing.T) {
	server := newHTTPServer(config.Config{}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Shutdown(context.Background()) })

	url := "http://" + listener.Addr().String() + "/"
	for _, c := range []struct {
		padding int
		want    int
	}{
		{padding: 32 << 10, want: http.StatusNoContent},
		// net/http reads up to MaxHeaderBytes plus 4 KiB of slack before refusing.
		{padding: 80 << 10, want: http.StatusRequestHeaderFieldsTooLarge},
	} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Padding", strings.Repeat("a", c.padding))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("padding %d: %v", c.padding, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("padding %d: status %d, want %d", c.padding, resp.StatusCode, c.want)
		}
	}
}
