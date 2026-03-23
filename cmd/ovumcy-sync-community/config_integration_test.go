package main

import (
	"strings"
	"testing"
	"time"

	"github.com/ovumcy/ovumcy-sync-community/internal/config"
)

func TestConfigLoadReturnsDefaults(t *testing.T) {
	t.Setenv("BIND_ADDR", "")
	t.Setenv("DB_PATH", "")
	t.Setenv("SESSION_TTL", "")
	t.Setenv("MAX_DEVICES", "")
	t.Setenv("MAX_BLOB_BYTES", "")
	t.Setenv("AUTH_RATE_LIMIT_COUNT", "")
	t.Setenv("AUTH_RATE_LIMIT_WINDOW", "")
	t.Setenv("METRICS_ENABLED", "")
	t.Setenv("METRICS_BEARER_TOKEN", "")
	t.Setenv("MANAGED_BRIDGE_TOKEN", "")
	t.Setenv("ALLOWED_ORIGINS", "")
	t.Setenv("TRUSTED_PROXY_CIDRS", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.BindAddr != ":8080" {
		t.Fatalf("unexpected bind addr %q", cfg.BindAddr)
	}
	if cfg.DBPath != "./data/ovumcy-sync-community.sqlite" {
		t.Fatalf("unexpected db path %q", cfg.DBPath)
	}
	if cfg.SessionTTL != 720*time.Hour {
		t.Fatalf("unexpected session ttl %s", cfg.SessionTTL)
	}
	if cfg.MaxDevices != 5 {
		t.Fatalf("unexpected max devices %d", cfg.MaxDevices)
	}
	if cfg.MaxBlobBytes != 16<<20 {
		t.Fatalf("unexpected max blob bytes %d", cfg.MaxBlobBytes)
	}
	if cfg.AuthRateLimitCount != 10 {
		t.Fatalf("unexpected auth limit count %d", cfg.AuthRateLimitCount)
	}
	if cfg.AuthRateLimitWindow != time.Minute {
		t.Fatalf("unexpected auth limit window %s", cfg.AuthRateLimitWindow)
	}
	if cfg.MetricsEnabled {
		t.Fatal("expected metrics to be disabled by default")
	}
	if cfg.MetricsBearerToken != "" {
		t.Fatalf("expected empty metrics bearer token, got %q", cfg.MetricsBearerToken)
	}
	if cfg.TrustedProxyCIDRs != nil {
		t.Fatalf("expected empty trusted proxy cidrs, got %#v", cfg.TrustedProxyCIDRs)
	}
}

func TestConfigLoadRejectsInvalidValues(t *testing.T) {
	t.Setenv("MAX_BLOB_BYTES", "0")

	_, err := config.Load()
	if err == nil || !strings.Contains(err.Error(), "MAX_BLOB_BYTES must be positive") {
		t.Fatalf("expected max blob validation error, got %v", err)
	}

	t.Setenv("MAX_BLOB_BYTES", "")
	t.Setenv("AUTH_RATE_LIMIT_WINDOW", "0s")

	_, err = config.Load()
	if err == nil || !strings.Contains(err.Error(), "AUTH_RATE_LIMIT_WINDOW must be positive") {
		t.Fatalf("expected auth rate limit window validation error, got %v", err)
	}

	t.Setenv("AUTH_RATE_LIMIT_WINDOW", "")
	t.Setenv("METRICS_ENABLED", "true")
	t.Setenv("METRICS_BEARER_TOKEN", "")
	t.Setenv("TRUSTED_PROXY_CIDRS", "invalid")

	_, err = config.Load()
	if err == nil || !strings.Contains(err.Error(), "TRUSTED_PROXY_CIDRS") {
		t.Fatalf("expected trusted proxy validation error, got %v", err)
	}

	t.Setenv("TRUSTED_PROXY_CIDRS", "")
	t.Setenv("METRICS_ENABLED", "false")
	t.Setenv("METRICS_BEARER_TOKEN", "secret")

	_, err = config.Load()
	if err == nil || !strings.Contains(err.Error(), "METRICS_BEARER_TOKEN") {
		t.Fatalf("expected metrics bearer token validation error, got %v", err)
	}
}
