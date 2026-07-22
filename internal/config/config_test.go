package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "empty bind addr",
			cfg: Config{
				DBPath:              "./data.sqlite",
				SessionTTL:          time.Hour,
				MaxDevices:          1,
				MaxBlobBytes:        1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "BIND_ADDR",
		},
		{
			name: "empty db path",
			cfg: Config{
				BindAddr:            ":8080",
				SessionTTL:          time.Hour,
				MaxDevices:          1,
				MaxBlobBytes:        1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "DB_PATH",
		},
		{
			name: "non-positive session ttl",
			cfg: Config{
				BindAddr:            ":8080",
				DBPath:              "./data.sqlite",
				MaxDevices:          1,
				MaxBlobBytes:        1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "SESSION_TTL",
		},
		{
			name: "non-positive max devices",
			cfg: Config{
				BindAddr:            ":8080",
				DBPath:              "./data.sqlite",
				SessionTTL:          time.Hour,
				MaxBlobBytes:        1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "MAX_DEVICES",
		},
		{
			name: "non-positive max blob bytes",
			cfg: Config{
				BindAddr:            ":8080",
				DBPath:              "./data.sqlite",
				SessionTTL:          time.Hour,
				MaxDevices:          1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "MAX_BLOB_BYTES",
		},
		{
			name: "non-positive auth rate limit count",
			cfg: Config{
				BindAddr:            ":8080",
				DBPath:              "./data.sqlite",
				SessionTTL:          time.Hour,
				MaxDevices:          1,
				MaxBlobBytes:        1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "AUTH_RATE_LIMIT_COUNT",
		},
		{
			name: "non-positive auth rate limit window",
			cfg: Config{
				BindAddr:           ":8080",
				DBPath:             "./data.sqlite",
				SessionTTL:         time.Hour,
				MaxDevices:         1,
				MaxBlobBytes:       1,
				AuthRateLimitCount: 1,
			},
			want: "AUTH_RATE_LIMIT_WINDOW",
		},
		{
			name: "metrics token without metrics enabled",
			cfg: Config{
				BindAddr:            ":8080",
				DBPath:              "./data.sqlite",
				SessionTTL:          time.Hour,
				MaxDevices:          1,
				MaxBlobBytes:        1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
				MetricsBearerToken:  "secret",
			},
			want: "METRICS_BEARER_TOKEN",
		},
		{
			name: "non-positive lapsed account grace period",
			cfg: Config{
				BindAddr:            ":8080",
				DBPath:              "./data.sqlite",
				SessionTTL:          time.Hour,
				MaxDevices:          1,
				MaxBlobBytes:        1,
				AuthRateLimitCount:  1,
				AuthRateLimitWindow: time.Minute,
			},
			want: "LAPSED_ACCOUNT_GRACE_PERIOD",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected validation error containing %q, got %v", test.want, err)
			}
		})
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	cfg := Config{
		BindAddr:                 ":8080",
		DBPath:                   "./data.sqlite",
		SessionTTL:               time.Hour,
		MaxDevices:               5,
		MaxBlobBytes:             16 << 20,
		AuthRateLimitCount:       10,
		AuthRateLimitWindow:      time.Minute,
		LapsedAccountGracePeriod: 60 * 24 * time.Hour,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestEnvHelperParsers(t *testing.T) {
	t.Setenv("STRING_ENV", "configured")
	t.Setenv("BOOL_ENV", "true")
	t.Setenv("DURATION_ENV", "2h")
	t.Setenv("INT_ENV", "42")
	t.Setenv("CSV_ENV", " https://a.example , ,https://b.example ")

	if got := stringFromEnv("STRING_ENV", "fallback"); got != "configured" {
		t.Fatalf("unexpected string env %q", got)
	}

	enabled, err := boolFromEnv("BOOL_ENV", false)
	if err != nil || !enabled {
		t.Fatalf("unexpected bool env result %t, err=%v", enabled, err)
	}

	duration, err := durationFromEnv("DURATION_ENV", time.Minute)
	if err != nil || duration != 2*time.Hour {
		t.Fatalf("unexpected duration env result %s, err=%v", duration, err)
	}

	count, err := intFromEnv("INT_ENV", 1)
	if err != nil || count != 42 {
		t.Fatalf("unexpected int env result %d, err=%v", count, err)
	}

	origins := csvListFromEnv("CSV_ENV")
	if len(origins) != 2 || origins[0] != "https://a.example" || origins[1] != "https://b.example" {
		t.Fatalf("unexpected csv env result %#v", origins)
	}

	prefix, err := ParseTrustedProxyCIDR("127.0.0.1")
	if err != nil || prefix.String() != "127.0.0.1/32" {
		t.Fatalf("unexpected trusted proxy ip parse result %q, err=%v", prefix.String(), err)
	}

	prefix, err = ParseTrustedProxyCIDR("10.0.0.0/24")
	if err != nil || prefix.String() != "10.0.0.0/24" {
		t.Fatalf("unexpected trusted proxy cidr parse result %q, err=%v", prefix.String(), err)
	}
}

func TestEnvHelperParsersUseFallbacksAndRejectInvalidInput(t *testing.T) {
	t.Setenv("STRING_ENV", "")
	t.Setenv("BOOL_ENV", "")
	t.Setenv("DURATION_ENV", "")
	t.Setenv("INT_ENV", "")
	t.Setenv("CSV_ENV", " , ")

	if got := stringFromEnv("STRING_ENV", "fallback"); got != "fallback" {
		t.Fatalf("unexpected string fallback %q", got)
	}

	enabled, err := boolFromEnv("BOOL_ENV", true)
	if err != nil || !enabled {
		t.Fatalf("unexpected bool fallback result %t, err=%v", enabled, err)
	}

	duration, err := durationFromEnv("DURATION_ENV", time.Minute)
	if err != nil || duration != time.Minute {
		t.Fatalf("unexpected duration fallback result %s, err=%v", duration, err)
	}

	count, err := intFromEnv("INT_ENV", 7)
	if err != nil || count != 7 {
		t.Fatalf("unexpected int fallback result %d, err=%v", count, err)
	}

	if csvListFromEnv("CSV_ENV") != nil {
		t.Fatalf("expected empty csv env to return nil")
	}

	t.Setenv("DURATION_ENV", "nope")
	if _, err := durationFromEnv("DURATION_ENV", time.Minute); err == nil || !strings.Contains(err.Error(), "DURATION_ENV") {
		t.Fatalf("expected duration parse error, got %v", err)
	}

	t.Setenv("BOOL_ENV", "nope")
	if _, err := boolFromEnv("BOOL_ENV", true); err == nil || !strings.Contains(err.Error(), "BOOL_ENV") {
		t.Fatalf("expected bool parse error, got %v", err)
	}

	t.Setenv("INT_ENV", "0")
	if _, err := intFromEnv("INT_ENV", 7); err == nil || !strings.Contains(err.Error(), "INT_ENV") {
		t.Fatalf("expected int validation error, got %v", err)
	}

	if _, err := ParseTrustedProxyCIDR("invalid-cidr"); err == nil {
		t.Fatal("expected trusted proxy parser to reject invalid input")
	}
}

// TestParseTrustedProxyCIDRRejectsEmptyValue exercises the empty-input guard
// directly (an env entry that collapsed to "" after trimming, e.g. a stray
// comma in TRUSTED_PROXY_CIDRS).
func TestParseTrustedProxyCIDRRejectsEmptyValue(t *testing.T) {
	if _, err := ParseTrustedProxyCIDR("   "); err == nil {
		t.Fatal("expected an empty/whitespace-only value to be rejected")
	}
}

// TestParseTrustedProxyCIDRRejectsMalformedCIDRSuffix exercises the
// netip.ParsePrefix error branch specifically: a value containing "/" takes
// the CIDR parse path, distinct from the bare-address path already covered
// by TestEnvHelperParsersUseFallbacksAndRejectInvalidInput's "invalid-cidr"
// case (which has no "/" and so exercises netip.ParseAddr instead).
func TestParseTrustedProxyCIDRRejectsMalformedCIDRSuffix(t *testing.T) {
	if _, err := ParseTrustedProxyCIDR("10.0.0.0/999"); err == nil {
		t.Fatal("expected an out-of-range CIDR suffix to be rejected")
	}
}

// TestParseTrustedProxyCIDRAcceptsBareIPv6Address exercises the IPv6 branch
// of the bare-address path (PrefixFrom(addr, 128)): every existing test only
// exercises a bare IPv4 address (-> /32), so the IPv6 /128 branch was never
// reached.
func TestParseTrustedProxyCIDRAcceptsBareIPv6Address(t *testing.T) {
	prefix, err := ParseTrustedProxyCIDR("::1")
	if err != nil {
		t.Fatalf("unexpected error parsing a bare IPv6 address: %v", err)
	}
	if prefix.String() != "::1/128" {
		t.Fatalf("expected ::1/128, got %q", prefix.String())
	}
}

// TestLoadAcceptsADisabledLapsedAccountSweep pins the rollback lever. Every
// other duration in this config is rejected when non-positive, so the obvious
// "consistency" cleanup is to validate this one the same way — which would
// silently remove the only way to turn the in-process purge off without
// shipping a new image. The zero is the feature.
func TestLoadAcceptsADisabledLapsedAccountSweep(t *testing.T) {
	t.Setenv("LAPSED_ACCOUNT_SWEEP_INTERVAL", "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load rejected a disabled sweep interval: %v", err)
	}
	if cfg.LapsedAccountSweepInterval != 0 {
		t.Fatalf("expected the interval to stay 0, got %v", cfg.LapsedAccountSweepInterval)
	}

	// The grace period keeps its opposite contract: it is a retention promise,
	// not a switch, and zero would mean "erase immediately".
	t.Setenv("LAPSED_ACCOUNT_GRACE_PERIOD", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected a zero grace period to be rejected")
	}
}

// TestLoadDefaultsTheLapsedAccountSweep pins the shipped defaults: the sweep is
// on out of the box, because a retention window nobody enforces is the failure
// this config exists to prevent.
func TestLoadDefaultsTheLapsedAccountSweep(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LapsedAccountSweepInterval != 24*time.Hour {
		t.Fatalf("expected a 24h default sweep interval, got %v", cfg.LapsedAccountSweepInterval)
	}
	if cfg.LapsedAccountSweepLimit != 0 {
		t.Fatalf("expected the limit to default to 0 (store default), got %d", cfg.LapsedAccountSweepLimit)
	}
}

// TestLoadRejectsUnparsableLapsedAccountSweepSettings covers the two parse
// branches the sweep settings add. A typo in either must stop the server at
// boot rather than silently fall back to a default: an operator who wrote
// "24" instead of "24h" to disable the purge, or "0" where they meant off,
// needs to be told — a server that quietly ran the default interval after a
// rejected value would delete data the operator believed was retained.
func TestLoadRejectsUnparsableLapsedAccountSweepSettings(t *testing.T) {
	t.Run("interval", func(t *testing.T) {
		t.Setenv("LAPSED_ACCOUNT_SWEEP_INTERVAL", "every-day")

		if _, err := Load(); err == nil {
			t.Fatal("expected an unparsable sweep interval to be rejected")
		} else if !strings.Contains(err.Error(), "LAPSED_ACCOUNT_SWEEP_INTERVAL") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})

	t.Run("limit", func(t *testing.T) {
		t.Setenv("LAPSED_ACCOUNT_SWEEP_LIMIT", "many")

		if _, err := Load(); err == nil {
			t.Fatal("expected an unparsable sweep limit to be rejected")
		} else if !strings.Contains(err.Error(), "LAPSED_ACCOUNT_SWEEP_LIMIT") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})

	t.Run("limit accepts an explicit zero as the store default", func(t *testing.T) {
		t.Setenv("LAPSED_ACCOUNT_SWEEP_LIMIT", "0")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected an explicit 0 sweep limit to load, got %v", err)
		}
		if cfg.LapsedAccountSweepLimit != 0 {
			t.Fatalf("expected sweep limit 0, got %d", cfg.LapsedAccountSweepLimit)
		}
	})

	t.Run("limit rejects negatives", func(t *testing.T) {
		t.Setenv("LAPSED_ACCOUNT_SWEEP_LIMIT", "-3")

		if _, err := Load(); err == nil {
			t.Fatal("expected a negative sweep limit to be rejected")
		} else if !strings.Contains(err.Error(), "LAPSED_ACCOUNT_SWEEP_LIMIT") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})
}

func TestLoadExpiredRowsSweepConfig(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load returned error: %v", err)
		}
		if cfg.ExpiredRowsSweepInterval != 24*time.Hour {
			t.Fatalf("expected default sweep interval 24h, got %v", cfg.ExpiredRowsSweepInterval)
		}
		if cfg.ExpiredRowsSweepLimit != 0 {
			t.Fatalf("expected default sweep limit 0 (store default), got %d", cfg.ExpiredRowsSweepLimit)
		}
	})

	t.Run("zero interval is the documented off switch", func(t *testing.T) {
		t.Setenv("EXPIRED_ROWS_SWEEP_INTERVAL", "0s")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("expected a zero interval to load (sweep disabled), got %v", err)
		}
		if cfg.ExpiredRowsSweepInterval != 0 {
			t.Fatalf("expected interval 0, got %v", cfg.ExpiredRowsSweepInterval)
		}
	})

	t.Run("rejects an unparsable interval", func(t *testing.T) {
		t.Setenv("EXPIRED_ROWS_SWEEP_INTERVAL", "sometimes")

		if _, err := Load(); err == nil {
			t.Fatal("expected an unparsable sweep interval to be rejected")
		} else if !strings.Contains(err.Error(), "EXPIRED_ROWS_SWEEP_INTERVAL") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})

	t.Run("rejects a negative limit", func(t *testing.T) {
		t.Setenv("EXPIRED_ROWS_SWEEP_LIMIT", "-1")

		if _, err := Load(); err == nil {
			t.Fatal("expected a negative sweep limit to be rejected")
		} else if !strings.Contains(err.Error(), "EXPIRED_ROWS_SWEEP_LIMIT") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})
}

func TestLoadHTTPTimeouts(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load returned error: %v", err)
		}
		if cfg.HTTPReadTimeout != 10*time.Second {
			t.Fatalf("expected default HTTP read timeout 10s, got %v", cfg.HTTPReadTimeout)
		}
		if cfg.HTTPWriteTimeout != 15*time.Second {
			t.Fatalf("expected default HTTP write timeout 15s, got %v", cfg.HTTPWriteTimeout)
		}
	})

	t.Run("override", func(t *testing.T) {
		t.Setenv("HTTP_READ_TIMEOUT", "2m")
		t.Setenv("HTTP_WRITE_TIMEOUT", "3m")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load returned error: %v", err)
		}
		if cfg.HTTPReadTimeout != 2*time.Minute || cfg.HTTPWriteTimeout != 3*time.Minute {
			t.Fatalf(
				"expected the overridden timeouts, got %v / %v",
				cfg.HTTPReadTimeout,
				cfg.HTTPWriteTimeout,
			)
		}
	})

	t.Run("rejects zero", func(t *testing.T) {
		t.Setenv("HTTP_READ_TIMEOUT", "0s")

		if _, err := Load(); err == nil {
			t.Fatal("expected a zero read timeout to be rejected")
		} else if !strings.Contains(err.Error(), "HTTP_READ_TIMEOUT") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})

	t.Run("rejects negative", func(t *testing.T) {
		t.Setenv("HTTP_WRITE_TIMEOUT", "-5s")

		if _, err := Load(); err == nil {
			t.Fatal("expected a negative write timeout to be rejected")
		} else if !strings.Contains(err.Error(), "HTTP_WRITE_TIMEOUT") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})

	t.Run("rejects an unparsable duration", func(t *testing.T) {
		t.Setenv("HTTP_WRITE_TIMEOUT", "soon")

		if _, err := Load(); err == nil {
			t.Fatal("expected an unparsable write timeout to be rejected")
		} else if !strings.Contains(err.Error(), "HTTP_WRITE_TIMEOUT") {
			t.Fatalf("expected the offending variable to be named, got %v", err)
		}
	})
}
