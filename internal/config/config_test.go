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
		BindAddr:            ":8080",
		DBPath:              "./data.sqlite",
		SessionTTL:          time.Hour,
		MaxDevices:          5,
		MaxBlobBytes:        16 << 20,
		AuthRateLimitCount:  10,
		AuthRateLimitWindow: time.Minute,
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}
}

func TestEnvHelperParsers(t *testing.T) {
	t.Setenv("STRING_ENV", "configured")
	t.Setenv("DURATION_ENV", "2h")
	t.Setenv("INT_ENV", "42")
	t.Setenv("CSV_ENV", " https://a.example , ,https://b.example ")

	if got := stringFromEnv("STRING_ENV", "fallback"); got != "configured" {
		t.Fatalf("unexpected string env %q", got)
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
}

func TestEnvHelperParsersUseFallbacksAndRejectInvalidInput(t *testing.T) {
	t.Setenv("STRING_ENV", "")
	t.Setenv("DURATION_ENV", "")
	t.Setenv("INT_ENV", "")
	t.Setenv("CSV_ENV", " , ")

	if got := stringFromEnv("STRING_ENV", "fallback"); got != "fallback" {
		t.Fatalf("unexpected string fallback %q", got)
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

	t.Setenv("INT_ENV", "0")
	if _, err := intFromEnv("INT_ENV", 7); err == nil || !strings.Contains(err.Error(), "INT_ENV") {
		t.Fatalf("expected int validation error, got %v", err)
	}
}
