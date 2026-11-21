package config

import (
	"strings"
	"testing"
	"time"
)

func validBase() Config {
	return Config{
		BindAddr:                 ":8080",
		DBPath:                   "./data.sqlite",
		SessionTTL:               time.Hour,
		MaxDevices:               1,
		MaxBlobBytes:             1,
		AuthRateLimitCount:       1,
		AuthRateLimitWindow:      time.Minute,
		SyncRateLimitCount:       1,
		SyncRateLimitWindow:      time.Minute,
		LapsedAccountGracePeriod: MinLapsedAccountGracePeriod,
	}
}

func TestValidateAllowedOrigins(t *testing.T) {
	for _, ok := range []string{
		"https://app.example.com",
		"http://localhost:3000",
		"https://app.example.com:8443",
		"http://[::1]:8080",
	} {
		cfg := validBase()
		cfg.AllowedOrigins = []string{ok}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("origin %q must pass, got %v", ok, err)
		}
	}
	for _, bad := range []string{
		"null", "*", "https://*.example.com", "https://app.example.com/",
		"https://app.example.com/path", "https://app.example.com?x=1",
		"https://app.example.com#f", "https://user@app.example.com",
		"ftp://app.example.com", "app.example.com", "https://", "http://:80",
		"https://app.example.com:", "https://app.example.com:99999",
		"https://app.example.com:80a", "https:// app.example.com",
		"https://App.example.com", "http://app.example.com:80", "https://app.example.com:443",
		"https://app.example.com:0443", "HTTPS://app.example.com",
	} {
		cfg := validBase()
		cfg.AllowedOrigins = []string{"https://ok.example.com", bad}
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "ALLOWED_ORIGINS entry") {
			t.Fatalf("origin %q must be refused with a named error, got %v", bad, err)
		}
	}
}

func TestValidateRefusesSharedBridgeAndMetricsToken(t *testing.T) {
	shared := strings.Repeat("s", 40)
	cfg := validBase()
	cfg.MetricsEnabled = true
	cfg.ManagedBridgeToken = shared
	cfg.MetricsBearerToken = " " + shared + "\n"
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must be different values") {
		t.Fatalf("a shared token must be refused, got %v", err)
	}
	if strings.Contains(err.Error(), shared) {
		t.Fatal("the error must not echo the token")
	}

	cfg.MetricsBearerToken = strings.Repeat("t", 40)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("distinct tokens must pass, got %v", err)
	}
}

func TestValidateRefusesAnAllZeroFieldKey(t *testing.T) {
	cfg := validBase()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("no key must validate (TOTP off), got %v", err)
	}
	for _, size := range []int{32, 48} {
		cfg.FieldEncryptionKey = make([]byte, size)
		err := cfg.Validate()
		if err == nil || !strings.Contains(err.Error(), "FIELD_ENCRYPTION_KEY must not be all zero bytes") {
			t.Fatalf("a %d-byte all-zero key must be refused, got %v", size, err)
		}
		if msg := err.Error(); strings.Contains(msg, "00") || strings.Contains(msg, "0 0") || strings.Contains(msg, "\x00") {
			t.Fatal("the error must not quote the key")
		}
		cfg.FieldEncryptionKey[size-1] = 1
		if err := cfg.Validate(); err != nil {
			t.Fatalf("a %d-byte key with one non-zero byte must validate, got %v", size, err)
		}
	}
}
