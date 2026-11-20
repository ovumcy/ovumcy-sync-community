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

func TestWarningsFlagAnAllZeroFieldKey(t *testing.T) {
	cfg := validBase()
	if w := cfg.Warnings(); len(w) != 0 {
		t.Fatalf("no key must not warn, got %v", w)
	}
	cfg.FieldEncryptionKey = make([]byte, 32)
	w := cfg.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "FIELD_ENCRYPTION_KEY is all zero bytes") {
		t.Fatalf("an all-zero key must warn once, got %v", w)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("an all-zero key must still validate, got %v", err)
	}
	cfg.FieldEncryptionKey[31] = 1
	if w := cfg.Warnings(); len(w) != 0 {
		t.Fatalf("a non-zero key must not warn, got %v", w)
	}
}
