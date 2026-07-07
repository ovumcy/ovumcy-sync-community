package config

import (
	"strings"
	"testing"
	"time"
)

// loadEnvVars lists every environment variable Load reads. Tests use it to
// reset the environment to a clean slate before applying only the overrides
// a given case cares about, so leftover state from an earlier subtest (or
// the developer's own shell) can never leak into Load's defaults.
var loadEnvVars = []string{
	"BIND_ADDR",
	"DB_PATH",
	"SESSION_TTL",
	"MAX_DEVICES",
	"MAX_BLOB_BYTES",
	"AUTH_RATE_LIMIT_COUNT",
	"AUTH_RATE_LIMIT_WINDOW",
	"MANAGED_BRIDGE_TOKEN",
	"METRICS_ENABLED",
	"METRICS_BEARER_TOKEN",
	"ALLOWED_ORIGINS",
	"TRUSTED_PROXY_CIDRS",
	"FIELD_ENCRYPTION_KEY",
	"TOTP_ISSUER",
}

// clearLoadEnv resets every Load-relevant environment variable to empty via
// t.Setenv, so Load observes only the overrides a test explicitly sets
// afterward. t.Setenv restores the prior value on test cleanup, so this is
// safe to call from every subtest without cross-test leakage.
func clearLoadEnv(t *testing.T) {
	t.Helper()
	for _, name := range loadEnvVars {
		t.Setenv(name, "")
	}
}

func TestLoadReturnsDefaultsWhenEnvironmentIsEmpty(t *testing.T) {
	clearLoadEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	want := Config{
		BindAddr:            ":8080",
		DBPath:              "./data/ovumcy-sync-community.sqlite",
		SessionTTL:          720 * time.Hour,
		MaxDevices:          5,
		MaxBlobBytes:        16 << 20,
		AuthRateLimitCount:  10,
		AuthRateLimitWindow: time.Minute,
		ManagedBridgeToken:  "",
		MetricsEnabled:      false,
		MetricsBearerToken:  "",
		AllowedOrigins:      nil,
		TrustedProxyCIDRs:   nil,
		FieldEncryptionKey:  nil,
		TOTPIssuer:          "ovumcy-sync-community",
	}

	if cfg.BindAddr != want.BindAddr {
		t.Errorf("BindAddr = %q, want %q", cfg.BindAddr, want.BindAddr)
	}
	if cfg.DBPath != want.DBPath {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, want.DBPath)
	}
	if cfg.SessionTTL != want.SessionTTL {
		t.Errorf("SessionTTL = %s, want %s", cfg.SessionTTL, want.SessionTTL)
	}
	if cfg.MaxDevices != want.MaxDevices {
		t.Errorf("MaxDevices = %d, want %d", cfg.MaxDevices, want.MaxDevices)
	}
	if cfg.MaxBlobBytes != want.MaxBlobBytes {
		t.Errorf("MaxBlobBytes = %d, want %d", cfg.MaxBlobBytes, want.MaxBlobBytes)
	}
	if cfg.AuthRateLimitCount != want.AuthRateLimitCount {
		t.Errorf("AuthRateLimitCount = %d, want %d", cfg.AuthRateLimitCount, want.AuthRateLimitCount)
	}
	if cfg.AuthRateLimitWindow != want.AuthRateLimitWindow {
		t.Errorf("AuthRateLimitWindow = %s, want %s", cfg.AuthRateLimitWindow, want.AuthRateLimitWindow)
	}
	if cfg.ManagedBridgeToken != want.ManagedBridgeToken {
		t.Errorf("ManagedBridgeToken = %q, want %q", cfg.ManagedBridgeToken, want.ManagedBridgeToken)
	}
	if cfg.MetricsEnabled != want.MetricsEnabled {
		t.Errorf("MetricsEnabled = %t, want %t", cfg.MetricsEnabled, want.MetricsEnabled)
	}
	if cfg.MetricsBearerToken != want.MetricsBearerToken {
		t.Errorf("MetricsBearerToken = %q, want %q", cfg.MetricsBearerToken, want.MetricsBearerToken)
	}
	if cfg.AllowedOrigins != nil {
		t.Errorf("AllowedOrigins = %#v, want nil", cfg.AllowedOrigins)
	}
	if cfg.TrustedProxyCIDRs != nil {
		t.Errorf("TrustedProxyCIDRs = %#v, want nil", cfg.TrustedProxyCIDRs)
	}
	if cfg.FieldEncryptionKey != nil {
		t.Errorf("FieldEncryptionKey = %#v, want nil", cfg.FieldEncryptionKey)
	}
	if cfg.TOTPIssuer != want.TOTPIssuer {
		t.Errorf("TOTPIssuer = %q, want %q", cfg.TOTPIssuer, want.TOTPIssuer)
	}
}

func TestLoadAppliesEveryEnvOverride(t *testing.T) {
	clearLoadEnv(t)

	// A hex string decoding to exactly 32 bytes (the minimum accepted
	// length): 64 repeated hex digits, obviously-fake and patterned rather
	// than a realistic-looking secret.
	fakeHexKey := strings.Repeat("ab", 32)

	t.Setenv("BIND_ADDR", "0.0.0.0:9090")
	t.Setenv("DB_PATH", "/data/custom.sqlite")
	t.Setenv("SESSION_TTL", "48h")
	t.Setenv("MAX_DEVICES", "3")
	t.Setenv("MAX_BLOB_BYTES", "1048576")
	t.Setenv("AUTH_RATE_LIMIT_COUNT", "20")
	t.Setenv("AUTH_RATE_LIMIT_WINDOW", "30s")
	t.Setenv("MANAGED_BRIDGE_TOKEN", "bridge-token-fixture")
	t.Setenv("METRICS_ENABLED", "true")
	t.Setenv("METRICS_BEARER_TOKEN", "metrics-token-fixture")
	t.Setenv("ALLOWED_ORIGINS", "https://a.example,https://b.example")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/24,127.0.0.1")
	t.Setenv("FIELD_ENCRYPTION_KEY", fakeHexKey)
	t.Setenv("TOTP_ISSUER", "custom-issuer")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.BindAddr != "0.0.0.0:9090" {
		t.Errorf("BindAddr = %q, want %q", cfg.BindAddr, "0.0.0.0:9090")
	}
	if cfg.DBPath != "/data/custom.sqlite" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "/data/custom.sqlite")
	}
	if cfg.SessionTTL != 48*time.Hour {
		t.Errorf("SessionTTL = %s, want %s", cfg.SessionTTL, 48*time.Hour)
	}
	if cfg.MaxDevices != 3 {
		t.Errorf("MaxDevices = %d, want 3", cfg.MaxDevices)
	}
	if cfg.MaxBlobBytes != 1048576 {
		t.Errorf("MaxBlobBytes = %d, want 1048576", cfg.MaxBlobBytes)
	}
	if cfg.AuthRateLimitCount != 20 {
		t.Errorf("AuthRateLimitCount = %d, want 20", cfg.AuthRateLimitCount)
	}
	if cfg.AuthRateLimitWindow != 30*time.Second {
		t.Errorf("AuthRateLimitWindow = %s, want %s", cfg.AuthRateLimitWindow, 30*time.Second)
	}
	if cfg.ManagedBridgeToken != "bridge-token-fixture" {
		t.Errorf("ManagedBridgeToken = %q, want %q", cfg.ManagedBridgeToken, "bridge-token-fixture")
	}
	if !cfg.MetricsEnabled {
		t.Error("MetricsEnabled = false, want true")
	}
	if cfg.MetricsBearerToken != "metrics-token-fixture" {
		t.Errorf("MetricsBearerToken = %q, want %q", cfg.MetricsBearerToken, "metrics-token-fixture")
	}
	if len(cfg.AllowedOrigins) != 2 || cfg.AllowedOrigins[0] != "https://a.example" || cfg.AllowedOrigins[1] != "https://b.example" {
		t.Errorf("AllowedOrigins = %#v, want [https://a.example https://b.example]", cfg.AllowedOrigins)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 || cfg.TrustedProxyCIDRs[0] != "10.0.0.0/24" || cfg.TrustedProxyCIDRs[1] != "127.0.0.1" {
		t.Errorf("TrustedProxyCIDRs = %#v, want [10.0.0.0/24 127.0.0.1]", cfg.TrustedProxyCIDRs)
	}
	if len(cfg.FieldEncryptionKey) != 32 {
		t.Errorf("len(FieldEncryptionKey) = %d, want 32", len(cfg.FieldEncryptionKey))
	}
	if cfg.TOTPIssuer != "custom-issuer" {
		t.Errorf("TOTPIssuer = %q, want %q", cfg.TOTPIssuer, "custom-issuer")
	}
}

// TestLoadSurfacesEveryValidationAndParseError exercises every error return
// path reachable through Load: each of the parse-then-validate helpers it
// calls in sequence, plus the Validate() call at the end. One misconfigured
// variable per case, everything else left at its valid default.
func TestLoadSurfacesEveryValidationAndParseError(t *testing.T) {
	tests := []struct {
		name    string
		envName string
		envValu string
		wantErr string
	}{
		{
			name:    "malformed session ttl duration",
			envName: "SESSION_TTL",
			envValu: "not-a-duration",
			wantErr: "SESSION_TTL",
		},
		{
			name:    "malformed max devices int",
			envName: "MAX_DEVICES",
			envValu: "not-an-int",
			wantErr: "MAX_DEVICES",
		},
		{
			name:    "non-positive max devices int",
			envName: "MAX_DEVICES",
			envValu: "0",
			wantErr: "MAX_DEVICES",
		},
		{
			name:    "malformed max blob bytes int",
			envName: "MAX_BLOB_BYTES",
			envValu: "not-an-int",
			wantErr: "MAX_BLOB_BYTES",
		},
		{
			name:    "non-positive max blob bytes int",
			envName: "MAX_BLOB_BYTES",
			envValu: "-1",
			wantErr: "MAX_BLOB_BYTES",
		},
		{
			name:    "malformed auth rate limit count int",
			envName: "AUTH_RATE_LIMIT_COUNT",
			envValu: "not-an-int",
			wantErr: "AUTH_RATE_LIMIT_COUNT",
		},
		{
			name:    "malformed auth rate limit window duration",
			envName: "AUTH_RATE_LIMIT_WINDOW",
			envValu: "not-a-duration",
			wantErr: "AUTH_RATE_LIMIT_WINDOW",
		},
		{
			name:    "malformed metrics enabled bool",
			envName: "METRICS_ENABLED",
			envValu: "not-a-bool",
			wantErr: "METRICS_ENABLED",
		},
		{
			name:    "field encryption key too short",
			envName: "FIELD_ENCRYPTION_KEY",
			envValu: strings.Repeat("ab", 16), // decodes to 16 bytes, below the 32-byte floor
			wantErr: "FIELD_ENCRYPTION_KEY",
		},
		{
			name:    "field encryption key malformed hex",
			envName: "FIELD_ENCRYPTION_KEY",
			envValu: "not-hex-at-all-zz",
			wantErr: "FIELD_ENCRYPTION_KEY",
		},
		{
			name:    "empty bind addr fails validation",
			envName: "BIND_ADDR",
			envValu: " ",
			wantErr: "BIND_ADDR",
		},
		{
			name:    "empty db path fails validation",
			envName: "DB_PATH",
			envValu: " ",
			wantErr: "DB_PATH",
		},
		{
			name:    "invalid trusted proxy cidr fails validation",
			envName: "TRUSTED_PROXY_CIDRS",
			envValu: "not-a-cidr",
			wantErr: "TRUSTED_PROXY_CIDRS",
		},
		{
			name:    "metrics bearer token without metrics enabled fails validation",
			envName: "METRICS_BEARER_TOKEN",
			envValu: "metrics-token-fixture",
			wantErr: "METRICS_BEARER_TOKEN",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clearLoadEnv(t)
			t.Setenv(test.envName, test.envValu)

			_, err := Load()
			if err == nil {
				t.Fatalf("Load() succeeded, want error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("Load() error = %q, want it to contain %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestFieldEncryptionKeyFromEnvAcceptsMinimumLength(t *testing.T) {
	t.Setenv("FIELD_ENCRYPTION_KEY", strings.Repeat("ab", 32)) // exactly 64 hex chars -> 32 bytes

	key, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("fieldEncryptionKeyFromEnv() returned error: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("len(key) = %d, want 32", len(key))
	}
}

func TestFieldEncryptionKeyFromEnvAcceptsLongerKey(t *testing.T) {
	t.Setenv("FIELD_ENCRYPTION_KEY", strings.Repeat("cd", 48)) // 96 hex chars -> 48 bytes

	key, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("fieldEncryptionKeyFromEnv() returned error: %v", err)
	}
	if len(key) != 48 {
		t.Fatalf("len(key) = %d, want 48", len(key))
	}
}

func TestFieldEncryptionKeyFromEnvTrimsWhitespace(t *testing.T) {
	t.Setenv("FIELD_ENCRYPTION_KEY", "  "+strings.Repeat("ab", 32)+"\t\n")

	key, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("fieldEncryptionKeyFromEnv() returned error: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("len(key) = %d, want 32", len(key))
	}
}

func TestFieldEncryptionKeyFromEnvReturnsNilWhenAbsent(t *testing.T) {
	t.Setenv("FIELD_ENCRYPTION_KEY", "")

	key, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("fieldEncryptionKeyFromEnv() returned error: %v", err)
	}
	if key != nil {
		t.Fatalf("key = %#v, want nil", key)
	}
}

func TestFieldEncryptionKeyFromEnvReturnsNilWhenWhitespaceOnly(t *testing.T) {
	t.Setenv("FIELD_ENCRYPTION_KEY", "   \t  ")

	key, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err != nil {
		t.Fatalf("fieldEncryptionKeyFromEnv() returned error: %v", err)
	}
	if key != nil {
		t.Fatalf("key = %#v, want nil", key)
	}
}

func TestFieldEncryptionKeyFromEnvRejectsTooShortKey(t *testing.T) {
	// Valid hex (even length, valid digits) but decodes to only 16 bytes,
	// below the 32-byte floor documented in SECURITY.md.
	t.Setenv("FIELD_ENCRYPTION_KEY", strings.Repeat("ab", 16))

	_, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err == nil {
		t.Fatal("expected error for a too-short key, got nil")
	}
	if !strings.Contains(err.Error(), "at least 32 bytes") {
		t.Fatalf("error = %q, want it to mention the 32-byte floor", err.Error())
	}
	if !strings.Contains(err.Error(), "got 16") {
		t.Fatalf("error = %q, want it to report the decoded length", err.Error())
	}
}

func TestFieldEncryptionKeyFromEnvRejectsOddLengthHex(t *testing.T) {
	// Odd-length string can never be valid hex (each byte needs two digits).
	t.Setenv("FIELD_ENCRYPTION_KEY", strings.Repeat("a", 63))

	_, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err == nil {
		t.Fatal("expected error for an odd-length hex string, got nil")
	}
	if !strings.Contains(err.Error(), "must be a hex-encoded byte string") {
		t.Fatalf("error = %q, want it to explain the hex-encoding requirement", err.Error())
	}
}

func TestFieldEncryptionKeyFromEnvRejectsInvalidHexCharacters(t *testing.T) {
	// Even length, but "z" is never a valid hex digit.
	t.Setenv("FIELD_ENCRYPTION_KEY", strings.Repeat("zz", 32))

	_, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err == nil {
		t.Fatal("expected error for invalid hex characters, got nil")
	}
	if !strings.Contains(err.Error(), "must be a hex-encoded byte string") {
		t.Fatalf("error = %q, want it to explain the hex-encoding requirement", err.Error())
	}
}
