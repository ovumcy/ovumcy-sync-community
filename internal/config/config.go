package config

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BindAddr            string
	DBPath              string
	SessionTTL          time.Duration
	MaxDevices          int
	MaxBlobBytes        int
	AuthRateLimitCount  int
	AuthRateLimitWindow time.Duration
	ManagedBridgeToken  string
	MetricsEnabled      bool
	MetricsBearerToken  string
	AllowedOrigins      []string
	TrustedProxyCIDRs   []string
	// FieldEncryptionKey holds the master key used to encrypt privacy-sensitive
	// account-row fields (currently the TOTP secret); HKDF derives the per-field
	// 32-byte key from it, so any length >= 32 bytes is accepted. The server
	// REQUIRES it to be set when any account has TOTP enabled. The env var
	// FIELD_ENCRYPTION_KEY must carry a hex string of at least 32 bytes
	// (>= 64 hex chars).
	FieldEncryptionKey []byte
	// TOTPIssuer is the issuer label embedded in TOTP otpauth:// provisioning
	// URIs. It controls how authenticator apps label the account in the user's
	// vault. Defaults to "ovumcy-sync-community" but operators with custom
	// branding can override via TOTP_ISSUER.
	TOTPIssuer string
	// LapsedAccountGracePeriod is how long a managed account is kept after its
	// entitlement-lapse marker (accounts.lapsed_at, set by the managed
	// bridge's POST /managed/accounts/{account_id}/premium lapse signal) is
	// recorded before the purge-lapsed-accounts CLI subcommand erases it. A
	// session mint (resubscribe) clears the marker at any point before the
	// grace period elapses, so this is purely a data-minimization window, not
	// a product feature deadline. One default for managed-cloud and
	// self-hosted deployments, operator-tunable via
	// LAPSED_ACCOUNT_GRACE_PERIOD. Defaults to 60 days.
	LapsedAccountGracePeriod time.Duration
	// LapsedAccountSweepInterval, from LAPSED_ACCOUNT_SWEEP_INTERVAL (default
	// 24h), paces the in-process purge of accounts whose grace period has
	// elapsed. It exists because retention that depends on an operator
	// remembering to schedule the purge-lapsed-accounts cron is retention that
	// silently does not happen: the managed side signals a lapse, this server
	// records it and starts the clock, and without a trigger the data is then
	// kept forever. The sweep is idempotent, so a deployment that also runs
	// the cron is unaffected.
	//
	// Set to 0 to disable the in-process sweep and leave the subcommand as the
	// only trigger. That is also the rollback: it takes effect on restart, with
	// no new image.
	LapsedAccountSweepInterval time.Duration
	// LapsedAccountSweepLimit, from LAPSED_ACCOUNT_SWEEP_LIMIT (default 0 =
	// the store's own default page size), caps how many candidate accounts one
	// in-process sweep run examines.
	LapsedAccountSweepLimit int
}

func Load() (Config, error) {
	sessionTTL, err := durationFromEnv("SESSION_TTL", 720*time.Hour)
	if err != nil {
		return Config{}, err
	}

	maxDevices, err := intFromEnv("MAX_DEVICES", 5)
	if err != nil {
		return Config{}, err
	}

	maxBlobBytes, err := intFromEnv("MAX_BLOB_BYTES", 16<<20)
	if err != nil {
		return Config{}, err
	}

	authRateLimitCount, err := intFromEnv("AUTH_RATE_LIMIT_COUNT", 10)
	if err != nil {
		return Config{}, err
	}

	authRateLimitWindow, err := durationFromEnv("AUTH_RATE_LIMIT_WINDOW", time.Minute)
	if err != nil {
		return Config{}, err
	}

	metricsEnabled, err := boolFromEnv("METRICS_ENABLED", false)
	if err != nil {
		return Config{}, err
	}

	fieldKey, err := fieldEncryptionKeyFromEnv("FIELD_ENCRYPTION_KEY")
	if err != nil {
		return Config{}, err
	}

	lapsedAccountGracePeriod, err := durationFromEnv("LAPSED_ACCOUNT_GRACE_PERIOD", 60*24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	lapsedAccountSweepInterval, err := durationFromEnv("LAPSED_ACCOUNT_SWEEP_INTERVAL", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	// Deliberately not validated as positive, unlike the grace period: 0 is the
	// documented way to turn the in-process sweep off and keep the cron as the
	// only trigger.
	lapsedAccountSweepLimit, err := intFromEnv("LAPSED_ACCOUNT_SWEEP_LIMIT", 0)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		BindAddr:                   stringFromEnv("BIND_ADDR", ":8080"),
		DBPath:                     stringFromEnv("DB_PATH", "./data/ovumcy-sync-community.sqlite"),
		SessionTTL:                 sessionTTL,
		MaxDevices:                 maxDevices,
		MaxBlobBytes:               maxBlobBytes,
		AuthRateLimitCount:         authRateLimitCount,
		AuthRateLimitWindow:        authRateLimitWindow,
		ManagedBridgeToken:         os.Getenv("MANAGED_BRIDGE_TOKEN"),
		MetricsEnabled:             metricsEnabled,
		MetricsBearerToken:         os.Getenv("METRICS_BEARER_TOKEN"),
		AllowedOrigins:             csvListFromEnv("ALLOWED_ORIGINS"),
		TrustedProxyCIDRs:          csvListFromEnv("TRUSTED_PROXY_CIDRS"),
		FieldEncryptionKey:         fieldKey,
		TOTPIssuer:                 stringFromEnv("TOTP_ISSUER", "ovumcy-sync-community"),
		LapsedAccountGracePeriod:   lapsedAccountGracePeriod,
		LapsedAccountSweepInterval: lapsedAccountSweepInterval,
		LapsedAccountSweepLimit:    lapsedAccountSweepLimit,
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func fieldEncryptionKeyFromEnv(name string) ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return nil, nil
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be a hex-encoded byte string: %w", name, err)
	}
	if len(decoded) < 32 {
		return nil, fmt.Errorf(
			"%s must decode to at least 32 bytes (got %d); generate one with `openssl rand -hex 32`",
			name,
			len(decoded),
		)
	}
	return decoded, nil
}

func (c Config) Validate() error {
	if strings.TrimSpace(c.BindAddr) == "" {
		return fmt.Errorf("BIND_ADDR must not be empty")
	}
	if strings.TrimSpace(c.DBPath) == "" {
		return fmt.Errorf("DB_PATH must not be empty")
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("SESSION_TTL must be positive")
	}
	if c.MaxDevices <= 0 {
		return fmt.Errorf("MAX_DEVICES must be positive")
	}
	if c.MaxBlobBytes <= 0 {
		return fmt.Errorf("MAX_BLOB_BYTES must be positive")
	}
	if c.AuthRateLimitCount <= 0 {
		return fmt.Errorf("AUTH_RATE_LIMIT_COUNT must be positive")
	}
	if c.AuthRateLimitWindow <= 0 {
		return fmt.Errorf("AUTH_RATE_LIMIT_WINDOW must be positive")
	}
	if strings.TrimSpace(c.MetricsBearerToken) != "" && !c.MetricsEnabled {
		return fmt.Errorf("METRICS_BEARER_TOKEN requires METRICS_ENABLED=true")
	}
	for _, value := range c.TrustedProxyCIDRs {
		if _, err := ParseTrustedProxyCIDR(value); err != nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS entry %q is invalid: %w", value, err)
		}
	}
	if c.LapsedAccountGracePeriod <= 0 {
		return fmt.Errorf("LAPSED_ACCOUNT_GRACE_PERIOD must be positive")
	}

	return nil
}

func stringFromEnv(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func boolFromEnv(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", name, err)
	}

	return parsed, nil
}

func durationFromEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}

	return parsed, nil
}

func intFromEnv(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", name, err)
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return parsed, nil
}

func csvListFromEnv(name string) []string {
	value := os.Getenv(name)
	if value == "" {
		return nil
	}

	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}

	if len(result) == 0 {
		return nil
	}

	return result
}

// ParseTrustedProxyCIDR parses one TRUSTED_PROXY_CIDRS entry: either a CIDR
// ("10.0.0.0/24") or a bare address ("127.0.0.1"), normalized to a masked
// prefix. It is the single parser shared by config validation and the API
// trusted-proxy matcher.
func ParseTrustedProxyCIDR(value string) (netip.Prefix, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return netip.Prefix{}, fmt.Errorf("must not be empty")
	}

	if strings.Contains(trimmed, "/") {
		prefix, err := netip.ParsePrefix(trimmed)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}

	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return netip.Prefix{}, err
	}

	if addr.Is4() {
		return netip.PrefixFrom(addr, 32), nil
	}

	return netip.PrefixFrom(addr, 128), nil
}
