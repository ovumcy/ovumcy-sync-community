package config

import (
	"fmt"
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
	AllowedOrigins      []string
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

	cfg := Config{
		BindAddr:            stringFromEnv("BIND_ADDR", ":8080"),
		DBPath:              stringFromEnv("DB_PATH", "./data/ovumcy-sync-community.sqlite"),
		SessionTTL:          sessionTTL,
		MaxDevices:          maxDevices,
		MaxBlobBytes:        maxBlobBytes,
		AuthRateLimitCount:  authRateLimitCount,
		AuthRateLimitWindow: authRateLimitWindow,
		ManagedBridgeToken:  os.Getenv("MANAGED_BRIDGE_TOKEN"),
		AllowedOrigins:      csvListFromEnv("ALLOWED_ORIGINS"),
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
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

	return nil
}

func stringFromEnv(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
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
