package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	BindAddr   string
	DBPath     string
	SessionTTL time.Duration
	MaxDevices int
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

	return Config{
		BindAddr:   stringFromEnv("BIND_ADDR", ":8080"),
		DBPath:     stringFromEnv("DB_PATH", "./data/ovumcy-sync-community.sqlite"),
		SessionTTL: sessionTTL,
		MaxDevices: maxDevices,
	}, nil
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
