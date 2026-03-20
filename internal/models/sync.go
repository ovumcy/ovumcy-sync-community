package models

import "time"

type Account struct {
	ID           string
	Login        string
	PasswordHash string
	CreatedAt    time.Time
}

type Session struct {
	ID         string
	AccountID  string
	TokenHash  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

type Device struct {
	DeviceID    string    `json:"device_id"`
	AccountID   string    `json:"-"`
	DeviceLabel string    `json:"device_label"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
}

type EncryptedBlob struct {
	AccountID      string    `json:"-"`
	SchemaVersion  int       `json:"schema_version"`
	Generation     int64     `json:"generation"`
	ChecksumSHA256 string    `json:"checksum_sha256"`
	Ciphertext     []byte    `json:"-"`
	CiphertextSize int       `json:"ciphertext_size"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type CapabilityDocument struct {
	Mode              string `json:"mode"`
	SyncEnabled       bool   `json:"sync_enabled"`
	PremiumActive     bool   `json:"premium_active"`
	RecoverySupported bool   `json:"recovery_supported"`
	PushSupported     bool   `json:"push_supported"`
	PortalSupported   bool   `json:"portal_supported"`
	AdvancedInsights  bool   `json:"advanced_cloud_insights"`
	MaxDevices        int    `json:"max_devices"`
	MaxBlobBytes      int64  `json:"max_blob_bytes"`
}
