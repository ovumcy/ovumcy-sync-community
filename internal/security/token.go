package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func NewOpaqueToken() (plain string, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err // codecov:ignore -- crypto/rand.Read failing is not deterministically injectable in-process without swapping the package-level Reader, a global-state hack that would risk polluting concurrent tests; a crypto-primitive error that cannot occur in practice.
	}

	plain = base64.RawURLEncoding.EncodeToString(raw)
	hash = HashToken(plain)
	return plain, hash, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func NewIdentifier() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err // codecov:ignore -- crypto/rand.Read failing is not deterministically injectable in-process without swapping the package-level Reader, a global-state hack that would risk polluting concurrent tests; a crypto-primitive error that cannot occur in practice.
	}

	return hex.EncodeToString(raw), nil
}
