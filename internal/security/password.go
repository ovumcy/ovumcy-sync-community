package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ErrWeakPassword = errors.New("weak_password")

func NormalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func ValidateLogin(login string) bool {
	return len(NormalizeLogin(login)) >= 3
}

func HashPassword(password string) (string, error) {
	if len(strings.TrimSpace(password)) < 12 {
		return "", ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func ComparePasswordHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// NewRecoveryCode generates a fresh account-level recovery code and returns
// the plaintext value together with its bcrypt hash. The plaintext value is
// what the operator hands to the owner; only the hash is ever stored.
//
// The recovery code is 32 lowercase hex characters (128 bits of entropy)
// without separators, deliberately the same shape as `HashToken` output so
// clients can treat it as an opaque token.
func NewRecoveryCode() (plain string, hash string, err error) {
	raw := make([]byte, 16)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}

	plain = hex.EncodeToString(raw)
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", "", err
	}
	return plain, string(bcryptHash), nil
}

// CompareRecoveryCodeHash returns nil when plain matches the stored bcrypt
// hash. An empty stored hash always fails — accounts created before recovery
// codes existed cannot use the forgot-password flow until they regenerate.
func CompareRecoveryCodeHash(hash string, plain string) error {
	if strings.TrimSpace(hash) == "" {
		return bcrypt.ErrMismatchedHashAndPassword
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}

// NormalizeRecoveryCode strips whitespace and lower-cases the input so
// operator-shown codes survive copy/paste irregularities. The hash is built
// over the normalized form so both ends compare deterministically.
func NormalizeRecoveryCode(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}
