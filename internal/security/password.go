package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var ErrWeakPassword = errors.New("weak_password")

// PasswordHashCost is the bcrypt cost for every hash this server generates:
// account passwords (HashPassword) and recovery codes (NewRecoveryCode).
//
// CWE-208 coupling: the login/forgot-password timing equalizer in
// internal/services burns bcrypt work against a fixed placeholder hash whose
// embedded cost MUST equal this constant. If real hashes and the placeholder
// ever diverge in cost, an early return on an unknown login performs a
// measurably different amount of work than a real wrong-credential compare,
// and login enumeration by timing becomes possible again. Move this constant
// and the placeholder together — a test pins the parity
// (TestPasswordTimingEqualizationHashCostMatchesPasswordHashCost).
const PasswordHashCost = 12

func NormalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

// reservedManagedLoginPrefix is the login namespace the managed-cloud bridge
// uses when it provisions bridged accounts (login = "managed:" + accountID, see
// managed_bridge_service.go). Public self-hosted registration must not be able
// to claim a login in this namespace, or a self-hosted user could squat a
// managed account's login and permanently block the bridge from provisioning
// that account (the bridge's upsert would collide on the login UNIQUE index).
const reservedManagedLoginPrefix = "managed:"

func ValidateLogin(login string) bool {
	normalized := NormalizeLogin(login)
	if len(normalized) < 3 {
		return false
	}
	if strings.HasPrefix(normalized, reservedManagedLoginPrefix) {
		return false
	}
	return true
}

// HashPassword enforces the minimum-strength rule (at least 12 Unicode runes
// after trimming whitespace, not bytes) before returning the bcrypt hash.
// Rune-counting matches ovumcy-managed's HashPassword exactly, so the same
// password is never accepted by one backend and rejected by the other.
func HashPassword(password string) (string, error) {
	if utf8.RuneCountInString(strings.TrimSpace(password)) < 12 {
		return "", ErrWeakPassword
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), PasswordHashCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func ComparePasswordHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// PasswordHashNeedsRehash reports whether a stored bcrypt hash was generated
// at a lower cost than PasswordHashCost and should be transparently upgraded
// after its next successful verification. An unparseable hash returns false:
// the caller has already verified the credential against the stored hash, so
// a hash whose cost cannot even be read is left to the compare path to
// surface — it is never rewritten blindly.
func PasswordHashNeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	return err == nil && cost < PasswordHashCost
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
		return "", "", err // codecov:ignore -- crypto/rand.Read failing is not deterministically injectable in-process without swapping the package-level Reader, a global-state hack that would risk polluting concurrent tests; a crypto-primitive error that cannot occur in practice.
	}

	plain = hex.EncodeToString(raw)
	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(plain), PasswordHashCost)
	if err != nil {
		return "", "", err // codecov:ignore -- unlike HashPassword's caller-controlled input, plain is always exactly 32 hex chars (16 bytes hex-encoded), far under bcrypt's 72-byte ErrPasswordTooLong ceiling, and PasswordHashCost is a fixed valid cost; bcrypt cannot fail on this fixed-shape input.
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
