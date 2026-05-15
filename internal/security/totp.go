package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
)

const (
	// TOTPStepSeconds is the standard RFC 6238 time step. Matches the default
	// most authenticator apps (Google Authenticator, Authy, 1Password) expect.
	TOTPStepSeconds = 30
	totpDigits      = 6
	totpSecretBytes = 20 // 160 bits = HMAC-SHA1 block, standard authenticator size
)

// NewTOTPSecret generates a fresh 160-bit TOTP secret. The returned plain
// value is the raw byte slice the authenticator app will share with us
// (typically base32-encoded for QR/manual entry).
func NewTOTPSecret() ([]byte, error) {
	raw := make([]byte, totpSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("totp: generate secret: %w", err)
	}
	return raw, nil
}

// EncodeTOTPSecretBase32 returns the unpadded base32 representation an
// authenticator app accepts as manual entry.
func EncodeTOTPSecretBase32(secret []byte) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString(secret), "=")
}

// DecodeTOTPSecretBase32 is the inverse of EncodeTOTPSecretBase32. Accepts
// both padded and unpadded inputs and is case-insensitive.
func DecodeTOTPSecretBase32(encoded string) ([]byte, error) {
	clean := strings.ToUpper(strings.ReplaceAll(encoded, " ", ""))
	clean = strings.TrimRight(clean, "=")
	padded := clean
	if remainder := len(padded) % 8; remainder != 0 {
		padded += strings.Repeat("=", 8-remainder)
	}
	return base32.StdEncoding.DecodeString(padded)
}

// BuildTOTPProvisioningURI constructs the standard otpauth:// URI for
// importing the secret into an authenticator app. Issuer and accountName
// are URL-escaped; the secret is base32-encoded.
func BuildTOTPProvisioningURI(secret []byte, issuer, accountName string) string {
	values := url.Values{}
	values.Set("secret", EncodeTOTPSecretBase32(secret))
	values.Set("issuer", issuer)
	values.Set("algorithm", "SHA1")
	values.Set("digits", fmt.Sprintf("%d", totpDigits))
	values.Set("period", fmt.Sprintf("%d", TOTPStepSeconds))

	label := fmt.Sprintf("%s:%s", issuer, accountName)
	return fmt.Sprintf(
		"otpauth://totp/%s?%s",
		url.PathEscape(label),
		values.Encode(),
	)
}

// GenerateTOTPCode computes the 6-digit RFC 6238 code for the given step
// (counter value). Used by tests and the verifier; production verification
// uses VerifyTOTPCode which walks ±1 step of clock skew.
func GenerateTOTPCode(secret []byte, step int64) string {
	if step < 0 {
		step = 0
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(step))

	mac := hmac.New(sha1.New, secret)
	mac.Write(counter)
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	value := binCode % 1_000_000
	return fmt.Sprintf("%06d", value)
}

// VerifyTOTPCode checks whether code matches the secret at the current step
// or ±1 step of clock skew. Returns the matching step and true on success;
// 0 and false on mismatch or malformed input. Comparison is constant-time
// to keep verification from leaking which step matched through latency.
//
// The caller MUST follow up with an atomic "claim this step" database
// update to prevent replay within the same step's lifetime — see
// `ClaimTOTPStep` on the DB layer.
func VerifyTOTPCode(secret []byte, code string, nowUnixSeconds int64) (int64, bool) {
	trimmed := strings.TrimSpace(code)
	if len(trimmed) == 0 {
		return 0, false
	}

	currentStep := nowUnixSeconds / TOTPStepSeconds
	for _, delta := range []int64{0, -1, +1} {
		step := currentStep + delta
		candidate := GenerateTOTPCode(secret, step)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(trimmed)) == 1 {
			return step, true
		}
	}
	return 0, false
}
