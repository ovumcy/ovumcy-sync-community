package security

import (
	"testing"

	"pgregory.net/rapid"
)

// Property-based tests over the security primitives, complementing the native
// fuzz targets with rapid's structured generators and shrinking. They pin
// invariants that line coverage cannot: crypto round-trips, AAD binding, and
// the TOTP generate/verify/skew contract.

// TestFieldCryptoRoundTripProperty: Decrypt(Encrypt(p, k, aad), k, aad) == p
// for any plaintext, any non-empty key, any non-empty aad.
func TestFieldCryptoRoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		plaintext := rapid.String().Draw(t, "plaintext")
		aad := rapid.String().Draw(t, "aad")
		if aad == "" {
			return
		}
		key := rapid.SliceOf(rapid.Byte()).Draw(t, "key")
		if len(key) == 0 {
			return
		}
		encoded, err := EncryptField(plaintext, key, []byte(aad))
		if err != nil {
			t.Fatalf("EncryptField errored: %v", err)
		}
		got, err := DecryptField(encoded, key, []byte(aad))
		if err != nil {
			t.Fatalf("DecryptField errored: %v", err)
		}
		if got != plaintext {
			t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
		}
	})
}

// TestFieldCryptoAADBindingProperty: a ciphertext sealed under one aad must
// never open under a different aad.
func TestFieldCryptoAADBindingProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		plaintext := rapid.String().Draw(t, "plaintext")
		aad := rapid.String().Draw(t, "aad")
		other := rapid.String().Draw(t, "other")
		if aad == "" || other == "" || aad == other {
			return
		}
		key := []byte("property-field-encryption-key-32-bytes-min!")
		encoded, err := EncryptField(plaintext, key, []byte(aad))
		if err != nil {
			t.Fatalf("EncryptField errored: %v", err)
		}
		if _, err := DecryptField(encoded, key, []byte(other)); err == nil {
			t.Fatalf("ciphertext opened under a different aad (binding broken)")
		}
	})
}

// TestTOTPGenerateVerifyProperty: a code generated for the current step always
// verifies and reports that same step.
func TestTOTPGenerateVerifyProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.SliceOf(rapid.Byte()).Draw(t, "secret")
		if len(secret) == 0 {
			return
		}
		now := rapid.Int64Range(0, 4102444800).Draw(t, "now") // through year 2100
		want := now / TOTPStepSeconds
		code := GenerateTOTPCode(secret, want)
		step, ok := VerifyTOTPCode(secret, code, now)
		if !ok {
			t.Fatalf("VerifyTOTPCode rejected a freshly generated code at now=%d", now)
		}
		if step != want {
			t.Fatalf("VerifyTOTPCode returned step %d, want %d", step, want)
		}
	})
}

// TestTOTPSkewWindowProperty: the ±1 step skew window accepts the previous
// step's code, and a code two steps away does not verify (barring a rare
// 6-digit collision with an in-window code).
func TestTOTPSkewWindowProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.SliceOf(rapid.Byte()).Draw(t, "secret")
		if len(secret) == 0 {
			return
		}
		now := rapid.Int64Range(120, 4102444800).Draw(t, "now")
		current := now / TOTPStepSeconds
		if _, ok := VerifyTOTPCode(secret, GenerateTOTPCode(secret, current-1), now); !ok {
			t.Fatalf("VerifyTOTPCode rejected a code from the previous step (skew window)")
		}
		far := GenerateTOTPCode(secret, current-2)
		inWindow := map[string]bool{
			GenerateTOTPCode(secret, current-1): true,
			GenerateTOTPCode(secret, current):   true,
			GenerateTOTPCode(secret, current+1): true,
		}
		if !inWindow[far] {
			if _, ok := VerifyTOTPCode(secret, far, now); ok {
				t.Fatalf("VerifyTOTPCode accepted a code two steps away")
			}
		}
	})
}

// TestTOTPBase32RoundTripProperty: Decode(Encode(secret)) == secret.
func TestTOTPBase32RoundTripProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		secret := rapid.SliceOf(rapid.Byte()).Draw(t, "secret")
		again, err := DecodeTOTPSecretBase32(EncodeTOTPSecretBase32(secret))
		if err != nil {
			t.Fatalf("base32 round-trip errored: %v", err)
		}
		if string(again) != string(secret) {
			t.Fatalf("base32 round-trip changed bytes")
		}
	})
}
