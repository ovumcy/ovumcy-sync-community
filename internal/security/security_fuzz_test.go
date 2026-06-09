package security

import (
	"strings"
	"testing"
)

// Native Go fuzz targets for the pure normalization / parsing / crypto helpers.
// Each asserts a behavioral oracle (idempotency, round-trip, AAD binding), not
// merely "does not panic". Under `go test` the seed corpus runs as ordinary
// regression tests; run e.g.
//
//	go test ./internal/security -run x -fuzz FuzzFieldCryptoRoundTrip -fuzztime 30s
//
// to actively fuzz a single target.

// FuzzNormalizeLogin checks that normalization is lowercase, trimmed, and a
// fixed point under re-normalization.
func FuzzNormalizeLogin(f *testing.F) {
	for _, seed := range []string{"", "ab", "abc", "  Owner@Example.com ", "MANAGED:x", "Имя"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := NormalizeLogin(raw)
		if got != strings.ToLower(got) {
			t.Fatalf("NormalizeLogin(%q) is not lowercase: %q", raw, got)
		}
		if got != strings.TrimSpace(got) {
			t.Fatalf("NormalizeLogin(%q) is not trimmed: %q", raw, got)
		}
		if again := NormalizeLogin(got); again != got {
			t.Fatalf("NormalizeLogin not idempotent: %q -> %q -> %q", raw, got, again)
		}
	})
}

// FuzzNormalizeRecoveryCode checks idempotency, including the invalid-UTF-8
// inputs that a naive byte-slicing implementation would mangle.
func FuzzNormalizeRecoveryCode(f *testing.F) {
	for _, seed := range []string{"", "  ABCD-ef12  ", "MixedCase", "OVUMOVUM", "\xa8\xb2000\xd9"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got := NormalizeRecoveryCode(raw)
		if again := NormalizeRecoveryCode(got); again != got {
			t.Fatalf("NormalizeRecoveryCode not idempotent: %q -> %q -> %q", raw, got, again)
		}
	})
}

// FuzzValidateLogin checks the total-function contract: any accepted login is
// at least three characters after normalization and never sits in the reserved
// managed: namespace (bridge-provisioned accounts only).
func FuzzValidateLogin(f *testing.F) {
	for _, seed := range []string{"", "ab", "abc", "managed:x", "MANAGED:abc123", "  managed:abc  ", "user@example.com"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if ValidateLogin(raw) {
			n := NormalizeLogin(raw)
			if len(n) < 3 {
				t.Fatalf("ValidateLogin accepted a login that normalizes below 3 chars: %q -> %q", raw, n)
			}
			if strings.HasPrefix(n, "managed:") {
				t.Fatalf("ValidateLogin accepted a reserved managed: login: %q", raw)
			}
		}
	})
}

// FuzzDecodeTOTPSecretBase32 checks that decoding never panics and that any
// accepted secret survives a canonical encode/decode round-trip.
func FuzzDecodeTOTPSecretBase32(f *testing.F) {
	for _, seed := range []string{"", "AAAA", "JBSWY3DPEHPK3PXP", "jbswy3dp ehpk", "====", "!!!!", "12345678"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		secret, err := DecodeTOTPSecretBase32(encoded)
		if err != nil {
			return // rejecting malformed base32 is a valid outcome
		}
		again, err := DecodeTOTPSecretBase32(EncodeTOTPSecretBase32(secret))
		if err != nil {
			t.Fatalf("re-decoding canonical base32 of %q failed: %v", encoded, err)
		}
		if string(again) != string(secret) {
			t.Fatalf("base32 decode is not a fixed point for input %q", encoded)
		}
	})
}

// FuzzFieldCryptoRoundTrip checks that EncryptField/DecryptField round-trip
// under the same key+aad and that a different aad never opens the ciphertext
// (the at-rest swap-resistance the AEAD binding is there to provide).
func FuzzFieldCryptoRoundTrip(f *testing.F) {
	for _, seed := range []string{"", "secret", "ovumcy totp secret", "Имя 123"} {
		f.Add(seed, "ovumcy.sync-community.field.totp_secret:acc")
	}
	f.Fuzz(func(t *testing.T, plaintext, aad string) {
		if aad == "" {
			return // EncryptField requires a non-empty aad by contract
		}
		key := []byte("fuzz-field-encryption-key-must-be-32+bytes-long")
		encoded, err := EncryptField(plaintext, key, []byte(aad))
		if err != nil {
			t.Fatalf("EncryptField(plaintext=%q, aad=%q) errored: %v", plaintext, aad, err)
		}
		got, err := DecryptField(encoded, key, []byte(aad))
		if err != nil {
			t.Fatalf("DecryptField round-trip failed for %q: %v", plaintext, err)
		}
		if got != plaintext {
			t.Fatalf("field-crypto round-trip mismatch: got %q want %q", got, plaintext)
		}
		if _, err := DecryptField(encoded, key, []byte(aad+"-tampered")); err == nil {
			t.Fatalf("DecryptField opened ciphertext under a mismatched aad")
		}
	})
}
