package security

import (
	"encoding/base32"
	"strings"
	"testing"
)

func TestNewTOTPSecretIs160Bits(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatalf("new secret: %v", err)
	}
	if len(secret) != 20 {
		t.Fatalf("expected 20-byte secret, got %d", len(secret))
	}
}

func TestEncodeDecodeBase32Roundtrip(t *testing.T) {
	secret := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	}
	encoded := EncodeTOTPSecretBase32(secret)
	if strings.ContainsRune(encoded, '=') {
		t.Fatalf("expected unpadded base32, got %q", encoded)
	}

	decoded, err := DecodeTOTPSecretBase32(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(secret) {
		t.Fatalf("roundtrip mismatch: %x vs %x", decoded, secret)
	}
}

func TestGenerateTOTPCodeIsRFC6238TestVector(t *testing.T) {
	// RFC 6238 Appendix B test vector for SHA-1 with the 20-byte ASCII secret
	// "12345678901234567890". Expected codes are listed against specific
	// Unix times. The step for time T is T / 30.
	secret := []byte("12345678901234567890")
	cases := []struct {
		nowSeconds int64
		expected   string
	}{
		{59, "287082"},          // T1 = 1, code 94287082 truncated to 6 digits → "287082"
		{1111111109, "081804"},  // T = 0x023523EC
		{1111111111, "050471"},  // T = 0x023523ED
		{1234567890, "005924"},  // T = 0x0273EF07
	}
	for _, tc := range cases {
		step := tc.nowSeconds / TOTPStepSeconds
		got := GenerateTOTPCode(secret, step)
		if got != tc.expected {
			t.Fatalf("RFC 6238 vector at %d (step %d): expected %s, got %s",
				tc.nowSeconds, step, tc.expected, got)
		}
	}
}

func TestVerifyTOTPCodeAcceptsCurrentAndAdjacentSteps(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := int64(1234567890)
	step := now / TOTPStepSeconds

	for _, delta := range []int64{-1, 0, 1} {
		code := GenerateTOTPCode(secret, step+delta)
		matchedStep, ok := VerifyTOTPCode(secret, code, now)
		if !ok {
			t.Fatalf("expected verify to succeed at delta %d", delta)
		}
		if matchedStep != step+delta {
			t.Fatalf("expected matched step %d at delta %d, got %d", step+delta, delta, matchedStep)
		}
	}
}

func TestVerifyTOTPCodeRejectsFarFutureAndPastSteps(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := int64(1234567890)
	step := now / TOTPStepSeconds

	farCode := GenerateTOTPCode(secret, step+10)
	if _, ok := VerifyTOTPCode(secret, farCode, now); ok {
		t.Fatal("expected verify to reject a +10-step code")
	}
}

func TestVerifyTOTPCodeRejectsEmpty(t *testing.T) {
	if _, ok := VerifyTOTPCode([]byte("12345678901234567890"), "", 1234567890); ok {
		t.Fatal("expected empty code to fail")
	}
}

func TestBuildTOTPProvisioningURIIncludesSecretAndIssuer(t *testing.T) {
	secret := []byte("12345678901234567890")
	uri := BuildTOTPProvisioningURI(secret, "Ovumcy", "owner@example.com")

	expectedSecret := strings.TrimRight(
		base32.StdEncoding.EncodeToString(secret),
		"=",
	)
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("unexpected scheme/host: %q", uri)
	}
	if !strings.Contains(uri, "issuer=Ovumcy") {
		t.Fatalf("missing issuer in URI: %q", uri)
	}
	if !strings.Contains(uri, "secret="+expectedSecret) {
		t.Fatalf("missing secret in URI: %q", uri)
	}
	if !strings.Contains(uri, "Ovumcy:owner@example.com") {
		t.Fatalf("expected issuer:account label, got %q", uri)
	}
}
