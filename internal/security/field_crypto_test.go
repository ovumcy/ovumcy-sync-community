package security

import (
	"strings"
	"testing"
)

func TestEncryptFieldRoundtrip(t *testing.T) {
	key := bytes32(0x42)
	aad := []byte("ovumcy.test:row-1")

	encrypted, err := EncryptField("secret payload", key, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if strings.TrimSpace(encrypted) == "" {
		t.Fatal("expected non-empty ciphertext")
	}

	got, err := DecryptField(encrypted, key, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != "secret payload" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
}

func TestDecryptFieldRejectsWrongAAD(t *testing.T) {
	key := bytes32(0x42)
	encrypted, err := EncryptField("secret payload", key, []byte("ovumcy.test:row-1"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptField(encrypted, key, []byte("ovumcy.test:row-2")); err == nil {
		t.Fatal("expected decrypt to fail with different aad")
	}
}

func TestDecryptFieldRejectsWrongKey(t *testing.T) {
	aad := []byte("ovumcy.test:row-1")
	encrypted, err := EncryptField("secret payload", bytes32(0x42), aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := DecryptField(encrypted, bytes32(0x99), aad); err == nil {
		t.Fatal("expected decrypt to fail with different key")
	}
}

func TestEncryptFieldRequiresKeyAndAAD(t *testing.T) {
	if _, err := EncryptField("x", nil, []byte("aad")); err == nil {
		t.Fatal("expected empty key to fail")
	}
	if _, err := EncryptField("x", bytes32(1), nil); err == nil {
		t.Fatal("expected empty aad to fail")
	}
}

func TestEncryptFieldProducesDifferentCiphertextEachCall(t *testing.T) {
	key := bytes32(0x42)
	aad := []byte("ovumcy.test:row-1")

	first, err := EncryptField("secret", key, aad)
	if err != nil {
		t.Fatalf("first encrypt: %v", err)
	}
	second, err := EncryptField("secret", key, aad)
	if err != nil {
		t.Fatalf("second encrypt: %v", err)
	}
	if first == second {
		t.Fatal("expected different ciphertexts via random nonce")
	}
}

func bytes32(seed byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	return key
}
