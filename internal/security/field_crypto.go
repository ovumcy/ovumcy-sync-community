package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	fieldCryptoSaltLabel = "ovumcy.sync-community.field-crypto.salt.v1"
	fieldCryptoInfoLabel = "ovumcy.sync-community.field-crypto.key.v1"
)

// EncryptField encrypts plaintext with AES-256-GCM using a key derived from
// secretKey via HKDF-SHA256. The ciphertext is bound to aad through the AEAD
// authentication tag so a database-level swap of one row's ciphertext into
// another row under the same key cannot be opened — the aad mismatch fails
// the decryption.
//
// aad MUST be non-empty. Callers should use a stable, context-specific
// identifier such as "ovumcy.sync-community.field.totp_secret:<account_id>".
// The returned value is base64url-encoded for persistent storage.
func EncryptField(plaintext string, secretKey []byte, aad []byte) (string, error) {
	if len(secretKey) == 0 {
		return "", errors.New("field crypto: secret key is required")
	}
	if len(aad) == 0 {
		return "", errors.New("field crypto: aad is required")
	}

	aead, err := newFieldCryptoAEAD(secretKey)
	if err != nil {
		return "", err // codecov:ignore -- newFieldCryptoAEAD cannot fail for a non-empty secretKey (HKDF-SHA256 expand to 32 bytes never errors below its ~8KB output ceiling, and 32 bytes is always a valid AES key size); needs a fake driver to fault the primitives themselves.
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("field crypto: generate nonce: %w", err) // codecov:ignore -- crypto/rand.Reader failing is not deterministically injectable in-process without swapping the package-level Reader, a global-state hack that would risk polluting concurrent tests; a crypto-primitive error that cannot occur in practice.
	}

	ciphertext := aead.Seal(nil, nonce, []byte(plaintext), aad)
	payload := make([]byte, 0, len(nonce)+len(ciphertext))
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)

	return base64.RawURLEncoding.EncodeToString(payload), nil
}

// DecryptField opens a ciphertext produced by EncryptField under the same
// secretKey and aad. A tampered ciphertext, swapped row, mis-bound aad, or
// truncated payload all fail decryption with the wrapped AEAD error.
func DecryptField(encoded string, secretKey []byte, aad []byte) (string, error) {
	if len(secretKey) == 0 {
		return "", errors.New("field crypto: secret key is required")
	}
	if len(aad) == 0 {
		return "", errors.New("field crypto: aad is required")
	}

	aead, err := newFieldCryptoAEAD(secretKey)
	if err != nil {
		return "", err // codecov:ignore -- same unreachable newFieldCryptoAEAD failure as EncryptField's identical call above; needs a fake driver.
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("field crypto: decode: %w", err)
	}

	nonceSize := aead.NonceSize()
	if len(payload) < nonceSize+1 {
		return "", errors.New("field crypto: ciphertext too short")
	}

	nonce, ct := payload[:nonceSize], payload[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", fmt.Errorf("field crypto: decrypt: %w", err)
	}

	return string(plaintext), nil
}

func newFieldCryptoAEAD(secretKey []byte) (cipher.AEAD, error) {
	reader := hkdf.New(sha256.New, secretKey, []byte(fieldCryptoSaltLabel), []byte(fieldCryptoInfoLabel))
	derivedKey := make([]byte, 32)
	if _, err := io.ReadFull(reader, derivedKey); err != nil {
		return nil, fmt.Errorf("field crypto: derive key: %w", err) // codecov:ignore -- HKDF-SHA256 expand can only fail past ~8160 bytes of output (255 * hash size); a fixed 32-byte read never approaches that ceiling for any secretKey, so this is a crypto-primitive error that cannot occur.
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("field crypto: create cipher: %w", err) // codecov:ignore -- derivedKey is always exactly 32 bytes (the make() length above), always a valid AES-256 key size; aes.NewCipher cannot reject it. Crypto-primitive error that cannot occur.
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("field crypto: create aead: %w", err) // codecov:ignore -- cipher.NewGCM only rejects a non-standard nonce size passed via NewGCMWithNonceSize; the default 12-byte nonce from a real AES block cipher never fails here. Crypto-primitive error that cannot occur.
	}

	return aead, nil
}
