// Package crypto provides AES-256-GCM primitives + keychain-backed data-key
// loader for encrypting secrets at rest (Postgres password in config.yaml,
// future encrypted columns).
//
// Wire format: [magic(0x01) | nonce(12) | ciphertext | gcm_tag(16)]
// MagicPrefixV1 is FROZEN — new schemes must add a new prefix byte.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/inovacc/unravel-oss/pkg/keychain"
)

const MagicPrefixV1 byte = 0x01

const (
	aesGCMKeySize   = 32 // AES-256
	aesGCMNonceSize = 12
	aesGCMTagSize   = 16
	magicPrefixSize = 1
	minCiphertext   = magicPrefixSize + aesGCMNonceSize + aesGCMTagSize // 29
)

// ErrEncryptionKeyMissing — keychain has no usable data-encryption key and
// the backend cannot generate one. Run `unravel db setup` to fix.
var ErrEncryptionKeyMissing = errors.New(
	"encryption key missing or corrupted — run `unravel db setup` or restore from backup",
)

// EncryptAESGCM encrypts plaintext under key (must be 32 bytes) and returns
// the wire-format blob.
func EncryptAESGCM(plaintext, key []byte) ([]byte, error) {
	if len(key) != aesGCMKeySize {
		return nil, fmt.Errorf("aes-gcm: key must be %d bytes, got %d", aesGCMKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new gcm: %w", err)
	}
	nonce := make([]byte, aesGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("aes-gcm: nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, magicPrefixSize+len(nonce)+len(ct))
	out = append(out, MagicPrefixV1)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptAESGCM decrypts a wire-format blob produced by EncryptAESGCM.
func DecryptAESGCM(blob, key []byte) ([]byte, error) {
	if len(key) != aesGCMKeySize {
		return nil, fmt.Errorf("aes-gcm: key must be %d bytes", aesGCMKeySize)
	}
	if len(blob) < minCiphertext {
		return nil, fmt.Errorf("aes-gcm: ciphertext too short (%d < %d)", len(blob), minCiphertext)
	}
	if blob[0] != MagicPrefixV1 {
		return nil, fmt.Errorf("aes-gcm: bad magic prefix 0x%02x", blob[0])
	}
	nonce := blob[magicPrefixSize : magicPrefixSize+aesGCMNonceSize]
	ct := blob[magicPrefixSize+aesGCMNonceSize:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: new gcm: %w", err)
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: open: %w", err)
	}
	return pt, nil
}

// IsEncrypted reports whether blob has the v1 magic prefix.
func IsEncrypted(blob []byte) bool {
	return len(blob) >= minCiphertext && blob[0] == MagicPrefixV1
}

// EncryptString is a convenience wrapper that returns base64-encoded
// ciphertext suitable for a YAML field.
func EncryptString(plaintext string, key []byte) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	ct, err := EncryptAESGCM([]byte(plaintext), key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// DecryptString is the inverse of EncryptString.
func DecryptString(b64 string, key []byte) (string, error) {
	if b64 == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decrypt: bad base64: %w", err)
	}
	pt, err := DecryptAESGCM(raw, key)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// LoadOrGenerateDataKey returns the 32-byte AES-256-GCM data key from
// keychain.AccountEncryptionKey. On first call (entry missing), a fresh
// 32 bytes from crypto/rand is generated and persisted. The keychain
// stores the key base64-encoded.
//
// Returns ErrEncryptionKeyMissing wrapping keychain.ErrSecretServiceUnavailable
// when the OS keychain backend is unreachable AND no entry exists.
func LoadOrGenerateDataKey() ([]byte, error) {
	enc, err := keychain.Get(keychain.AccountEncryptionKey)
	switch {
	case err == nil:
		raw, derr := base64.StdEncoding.DecodeString(enc)
		if derr != nil {
			return nil, fmt.Errorf("%w: stored key is not valid base64: %v", ErrEncryptionKeyMissing, derr)
		}
		if len(raw) != aesGCMKeySize {
			return nil, fmt.Errorf("%w: stored key is %d bytes (want %d)", ErrEncryptionKeyMissing, len(raw), aesGCMKeySize)
		}
		return raw, nil

	case errors.Is(err, keychain.ErrNotFound):
		// First-run: generate, persist.
		key := make([]byte, aesGCMKeySize)
		if _, rerr := io.ReadFull(rand.Reader, key); rerr != nil {
			return nil, fmt.Errorf("generate data key: %w", rerr)
		}
		if serr := keychain.Set(keychain.AccountEncryptionKey, base64.StdEncoding.EncodeToString(key)); serr != nil {
			if keychain.IsSecretServiceUnavailable(serr) {
				return nil, fmt.Errorf("%w: %w", ErrEncryptionKeyMissing, serr)
			}
			return nil, fmt.Errorf("persist data key: %w", serr)
		}
		return key, nil

	default:
		if keychain.IsSecretServiceUnavailable(err) {
			return nil, fmt.Errorf("%w: %w", ErrEncryptionKeyMissing, err)
		}
		return nil, fmt.Errorf("load data key: %w", err)
	}
}
