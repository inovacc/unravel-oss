// Tests for the AES-GCM wire format and base64 helpers. Skips
// LoadOrGenerateDataKey because it touches the real OS keychain — that
// path is exercised end-to-end by the `unravel db setup` smoke test.

package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := newKey(t)
	cases := []string{
		"",
		"short",
		"with spaces and newline\n",
		strings.Repeat("a", 1<<10),
		"日本語 + emoji 🔐",
	}
	for _, plaintext := range cases {
		t.Run(plaintext, func(t *testing.T) {
			if plaintext == "" {
				return // EncryptString short-circuits the empty path; covered separately.
			}
			ct, err := EncryptAESGCM([]byte(plaintext), key)
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			if ct[0] != MagicPrefixV1 {
				t.Fatalf("magic prefix = 0x%02x, want 0x%02x", ct[0], MagicPrefixV1)
			}
			if !IsEncrypted(ct) {
				t.Fatal("IsEncrypted = false on fresh ciphertext")
			}
			pt, err := DecryptAESGCM(ct, key)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(pt, []byte(plaintext)) {
				t.Fatalf("plaintext mismatch: got %q, want %q", pt, plaintext)
			}
		})
	}
}

func TestEncryptStringEmptyPassthrough(t *testing.T) {
	key := newKey(t)
	got, err := EncryptString("", key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty ciphertext for empty plaintext, got %q", got)
	}
	pt, err := DecryptString("", key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if pt != "" {
		t.Fatalf("expected empty plaintext, got %q", pt)
	}
}

func TestEncryptStringRoundTripBase64(t *testing.T) {
	key := newKey(t)
	enc, err := EncryptString("postgres-password", key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if enc == "postgres-password" {
		t.Fatal("encrypted blob equals plaintext — encryption is not happening")
	}
	dec, err := DecryptString(enc, key)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != "postgres-password" {
		t.Fatalf("got %q want postgres-password", dec)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	k1 := newKey(t)
	k2 := newKey(t)
	ct, err := EncryptAESGCM([]byte("secret"), k1)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := DecryptAESGCM(ct, k2); err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestDecryptBadMagicFails(t *testing.T) {
	key := newKey(t)
	ct, err := EncryptAESGCM([]byte("x"), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct[0] = 0xff
	if _, err := DecryptAESGCM(ct, key); err == nil {
		t.Fatal("expected magic-prefix error, got nil")
	}
}

func TestDecryptShortCiphertextFails(t *testing.T) {
	key := newKey(t)
	if _, err := DecryptAESGCM([]byte{MagicPrefixV1}, key); err == nil {
		t.Fatal("expected short-ciphertext error")
	}
}

func TestEncryptWrongKeyLengthFails(t *testing.T) {
	if _, err := EncryptAESGCM([]byte("x"), make([]byte, 16)); err == nil {
		t.Fatal("expected key-size error")
	}
}

func TestIsEncryptedRejectsLegacy(t *testing.T) {
	if IsEncrypted([]byte("plain")) {
		t.Fatal("legacy plaintext should not be detected as encrypted")
	}
	if IsEncrypted(nil) {
		t.Fatal("nil should not be detected as encrypted")
	}
}
