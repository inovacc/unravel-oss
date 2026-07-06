// Package keychain wraps github.com/zalando/go-keyring for storing small
// secrets in the OS-native credential store (Windows Credential Manager,
// macOS Keychain, Linux Secret Service via D-Bus).
//
// Service identifier and account names are FROZEN — changing them would
// orphan secrets stored by prior installs.
package keychain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

// Service is the unravel-wide service identifier. FROZEN.
const Service = "unravel"

// AccountDBPassword is the FROZEN account name of a legacy plaintext password
// mirror. It is NO LONGER written; `unravel db setup` and `db rotate-password`
// best-effort delete it to wipe stale copies left by prior installs. The
// password lives only as config.yaml.password_enc ciphertext (decrypted with
// the data key in AccountEncryptionKey). Kept solely for that cleanup delete.
const AccountDBPassword = "db-password"

// AccountEncryptionKey is the account holding the 32-byte AES-256-GCM
// data key that decrypts config.yaml.password_enc and any future
// at-rest-encrypted columns. Generated on first call to
// crypto.LoadOrGenerateDataKey.
const AccountEncryptionKey = "db-encryption-key"

// ErrNotFound — no entry exists. Wraps keyring.ErrNotFound. Use errors.Is.
var ErrNotFound = errors.New("keychain: account not found")

// ErrSecretServiceUnavailable — Linux backend unreachable (no
// gnome-keyring/kwallet running, headless CI, etc.).
var ErrSecretServiceUnavailable = errors.New("keychain: secret service unavailable")

func isSecretServiceUnavailableErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "secret service") ||
		strings.Contains(msg, "no such interface") ||
		strings.Contains(msg, "dbus") ||
		strings.Contains(msg, "service is not available")
}

// IsSecretServiceUnavailable reports whether err is (or wraps)
// ErrSecretServiceUnavailable.
func IsSecretServiceUnavailable(err error) bool {
	return errors.Is(err, ErrSecretServiceUnavailable)
}

// Set writes value under Service+account.
func Set(account, value string) error {
	if err := keyring.Set(Service, account, value); err != nil {
		if isSecretServiceUnavailableErr(err) {
			return fmt.Errorf("%w: %w", ErrSecretServiceUnavailable, err)
		}
		return fmt.Errorf("keychain set %q: %w", account, err)
	}
	return nil
}

// Get reads the secret stored under Service+account.
func Get(account string) (string, error) {
	v, err := keyring.Get(Service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", fmt.Errorf("%w: %s", ErrNotFound, account)
		}
		if isSecretServiceUnavailableErr(err) {
			return "", fmt.Errorf("%w: %w", ErrSecretServiceUnavailable, err)
		}
		return "", fmt.Errorf("keychain get %q: %w", account, err)
	}
	return v, nil
}

// Delete removes the entry. Idempotent: missing entry returns nil.
func Delete(account string) error {
	err := keyring.Delete(Service, account)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	if isSecretServiceUnavailableErr(err) {
		return fmt.Errorf("%w: %w", ErrSecretServiceUnavailable, err)
	}
	return fmt.Errorf("keychain delete %q: %w", account, err)
}
