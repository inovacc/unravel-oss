package keychain

import (
	"errors"
	"strings"
	"testing"
)

// Constants are FROZEN per ADR; this test fails loudly if anyone renames
// them — orphan secrets on user machines is the failure mode we are
// preventing.
func TestFrozenServiceAndAccountNames(t *testing.T) {
	if Service != "unravel" {
		t.Fatalf("Service renamed (FROZEN): got %q", Service)
	}
	if AccountDBPassword != "db-password" {
		t.Fatalf("AccountDBPassword renamed (FROZEN): got %q", AccountDBPassword)
	}
	if AccountEncryptionKey != "db-encryption-key" {
		t.Fatalf("AccountEncryptionKey renamed (FROZEN): got %q", AccountEncryptionKey)
	}
}

// IsSecretServiceUnavailable should follow errors.Is wrapping conventions.
func TestIsSecretServiceUnavailable(t *testing.T) {
	if IsSecretServiceUnavailable(nil) {
		t.Fatal("nil should not be unavailable")
	}
	if !IsSecretServiceUnavailable(ErrSecretServiceUnavailable) {
		t.Fatal("sentinel should match itself")
	}
	wrapped := errors.New("wrap: " + ErrSecretServiceUnavailable.Error())
	if IsSecretServiceUnavailable(wrapped) {
		t.Fatal("plain string-wrap should NOT match (errors.Is requires Unwrap chain)")
	}
}

// isSecretServiceUnavailableErr is the message-pattern fallback used when
// the underlying go-keyring error doesn't surface a typed sentinel.
func TestIsSecretServiceUnavailableErr(t *testing.T) {
	cases := map[string]bool{
		"":                             false,
		"random failure":               false,
		"Secret Service Unavailable":   true,
		"dbus: connection refused":     true,
		"no such interface":            true,
		"the service is not available": true,
	}
	for msg, want := range cases {
		got := isSecretServiceUnavailableErr(errors.New(msg))
		if msg == "" {
			got = isSecretServiceUnavailableErr(nil)
		}
		if got != want {
			t.Errorf("msg=%q got=%v want=%v", msg, got, want)
		}
	}
}

// Get / Set / Delete on a real backend would be flaky in CI, so just
// verify the typed sentinels surface for unknown accounts when the
// keychain backend exists. Skip when the backend is unavailable.
func TestGetUnknownAccountReturnsNotFound(t *testing.T) {
	const probeAccount = "unravel-test-probe-account-deadbeef"
	_, err := Get(probeAccount)
	if err == nil {
		t.Skip("entry exists from prior run; cleanup not implemented")
	}
	if errors.Is(err, ErrSecretServiceUnavailable) {
		t.Skip("keychain backend unavailable; skipping live test")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), probeAccount) {
		t.Fatalf("error should mention account: %v", err)
	}
}

// TestDelete_RoundTrip locks the cleanup primitive used to wipe the legacy
// db-password mirror: Set then Delete then Get must report ErrNotFound, and a
// second Delete (absent entry) must be a no-op. Skip-guarded for headless CI.
func TestDelete_RoundTrip(t *testing.T) {
	const probe = "unravel-test-delete-probe-deadbeef"
	if err := Set(probe, "secret"); err != nil {
		if errors.Is(err, ErrSecretServiceUnavailable) {
			t.Skip("keychain backend unavailable; skipping live test")
		}
		t.Fatalf("Set: %v", err)
	}
	if err := Delete(probe); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := Get(probe); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after Delete, Get = %v, want ErrNotFound", err)
	}
	if err := Delete(probe); err != nil {
		t.Fatalf("Delete (absent) = %v, want nil", err)
	}
}
