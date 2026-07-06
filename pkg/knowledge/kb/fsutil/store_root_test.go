package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKBStoreRoot_EnvOverride(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "custom-store")
	t.Setenv(envKBStore, abs)
	got, err := KBStoreRoot()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != abs {
		t.Fatalf("got %q want %q", got, abs)
	}
}

func TestKBStoreRoot_DefaultUnderHome(t *testing.T) {
	t.Setenv(envKBStore, "")
	// Clear LOCALAPPDATA so the home fallback (resolution step 3) is exercised
	// deterministically on every OS; otherwise on Windows the LOCALAPPDATA
	// branch (step 2) wins and this assertion would not hold.
	t.Setenv("LOCALAPPDATA", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("os.UserHomeDir failed: %v", err)
	}
	got, err := KBStoreRoot()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := filepath.Join(home, "unravel", "kb-store")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestKBStoreRoot_LocalAppData(t *testing.T) {
	t.Setenv(envKBStore, "")
	local := filepath.Join(t.TempDir(), "AppData", "Local")
	t.Setenv("LOCALAPPDATA", local)
	got, err := KBStoreRoot()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := filepath.Join(local, "Unravel", "kb-store")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestKBStoreRoot_RejectsRelative(t *testing.T) {
	t.Setenv(envKBStore, "./bad")
	_, err := KBStoreRoot()
	if err == nil {
		t.Fatalf("expected error for relative path")
	}
	if !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected error to mention 'absolute', got %v", err)
	}
}
