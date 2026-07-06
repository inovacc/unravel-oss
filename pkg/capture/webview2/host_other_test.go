//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"errors"
	"testing"
)

// TestUnsupportedPlatform asserts the non-windows host stub fails loudly:
// every ProcessHost method returns ErrUnsupportedPlatform (the launcher's
// HKCU-env / WM_SETTINGCHANGE / AUMID-broker route is Windows-only, 83-04).
func TestUnsupportedPlatform(t *testing.T) {
	h := newPlatformHost(nil)
	ctx := context.Background()

	if _, err := h.Find(ctx, "x"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Find: want ErrUnsupportedPlatform, got %v", err)
	}
	if err := h.Kill(ctx, 1); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Kill: want ErrUnsupportedPlatform, got %v", err)
	}
	if _, err := h.ResolveExe(ctx, "p"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("ResolveExe: want ErrUnsupportedPlatform, got %v", err)
	}
	if _, err := h.Spawn(ctx, "e", nil, nil); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Spawn: want ErrUnsupportedPlatform, got %v", err)
	}
	if _, err := h.SpawnAUMID(ctx, "a", 9222); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("SpawnAUMID: want ErrUnsupportedPlatform, got %v", err)
	}
	if err := h.CleanupHKCUEnv(ctx); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("CleanupHKCUEnv: want ErrUnsupportedPlatform, got %v", err)
	}

	// NewHost wrapper must dispatch to the same stub on !windows.
	if _, err := NewHost(nil).Find(ctx, "x"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("NewHost->Find: want ErrUnsupportedPlatform, got %v", err)
	}
}
