//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"log/slog"
)

// SelfHeal is a no-op on non-Windows builds: the HKCU\Environment leak
// (D-05) can only exist on Windows, so there is nothing to heal. Provided
// so cross-platform callers (root PersistentPreRunE) can invoke it
// unconditionally and early without build tags (CR-01).
func SelfHeal(_ context.Context, _ *slog.Logger) error {
	return nil
}
