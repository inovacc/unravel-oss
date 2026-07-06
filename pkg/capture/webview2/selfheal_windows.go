//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"fmt"
	"log/slog"
)

// SelfHeal implements D-05: on launcher start, if a prior run was killed
// before its deferred D-04 CleanupHKCUEnv could fire, an unravel-tagged
// stale value is left in HKCU\Environment. Detect it and idempotently
// revert (delete + re-broadcast WM_SETTINGCHANGE) BEFORE proceeding.
//
// Only a value that EXACTLY matches the form this launcher writes
// (isUnravelTaggedValue: --remote-debugging-port= prefix AND
// --remote-allow-origins=* present) is touched. An absent value, or an
// operator-set value that does not match our tag, is left untouched.
// Pure-Go registry (no PowerShell). Idempotent on repeat calls.
func SelfHeal(ctx context.Context, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	h, ok := NewHost(logger).(*windowsHost)
	if !ok {
		// Non-Windows builds never reach here (build-tagged file), but be
		// defensive: nothing to heal.
		return nil
	}
	return selfHealWith(ctx, logger, h.reg, h.broadcast)
}

// selfHealWith is the unit-test seam — tests inject a fakeRegistry +
// no-op broadcast (host_windows_test.go un-skipped TestSelfHeal).
func selfHealWith(_ context.Context, logger *slog.Logger, reg envRegistry, broadcast broadcastFn) error {
	cur, present, err := reg.Get()
	if err != nil {
		return fmt.Errorf("webview2/windows: self-heal read HKCU env: %w", err)
	}
	if !present {
		return nil // nothing to heal
	}
	if !isUnravelTaggedValue(cur) {
		// Operator-set value — never touch it.
		logger.Debug("webview2.selfheal.skip_operator_value")
		return nil
	}
	logger.Warn("webview2.selfheal.stale_value_detected",
		"value_name", hkcuEnvValueName,
		"action", "reverting stale unravel-tagged HKCU env")
	if derr := reg.Delete(); derr != nil {
		return fmt.Errorf("webview2/windows: self-heal delete stale value: %w", derr)
	}
	if broadcast != nil {
		if berr := broadcast(); berr != nil {
			logger.Warn("webview2.selfheal.broadcast", "err", berr.Error())
		}
	}
	return nil
}
