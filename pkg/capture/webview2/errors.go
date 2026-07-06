/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors. Use errors.Is to match (per CLAUDE.md).
var (
	// ErrPortDown signals the /json probe failed (no listener, non-200,
	// or unparseable body). Wrapped with the underlying detail.
	ErrPortDown = errors.New("webview2: cdp port not reachable")

	// ErrTargetRunningWithoutCDP is returned when the target exe is
	// already running but the CDP port is down and Target.NoKill=true
	// (T-83-03-02).
	ErrTargetRunningWithoutCDP = errors.New("webview2: target running without CDP arg; --no-kill prevented relaunch")

	// ErrUnsupportedPlatform is what every ProcessHost method returns on
	// non-Windows builds.
	ErrUnsupportedPlatform = errors.New("webview2: unsupported platform (Windows only)")

	// ErrCDPLaunchTimeout is the umbrella sentinel that LaunchTimeoutError
	// unwraps to. errors.Is(err, ErrCDPLaunchTimeout) is the caller-facing
	// honest-BLOCK check (D-09).
	ErrCDPLaunchTimeout = errors.New("webview2: cdp launch timeout")

	// ErrUWPLaunch wraps PowerShell / shell:AppsFolder failures on the
	// MethodAUMID path, before the wait-for-port loop began.
	ErrUWPLaunch = errors.New("webview2: uwp launch failed")

	// ErrNoMatchingTarget signals /json was reachable and parseable but no
	// page target's `url` contained Target.URLContains. Unwraps to
	// ErrPortDown so the wait-for-port loop keeps retrying naturally.
	ErrNoMatchingTarget = &noMatchingTargetSentinel{}
)

// noMatchingTargetSentinel is the concrete type behind ErrNoMatchingTarget.
// Its Unwrap returns ErrPortDown so errors.Is(err, ErrPortDown) succeeds.
type noMatchingTargetSentinel struct{}

func (*noMatchingTargetSentinel) Error() string { return "webview2: no target url matched" }
func (*noMatchingTargetSentinel) Unwrap() error { return ErrPortDown }

// LaunchTimeoutError carries structured detail about a wait-for-port
// timeout — the D-09 honest BLOCK. Unwraps to ErrCDPLaunchTimeout.
type LaunchTimeoutError struct {
	Kind    string
	Port    int
	ExePath string
	Elapsed time.Duration
	LastErr error
}

// Error formats the timeout with captured failure evidence (D-08/D-09).
func (e *LaunchTimeoutError) Error() string {
	return fmt.Sprintf("cdp launch timeout: %s did not expose port %d within %s (last probe: %v)",
		e.Kind, e.Port, e.Elapsed, e.LastErr)
}

// Unwrap lets errors.Is match the sentinel.
func (e *LaunchTimeoutError) Unwrap() error { return ErrCDPLaunchTimeout }
