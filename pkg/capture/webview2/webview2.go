/*
Copyright (c) 2026 Security Research
*/

// Package webview2 owns the lifecycle of a Chrome DevTools Protocol (CDP)
// target — Microsoft Teams Desktop and WhatsApp Desktop on Windows — for the
// no-admin WebView2/UWP user-data capture path. It is a faithful 1:1 port of
// the proven spectra cdpboot technique (83-CONTEXT D-03).
//
// The orchestration is "probe-first, launch-second":
//
//  1. GET http://127.0.0.1:{Port}/json. If reachable and URLContains matches,
//     attach (Spawned=false).
//  2. Otherwise consult the OS via [ProcessHost]. If the target is already
//     running but the port is down, kill silently (unless Target.NoKill)
//     and relaunch.
//  3. Launch the target according to Target.Method:
//     - [MethodDirect] (Teams 2.0): os/exec.Cmd with
//     WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS via Cmd.Env only.
//     - [MethodAUMID] (WhatsApp Desktop, true-UWP): a transient
//     HKCU\Environment set + WM_SETTINGCHANGE broadcast + Start-Process
//     shell:AppsFolder\<AUMID>, paired with mandatory HKCU cleanup on
//     every exit path (success, error, panic).
//  4. Poll /json every PollInterval until LaunchTimeout, with one bounded
//     retry, then an honest *LaunchTimeoutError BLOCK (D-09) — no skip-cdp
//     path, no fabricated success.
//
// Platform: the launcher is Windows only. Non-Windows callers receive
// [ErrUnsupportedPlatform] from [NewHost]'s methods. Probe + presets are
// portable. The Windows HKCU/AUMID host + subcommand are 83-04.
package webview2

import (
	"log/slog"
	"time"
)

// LaunchMethod selects how the target is started. Teams 2.0 is a
// packaged-Win32 binary that respects per-process env (MethodDirect).
// WhatsApp Desktop is true-UWP / AppContainer-confined, so only the COM
// activation broker (shell:AppsFolder) can launch it (MethodAUMID).
type LaunchMethod int

const (
	// MethodDirect launches via os/exec.Cmd with Cmd.Env carrying
	// WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS. Per-process env only.
	MethodDirect LaunchMethod = iota
	// MethodAUMID launches via PowerShell:
	// HKCU\Environment set → WM_SETTINGCHANGE → Start-Process shell:AppsFolder\<AUMID>
	// → mandatory cleanup of the HKCU value.
	MethodAUMID
)

// String renders the method for slog event fields.
func (m LaunchMethod) String() string {
	switch m {
	case MethodDirect:
		return "direct"
	case MethodAUMID:
		return "aumid"
	default:
		return "unknown"
	}
}

// Target describes what CDP endpoint the caller wants reachable.
//
// Kind is the canonical short name ("teams-desktop" | "wa-desktop") and
// indexes into Presets for the OS-level metadata. Method, ExePath, AUMID
// can be left zero — Ensure fills them from the matching preset (D-07).
type Target struct {
	// Kind selects the preset, e.g. "teams-desktop" or "wa-desktop".
	Kind string

	// Port is the CDP remote-debugging port. Zero → Preset.Port.
	Port int

	// Method dispatches the launch path. Zero (MethodDirect) is fine for
	// Teams; for WA the preset overrides to MethodAUMID.
	Method LaunchMethod

	// ExePath is an explicit override for MethodDirect. Empty → Ensure
	// resolves InstallLocation via Preset.PkgName + Preset.ExeBasename.
	ExePath string

	// AUMID is the AppUserModelId for MethodAUMID launches. Zero →
	// Preset.AUMID.
	AUMID string

	// UserDataDir is reserved for future use.
	UserDataDir string

	// URLContains, when non-empty, gates Probe success on at least one
	// /json page target whose `url` contains this substring. Zero →
	// Preset.URLContains.
	URLContains string

	// LaunchTimeout is the total wait-for-port budget after spawn.
	// Zero → 30s.
	LaunchTimeout time.Duration

	// PollInterval is the spacing between /json probes during the
	// wait-for-port loop. Zero → 500ms.
	PollInterval time.Duration

	// NoKill, when true, makes Ensure return ErrTargetRunningWithoutCDP
	// instead of killing+relaunching a target running without CDP.
	NoKill bool

	// Logger is the structured logger Ensure / Probe / host emit through.
	// Nil → slog.Default(). Emits to stderr only.
	Logger *slog.Logger
}

// Attached is what Ensure returns on success.
type Attached struct {
	// BaseURL is the CDP base, e.g. "http://127.0.0.1:9223".
	BaseURL string

	// WebSocketDebugURL is the first matching page target's
	// webSocketDebuggerUrl, gated by URLContains.
	WebSocketDebugURL string

	// Spawned is true if Ensure launched the process; false if the port
	// was already up at first probe.
	Spawned bool

	// PID is the OS process id of the spawned child. Zero if Spawned=false
	// or Method=MethodAUMID (the activation broker detaches).
	PID int
}

// defaults returns t with zero-valued LaunchTimeout / PollInterval / Logger
// filled in. It does NOT mutate the caller's Target.
func (t Target) defaults() Target {
	if t.LaunchTimeout == 0 {
		t.LaunchTimeout = 30 * time.Second
	}
	if t.PollInterval == 0 {
		t.PollInterval = 500 * time.Millisecond
	}
	if t.Logger == nil {
		t.Logger = slog.Default()
	}
	return t
}
