/*
Copyright (c) 2026 Security Research
*/

// Package elevate provides cross-platform privilege-escalation helpers. On
// Windows, EnsureReadable and ReExec re-launch the current process under
// UAC when a target path requires Administrator access (e.g. anything under
// C:\Program Files\WindowsApps). On non-Windows platforms the helpers are
// no-ops — callers must handle EACCES themselves.
//
// Opt-in only: nothing in this package fires unless a caller explicitly
// invokes EnsureReadable or ReExec. There is no global hook.
package elevate

import "errors"

// ErrNotSupported is returned by ReExec on non-Windows platforms.
var ErrNotSupported = errors.New("elevate: not supported on this platform")

// ErrAlreadyElevated is returned by ReExec when the current process is
// already running with Administrator privileges.
var ErrAlreadyElevated = errors.New("elevate: already running elevated")

// ErrUserDeclined is returned by ReExec when the UAC prompt was dismissed.
// On Windows this surfaces as a ShellExecute return value of 5 (access
// denied) or 1223 (operation cancelled by user).
var ErrUserDeclined = errors.New("elevate: user declined UAC prompt")
