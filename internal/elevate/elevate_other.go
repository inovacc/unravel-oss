//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package elevate

// IsElevated returns false on non-Windows platforms. Callers that care about
// privilege escalation on Linux/macOS should check euid==0 themselves; this
// package's contract is Windows UAC only.
func IsElevated() bool { return false }

// ReExec returns ErrNotSupported on non-Windows platforms. Callers should
// fall back to printing a sudo-style instruction or fail.
func ReExec(reason string) error { return ErrNotSupported }

// EnsureReadable is a no-op on non-Windows platforms — POSIX permission
// errors surface naturally via os.Open; the caller decides whether to abort
// or continue with degraded scope.
func EnsureReadable(path, reason string, optional bool) error { return nil }

// ElevateChildFlag is the hidden CLI flag that would be injected into a
// re-launched elevated process on Windows. On non-Windows platforms it is
// defined for compilation compatibility but will never appear in os.Args
// because ReExec returns ErrNotSupported.
const ElevateChildFlag = "--__elevate-child"
