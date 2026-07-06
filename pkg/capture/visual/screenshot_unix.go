//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package visual

// ContentProtected is a stub on non-Windows. macOS detection requires private
// CG APIs (RESEARCH A6); Linux has no equivalent. Returns (false, nil) — the
// caller emits the warning when CDP fallback wasn't used and the captured PNG
// has very low entropy (heuristic deferred to 08-02).
func ContentProtected(hwnd uintptr) (bool, error) { return false, nil }
