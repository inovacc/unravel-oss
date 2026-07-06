//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package analyze

// detectEvergreen is a no-op on non-Windows (registry-only concept).
func detectEvergreen() (RuntimeInfo, bool) {
	return RuntimeInfo{}, false
}
