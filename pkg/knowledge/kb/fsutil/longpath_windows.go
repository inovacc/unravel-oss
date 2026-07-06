//go:build windows

package fsutil

import "strings"

const longPathThreshold = 247
const longPathPrefix = `\\?\`

// WrapLongPath returns path prefixed with \\?\ when its length exceeds the
// Windows MAX_PATH-style threshold (247). Idempotent: paths already prefixed
// are returned unchanged. UNC paths are not handled in P29 (no \\?\UNC\ form);
// Phase 30 will revisit if shared-store layouts are needed.
func WrapLongPath(path string) string {
	if strings.HasPrefix(path, longPathPrefix) {
		return path
	}
	if len(path) <= longPathThreshold {
		return path
	}
	return longPathPrefix + path
}
