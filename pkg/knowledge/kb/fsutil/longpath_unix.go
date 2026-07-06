//go:build !windows

package fsutil

// WrapLongPath is a no-op on POSIX systems.
func WrapLongPath(path string) string { return path }
