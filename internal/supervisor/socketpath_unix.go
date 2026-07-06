//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package supervisor

import "path/filepath"

// socketPath returns the UDS socket path for the given socketDir.
func socketPath(socketDir string) string {
	return filepath.Join(socketDir, "daemon.sock")
}
