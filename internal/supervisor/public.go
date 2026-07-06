/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"os"
	"path/filepath"
)

// SocketPath returns the IPC address (UDS file on POSIX, named pipe on
// Windows) derived from socketDir. Exported wrapper around the
// platform-specific socketPath() so external callers (e.g. MCP tool
// processes) can resolve the supervisor endpoint without depending on
// internal symbols.
func SocketPath(socketDir string) string {
	return socketPath(socketDir)
}

// DefaultSocketDir returns the platform-appropriate directory that
// holds the supervisor's daemon.sock + server.json + spawn-history.json.
// Mirrors internal/server/daemon.go::defaultDataDir() so MCP tool
// processes resolve the same location as the daemon binary.
//
// The directory is created with 0700 so the UDS it contains is not
// exposed through a world-listable parent. MkdirAll is a no-op when the
// directory already exists (it does not relax existing permissions, so
// callers that need to harden a pre-existing dir should chmod separately).
func DefaultSocketDir() string {
	var dir string
	if local := os.Getenv("LOCALAPPDATA"); local != "" {
		dir = filepath.Join(local, "Unravel")
	} else {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "share", "unravel")
	}
	// Best-effort: ensure the dir exists with owner-only perms. Errors are
	// non-fatal here (the caller will surface a clearer error when it tries
	// to bind/open the socket), so we deliberately ignore the return.
	_ = os.MkdirAll(dir, 0o700)
	return dir
}
