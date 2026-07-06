//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// socketPath returns the Windows named-pipe path for the given socketDir.
// Named pipes on Windows use the \\.\pipe\<name> namespace — filesystem
// paths are not valid. We derive a stable, user-unique name from socketDir
// using the first 8 hex characters of its SHA-256 hash.
func socketPath(socketDir string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(socketDir)))
	shortHash := fmt.Sprintf("%x", sum[:4])
	return `\\.\pipe\unravel-` + shortHash
}
