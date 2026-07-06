//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"fmt"
	"os"
	"syscall"
)

// WriteTokenFile writes the token to path as a 0600 file. Forces a
// restrictive umask around the create so the node is never world/group
// readable even briefly, then re-asserts 0600 (mirrors listen_posix.go).
func WriteTokenFile(path, token string) error {
	oldMask := syscall.Umask(0o177)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("create token file %s: %w", path, err)
	}
	if _, err := f.WriteString(token); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write token file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close token file %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod token file %s: %w", path, err)
	}
	return nil
}
