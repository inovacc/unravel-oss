//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"fmt"
	"os/exec"
	"syscall"
)

// detachedExec launches execPath as a detached background process
// (sets a new session via Setsid so it reparents to PID 1 when the
// parent exits).
func detachedExec(execPath string, args ...string) error {
	cmd := exec.Command(execPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start detached: %w", err)
	}
	// Release the process so the parent doesn't block in Wait.
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	return nil
}
