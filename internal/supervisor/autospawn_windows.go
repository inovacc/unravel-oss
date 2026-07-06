//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"fmt"
	"os/exec"
	"syscall"
)

// Windows process creation flags. Values match syscall constants but
// duplicated here for clarity (some flags aren't constants in stdlib).
//
// IMPORTANT: DETACHED_PROCESS alone is NOT enough to suppress the conhost.exe
// window for a Go-compiled console-subsystem child — Windows allocates a
// fresh console on first stdin/stdout access. CREATE_NO_WINDOW is the
// load-bearing flag that prevents the console from appearing at all. The
// two flags are documented as mutually exclusive, so we use CREATE_NO_WINDOW
// (which implies detachment from the parent's console) + CREATE_NEW_PROCESS_GROUP
// (so Ctrl-C in the parent terminal doesn't propagate to the daemon).
const (
	createNewProcessGroup = 0x00000200
	createNoWindow        = 0x08000000
)

func detachedExec(execPath string, args ...string) error {
	cmd := exec.Command(execPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: createNewProcessGroup | createNoWindow,
		HideWindow:    true,
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start detached: %w", err)
	}
	if err := cmd.Process.Release(); err != nil {
		return fmt.Errorf("release: %w", err)
	}
	return nil
}
