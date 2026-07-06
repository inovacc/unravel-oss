//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package lifecycle

import (
	"errors"
	"os"
	"syscall"
)

// ProcessAlive (Unix): probe via signal 0. The kernel returns ESRCH for
// dead PIDs, EPERM for live-but-foreign-uid PIDs (treated as alive), nil
// for live-and-owned. We treat anything other than ErrProcessDone +
// explicit ESRCH as alive to match the Windows fallback semantics.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	if errors.Is(err, os.ErrProcessDone) {
		return false
	}
	if errors.Is(err, syscall.ESRCH) {
		return false
	}
	// EPERM and other errnos imply the process exists but we cannot
	// signal it — alive.
	return true
}
