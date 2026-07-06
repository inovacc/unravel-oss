//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package lifecycle

import (
	"golang.org/x/sys/windows"
)

// ProcessAlive (Windows): OpenProcess with SYNCHRONIZE rights, then poll
// the handle with WaitForSingleObject(0). WAIT_TIMEOUT means the
// process is still running; WAIT_OBJECT_0 means it has exited and the
// kernel is just waiting for the last handle to close. Anything else
// (OpenProcess failure, handle exhaustion) is treated as "dead" so the
// caller falls into its cleanup path.
//
// Why not Signal(0)? On Windows, os.Process.Signal returns syscall.EWINDOWS
// for any non-Kill signal when the process is still alive, but
// os.ErrProcessDone only after Wait() has been called on that specific
// *Process. Since the watcher creates a fresh FindProcess handle per
// poll, done() is never set and dead processes look alive — the bug
// this implementation fixes.
func ProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	s, err := windows.WaitForSingleObject(h, 0)
	if err != nil {
		return false
	}
	return s == uint32(windows.WAIT_TIMEOUT)
}
