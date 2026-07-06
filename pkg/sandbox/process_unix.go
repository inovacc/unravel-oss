//go:build unix

/*
Copyright (c) 2026 Security Research
*/

package sandbox

import (
	"os/exec"
	"syscall"
)

// configureProcAttr sets up a new process group for cmd so that
// killProcessGroup can SIGKILL the whole tree.
func configureProcAttr(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// killProcessGroup is best-effort: it sends SIGKILL to -pgid (the
// entire process group). Errors are ignored since the process may have
// already exited.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return
	}
	_ = cmd.Process.Kill()
}
