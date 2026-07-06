//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package sandbox

import "os/exec"

// configureProcAttr is a no-op on Windows for v2.4. Future work could
// attach the child to a Job Object for tree termination (BACKLOG).
func configureProcAttr(cmd *exec.Cmd) {}

// killProcessGroup uses cmd.Process.Kill which terminates the immediate
// process. Renderer subprocesses spawned by Electron/Tauri/WebView2
// hosts will exit when their parent closes. Best-effort per D-13;
// full Job Object integration is BACKLOG for v2.5+.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
