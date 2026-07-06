//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen binds a UDS listener at socketPath. Removes a stale socket
// file if present. Single-daemon ownership is enforced upstream by the
// supervisor's exclusive daemon.lock (see filelock_unix.go), acquired
// before Listen — so by the time we os.Remove + rebind here, no live peer
// holds the path and the remove cannot hijack another daemon's listener.
//
// Security: the socket must never be world-accessible, even briefly.
// net.Listen("unix", …) creates the socket honouring the process umask,
// so there is a TOCTOU window between bind and a later Chmod where the
// node could be 0777 & ~umask. We close that window by (1) hardening the
// parent directory to 0700 (defence in depth — see supervisor.DefaultSocketDir)
// and (2) forcing the umask to 0177 around the bind so the socket is
// created 0600 atomically. A post-bind Chmod re-asserts 0600 in case the
// platform ignores umask for sockets.
func Listen(socketPath string) (net.Listener, error) {
	// Defence in depth: ensure the containing directory is owner-only.
	if dir := filepath.Dir(socketPath); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
		_ = os.Chmod(dir, 0o700)
	}

	_ = os.Remove(socketPath)

	// Force a restrictive umask so the socket node is created 0600,
	// eliminating the world-accessible TOCTOU window. Restore afterwards.
	oldMask := syscall.Umask(0o177)
	ln, err := net.Listen("unix", socketPath)
	syscall.Umask(oldMask)
	if err != nil {
		return nil, fmt.Errorf("listen unix %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", socketPath, err)
	}
	return ln, nil
}
