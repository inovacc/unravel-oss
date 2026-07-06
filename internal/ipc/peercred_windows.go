//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"net"
	"os/user"
)

// LocalPeerVerifier on Windows relies on the named pipe's owner-only SDDL
// (D:P(A;;GA;;;OW) in listen_windows.go), which the kernel already enforces:
// only the current user can open the pipe, so any accepted conn is same-user
// by construction. We therefore return OK with the current user's SID and a
// best-effort PID of 0. (Optional future hardening: GetNamedPipeClientProcessId
// for a verified peer PID in the audit log — see spec section 3.)
func LocalPeerVerifier(conn net.Conn) (PeerInfo, error) {
	u, err := user.Current()
	if err != nil {
		return PeerInfo{UID: "", PID: 0}, nil //nolint:nilerr // SDDL already enforced same-user; UID is audit-only
	}
	return PeerInfo{UID: u.Uid, PID: 0}, nil
}
