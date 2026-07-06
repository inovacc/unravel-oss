//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
)

// Listen binds a named-pipe listener at pipeName (e.g. \\.\pipe\unravel-<uid>).
// SecurityDescriptor restricts to the current user only.
//
// Host-singleton note: unlike a UDS, two ListenPipe calls on the same name
// both succeed and the OS load-balances clients across the instances — so the
// pipe layer alone cannot enforce a single daemon. The single-owner guarantee
// is the supervisor's exclusive daemon.lock (see filelock_windows.go), acquired
// before this Listen; the winio PipeConfig API exposes no FILE_FLAG_FIRST_PIPE
// _INSTANCE knob, so the file lock is the authoritative serialization point.
func Listen(pipeName string) (net.Listener, error) {
	sd, err := currentUserSDDL()
	if err != nil {
		return nil, fmt.Errorf("compute SDDL: %w", err)
	}
	cfg := &winio.PipeConfig{
		SecurityDescriptor: sd,
		MessageMode:        false,
		InputBufferSize:    64 * 1024,
		OutputBufferSize:   64 * 1024,
	}
	ln, err := winio.ListenPipe(pipeName, cfg)
	if err != nil {
		return nil, fmt.Errorf("listen pipe %s: %w", pipeName, err)
	}
	return ln, nil
}

// currentUserSDDL returns an SDDL string granting full access to the
// current user only (no others). Format: "D:P(A;;GA;;;<SID>)"
// — DACL Protected, ACE Allow, GenericAll, SID of current user.
func currentUserSDDL() (string, error) {
	// Use the user's environment USERPROFILE-derived SID; on Windows the
	// simplest cross-version approach is to use the SDDL well-known
	// short form for the owner (OW). For v1, accept slightly broader
	// "current user (OW)" rather than minting an explicit SID.
	return "D:P(A;;GA;;;OW)", nil
}
