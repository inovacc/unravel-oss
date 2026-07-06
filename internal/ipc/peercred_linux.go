//go:build linux

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"fmt"
	"net"
	"strconv"

	"golang.org/x/sys/unix"
)

// LocalPeerVerifier reads SO_PEERCRED on a UDS conn and asserts the peer's
// UID equals the server's UID. Returns the verified UID + PID for audit.
func LocalPeerVerifier(conn net.Conn) (PeerInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerInfo{}, fmt.Errorf("peercred: conn is %T, not *net.UnixConn", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerInfo{}, fmt.Errorf("peercred: syscall conn: %w", err)
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return PeerInfo{}, fmt.Errorf("peercred: control: %w", err)
	}
	if cerr != nil {
		return PeerInfo{}, fmt.Errorf("peercred: getsockopt: %w", cerr)
	}
	self := unix.Getuid()
	if int(cred.Uid) != self {
		return PeerInfo{}, fmt.Errorf("peercred: peer uid %d != server uid %d", cred.Uid, self)
	}
	return PeerInfo{UID: strconv.Itoa(int(cred.Uid)), PID: int(cred.Pid)}, nil
}
