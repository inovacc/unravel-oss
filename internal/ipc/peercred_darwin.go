//go:build darwin

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

// LocalPeerVerifier reads LOCAL_PEERCRED (getpeereid) on a UDS conn and
// asserts the peer's effective UID equals the server's UID. Darwin's
// xucred carries no PID, so PID is reported as 0.
func LocalPeerVerifier(conn net.Conn) (PeerInfo, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return PeerInfo{}, fmt.Errorf("peercred: conn is %T, not *net.UnixConn", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return PeerInfo{}, fmt.Errorf("peercred: syscall conn: %w", err)
	}
	var xucred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		xucred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return PeerInfo{}, fmt.Errorf("peercred: control: %w", err)
	}
	if cerr != nil {
		return PeerInfo{}, fmt.Errorf("peercred: getsockopt: %w", cerr)
	}
	self := unix.Getuid()
	if int(xucred.Uid) != self {
		return PeerInfo{}, fmt.Errorf("peercred: peer uid %d != server uid %d", xucred.Uid, self)
	}
	return PeerInfo{UID: strconv.Itoa(int(xucred.Uid)), PID: 0}, nil
}
