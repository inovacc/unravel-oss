//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"net"
	"os"
	"strconv"
	"testing"
)

// socketPair returns a connected pair of *net.UnixConn via a temp UDS so
// LocalPeerVerifier has a real kernel-backed peer to inspect.
func socketPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	dir := t.TempDir()
	path := dir + "/p.sock"
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	client, err = net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { _ = client.Close(); _ = r.c.Close() })
	return r.c, client
}

func TestLocalPeerVerifier_SameUserOK(t *testing.T) {
	srv, _ := socketPair(t)
	info, err := LocalPeerVerifier(srv)
	if err != nil {
		t.Fatalf("LocalPeerVerifier: %v", err)
	}
	if info.UID != strconv.Itoa(os.Getuid()) {
		t.Fatalf("peer UID = %s, want %d", info.UID, os.Getuid())
	}
}

func TestLocalPeerVerifier_RejectsNonUnixConn(t *testing.T) {
	s, _ := net.Pipe()
	if _, err := LocalPeerVerifier(s); err == nil {
		t.Fatal("expected error for non-unix conn, got nil")
	}
}
