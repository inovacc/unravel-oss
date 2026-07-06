/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
)

// MethodHello is the reserved IPC method for the authenticating handshake.
// It is handled inline by the server BEFORE the verb loop and is never
// registered as a normal verb.
const MethodHello = "sys.hello"

// ProtocolVersion is the IPC handshake protocol version echoed in HelloResponse.
const ProtocolVersion = "1"

// GenerateToken returns a 256-bit capability token, base64url (no padding).
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// PeerInfo is the kernel-verified identity of a connected client. On Windows
// PID may be 0 (best-effort) and UID is the current-user SID string.
type PeerInfo struct {
	UID string
	PID int
}

// PeerVerifier inspects an accepted conn and returns the verified peer
// identity, or an error if the peer is not the same user as the server.
type PeerVerifier func(conn net.Conn) (PeerInfo, error)
