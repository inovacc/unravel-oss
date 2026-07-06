//go:build !windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"context"
	"fmt"
	"net"
)

// Dial connects to the UDS at socketPath, honoring ctx deadline/cancel.
func Dial(ctx context.Context, socketPath string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial unix %s: %w", socketPath, err)
	}
	return conn, nil
}
