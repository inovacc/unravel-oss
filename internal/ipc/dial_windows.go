//go:build windows

/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
)

// Dial connects to the named pipe at pipeName, honoring ctx deadline.
// If ctx has no deadline, defaults to 5 seconds.
func Dial(ctx context.Context, pipeName string) (net.Conn, error) {
	var timeout time.Duration
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := winio.DialPipe(pipeName, &timeout)
	if err != nil {
		return nil, fmt.Errorf("dial pipe %s: %w", pipeName, err)
	}
	return conn, nil
}
