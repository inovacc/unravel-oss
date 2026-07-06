/*
Copyright (c) 2026 Security Research
*/

package cdp

import (
	"context"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// TestListenNilConnDoesNotPanic is the deterministic regression repro for the
// Phase-83 Test-2 panic (.planning/debug/wa-cdp-listen-nil-conn-panic.md).
//
// Root cause: cmd/capture_webview2_attach.go spawns the Listen goroutine BEFORE
// ConnectAndAttach dials the websocket, so c.conn is nil when Listen calls
// c.conn.ReadMessage() -> panic websocket.(*Conn).NextReader(0x0).
//
// BEFORE FIX: this test panics (nil pointer deref) — RED.
// AFTER FIX (Listen nil-conn readiness guard + typed error): Listen returns a
// non-nil error within the context deadline and does NOT panic — GREEN.
func TestListenNilConnDoesNotPanic(t *testing.T) {
	cli := New("127.0.0.1:9222", make(chan capture.Event, 8), func() int { return 1 })

	// Never call Connect/ConnectAndAttach: c.conn stays nil, exactly as it is
	// when the cmd goroutine wins the race against the dialer handshake.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- &panicErr{r}
			}
		}()
		done <- cli.Listen(ctx)
	}()

	select {
	case err := <-done:
		if pe, ok := err.(*panicErr); ok {
			t.Fatalf("Listen panicked on nil conn (RED — fix not yet applied): %v", pe.v)
		}
		if err == nil {
			t.Fatalf("Listen returned nil on nil conn; expected a typed error so the caller can emit an honest D-09 BLOCK")
		}
		// GREEN: graceful typed error, no panic.
	case <-time.After(5 * time.Second):
		t.Fatalf("Listen did not return within deadline on nil conn (hung)")
	}
}

type panicErr struct{ v any }

func (e *panicErr) Error() string { return "panic" }
