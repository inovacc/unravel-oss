/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// newTestClient constructs a minimal Client suitable for handler-driven tests
// (no real WebSocket connection). The handlers map is initialised so OnEvent
// behaves as in production.
func newTestClient() *Client {
	return &Client{
		handlers: make(map[string]func(json.RawMessage)),
		pending:  make(map[int64]chan rpcResponse),
	}
}

func TestSubscribeWebSocketFrames_NilClient(t *testing.T) {
	if _, err := SubscribeWebSocketFrames(context.Background(), nil); err == nil {
		t.Fatal("expected error on nil client")
	}
}

func TestSubscribeWebSocketFrames_RegistersHandlers(t *testing.T) {
	c := newTestClient()
	ctx := t.Context()
	if _, err := SubscribeWebSocketFrames(ctx, c); err != nil {
		t.Fatalf("SubscribeWebSocketFrames: %v", err)
	}
	if _, ok := c.handlers["Network.webSocketFrameSent"]; !ok {
		t.Error("Sent handler not registered")
	}
	if _, ok := c.handlers["Network.webSocketFrameReceived"]; !ok {
		t.Error("Received handler not registered")
	}
}

func TestSubscribeWebSocketFrames_EmitsFrames(t *testing.T) {
	c := newTestClient()
	ctx := t.Context()
	ch, err := SubscribeWebSocketFrames(ctx, c)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	// Simulate a CDP event by directly invoking the registered handler with
	// a realistic params payload.
	sentParams := json.RawMessage(`{"requestId":"r1","timestamp":1.234,"response":{"opcode":1,"payloadData":"hello"}}`)
	c.handlers["Network.webSocketFrameSent"](sentParams)

	recvParams := json.RawMessage(`{"requestId":"r1","timestamp":1.235,"response":{"opcode":2,"payloadData":"abcdefgh"}}`)
	c.handlers["Network.webSocketFrameReceived"](recvParams)

	got := drain(t, ch, 2, 200*time.Millisecond)
	if len(got) != 2 {
		t.Fatalf("want 2 frames, got %d", len(got))
	}
	if got[0].Direction != "sent" || got[0].OpCode != 1 || got[0].PayloadLen != len("hello") {
		t.Errorf("sent frame mismatch: %+v", got[0])
	}
	if got[1].Direction != "received" || got[1].OpCode != 2 || got[1].PayloadLen != len("abcdefgh") {
		t.Errorf("received frame mismatch: %+v", got[1])
	}
}

func TestSubscribeWebSocketFrames_BadJSONIgnored(t *testing.T) {
	c := newTestClient()
	ctx := t.Context()
	ch, err := SubscribeWebSocketFrames(ctx, c)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	c.handlers["Network.webSocketFrameSent"](json.RawMessage(`not-json`))
	select {
	case f := <-ch:
		t.Fatalf("expected no frame for bad JSON, got %+v", f)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestSubscribeWebSocketFrames_CtxCancelClosesChannel(t *testing.T) {
	c := newTestClient()
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := SubscribeWebSocketFrames(ctx, c)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			// allow a single buffered frame to flush before close
		}
		// drain until close
		for range ch {
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("channel did not close after ctx cancel")
	}
}

func drain(t *testing.T, ch <-chan WSFrame, n int, d time.Duration) []WSFrame {
	t.Helper()
	out := make([]WSFrame, 0, n)
	deadline := time.After(d)
	for len(out) < n {
		select {
		case f, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, f)
		case <-deadline:
			return out
		}
	}
	return out
}
