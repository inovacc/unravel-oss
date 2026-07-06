/*
Copyright (c) 2026 Security Research
*/

// Package cdp — webSocketFrame event subscription helper (P57-02).
//
// CDP exposes Network.webSocketFrameSent and Network.webSocketFrameReceived
// events; this file wraps Client.OnEvent into a typed channel so consumers
// (P57 dispatcher) can drain frames without writing per-event JSON parsing.
//
// SubscribeWebSocketFrames registers handlers for both Sent and Received
// methods and returns a channel that closes when ctx is cancelled. The
// caller MUST have already enabled the Network domain on the connected
// Client (e.g. via Client.ConnectAndAttach which does this via SendAndWait,
// or via Client.EnableDomains for the multi-domain case) — this function
// does NOT send Network.enable. Payload bytes are NOT stored — only
// direction, opcode, payload length, and timestamp (T-57-02).
package cdp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// WSFrame is the typed surface returned by SubscribeWebSocketFrames. Direction
// is "sent" or "received". OpCode follows RFC 6455 (1=text, 2=binary, 8=close,
// 9=ping, 10=pong). PayloadLen is the byte length of the frame payload as
// reported by CDP; the payload itself is intentionally NOT retained.
type WSFrame struct {
	Direction  string    `json:"direction"`
	OpCode     int       `json:"opcode"`
	PayloadLen int       `json:"payload_len"`
	TS         time.Time `json:"ts"`
}

// cdpFrameEnvelope mirrors the params shape of Network.webSocketFrame{Sent,Received}.
// We only decode what we keep (T-57-02 — no payload bytes retained beyond length).
type cdpFrameEnvelope struct {
	RequestID string `json:"requestId"`
	// Timestamp is intentionally omitted: CDP sends a float seconds-since-epoch
	// here and we use time.Now() for our own monotonic ordering anyway.
	Response struct {
		Opcode     int    `json:"opcode"`
		PayloadStr string `json:"payloadData"`
	} `json:"response"`
}

// WSFrameWithPayload mirrors WSFrame but additionally carries the raw payload
// bytes captured from CDP. Added in P64-05 to support the frames.ndjson
// sidecar (payload_hash + payload_truncated columns; T-64-04 mitigation).
//
// T-57-02 acceptance is preserved on the existing WSFrame surface; callers
// that need payload bytes opt in via SubscribeWebSocketFramesWithPayload.
// Per T-64-05, payload retention here matches the existing v2.10 sidecar
// disclosure policy (truncated to first 256 bytes by the consumer).
type WSFrameWithPayload struct {
	WSFrame
	Masked  bool
	Payload []byte
}

// SubscribeWebSocketFramesWithPayload is the payload-bearing variant of
// SubscribeWebSocketFrames. Buffer size is 256; frames are dropped on
// overflow rather than blocking the CDP listen loop.
func SubscribeWebSocketFramesWithPayload(ctx context.Context, c *Client) (<-chan WSFrameWithPayload, error) {
	if c == nil {
		return nil, fmt.Errorf("cdp: nil client")
	}
	out := make(chan WSFrameWithPayload, 256)
	// closedMu serializes send-vs-close; closed flag is the canonical
	// "channel closed" indicator checked by emit before any send.
	var closedMu sync.Mutex
	closed := false
	closeCh := func() {
		closedMu.Lock()
		if !closed {
			closed = true
			close(out)
		}
		closedMu.Unlock()
	}

	emit := func(direction string) func(json.RawMessage) {
		return func(params json.RawMessage) {
			var env cdpFrameEnvelope
			if err := json.Unmarshal(params, &env); err != nil {
				return
			}
			payload := []byte(env.Response.PayloadStr)
			frame := WSFrameWithPayload{
				WSFrame: WSFrame{
					Direction:  direction,
					OpCode:     env.Response.Opcode,
					PayloadLen: len(payload),
					TS:         time.Now().UTC(),
				},
				Payload: payload,
			}
			closedMu.Lock()
			if closed {
				closedMu.Unlock()
				return
			}
			select {
			case out <- frame:
			default:
				// drop on overflow — listen loop must not block
			}
			closedMu.Unlock()
		}
	}

	c.OnEvent("Network.webSocketFrameSent", emit("sent"))
	c.OnEvent("Network.webSocketFrameReceived", emit("received"))

	go func() {
		<-ctx.Done()
		closeCh()
	}()

	return out, nil
}

// SubscribeWebSocketFrames registers handlers for Network.webSocketFrameSent
// and Network.webSocketFrameReceived on c, returning a channel of WSFrame
// records. The channel is closed when ctx is cancelled. Buffer size is 256;
// frames are dropped on overflow rather than blocking the CDP listen loop.
//
// Caller is responsible for calling Network.enable separately if domains
// haven't already been enabled (Client.EnableDomains already covers this).
func SubscribeWebSocketFrames(ctx context.Context, c *Client) (<-chan WSFrame, error) {
	if c == nil {
		return nil, fmt.Errorf("cdp: nil client")
	}

	out := make(chan WSFrame, 256)
	var closeOnce sync.Once
	closeCh := func() { closeOnce.Do(func() { close(out) }) }

	emit := func(direction string) func(json.RawMessage) {
		return func(params json.RawMessage) {
			var env cdpFrameEnvelope
			if err := json.Unmarshal(params, &env); err != nil {
				return
			}
			frame := WSFrame{
				Direction:  direction,
				OpCode:     env.Response.Opcode,
				PayloadLen: len(env.Response.PayloadStr),
				TS:         time.Now().UTC(),
			}
			select {
			case out <- frame:
			default:
				// drop on overflow — listen loop must not block
			}
		}
	}

	c.OnEvent("Network.webSocketFrameSent", emit("sent"))
	c.OnEvent("Network.webSocketFrameReceived", emit("received"))

	go func() {
		<-ctx.Done()
		closeCh()
	}()

	return out, nil
}
