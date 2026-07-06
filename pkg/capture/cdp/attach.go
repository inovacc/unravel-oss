/*
Copyright (c) 2026 Security Research
*/

package cdp

import (
	"context"
	"fmt"
)

// ConnectAndAttach dials a target's webSocketDebuggerUrl and sends
// Network.enable via SendAndWait so we surface protocol errors before the
// caller subscribes to frame events.
//
// IMPORTANT: SendAndWait blocks until the response is demultiplexed by
// Client.dispatchFrame which runs inside Client.Listen. The caller MUST
// spawn Listen BEFORE invoking ConnectAndAttach (or this method will
// deadlock until ctx expires). For the canonical orchestration sequence
// see pkg/knowledge/scorecard/cdp_source.go which uses Connect + spawn
// Listen + SendAndWait directly to keep the ordering explicit.
//
// Caller is responsible for calling Close when done.
//
// This is the canonical "page-target attach" recipe used by P63's
// pkg/knowledge/scorecard/cdp_source.go (composed-primitives orchestration).
// Mirrors the .scripts/cdp-capture.py reference: connect → Network.enable.
// Page.enable is intentionally NOT sent here — it is not required for
// Network.webSocketFrame{Sent,Received} events to fire and adding it would
// surprise other callers that don't need page lifecycle events.
func (c *Client) ConnectAndAttach(ctx context.Context, t Target) error {
	if t.WebSocketDebugURL == "" {
		return fmt.Errorf("cdp: target %s has no webSocketDebuggerUrl", t.ID)
	}
	if err := c.Connect(ctx, t.WebSocketDebugURL); err != nil {
		return err
	}
	if _, err := c.SendAndWait(ctx, "Network.enable", nil); err != nil {
		return fmt.Errorf("cdp: Network.enable: %w", err)
	}
	return nil
}
