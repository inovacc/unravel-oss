/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — production CDP frame source (P63).
//
// cdpFrameSource is the production implementation of the unexported
// frameSource interface (defined in dispatch.go). It is wired into
// defaultFrameSourceFactory via SetFrameSourceFactory (factory.go) by
// cmd/knowledge.go when --cdp-port is non-zero. The default factory remains
// noopFrameSource{} so static-only / no-CDP runs do not regress.
//
// Composes existing pkg/capture/cdp primitives (NOT a reimplementation of
// the WS lifecycle): DiscoverTargets → page-type filter → ConnectAndAttach
// (Connect + Network.enable via SendAndWait) → SubscribeWebSocketFrames →
// Listen pump goroutine → atomic counter → 100ms grace.
//
// Mirrors .scripts/cdp-capture.py command sequence (see 63-00 fixture audit
// section 6 for the line-by-line correspondence).
//
// INTEGER-ONLY (B2): no float types. D-09 (MCP-only AI invariant) preserved
// — no anthropic-sdk-go imports. Pure Go; no CGO.
package scorecard

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// cdpFrameSource is the production frameSource. It enumerates page-type CDP
// targets on host, attaches to each (Network.enable per session), drains
// Network.webSocketFrame{Sent,Received} events for the configured duration,
// and returns the aggregated count. Errors on per-target attach are logged
// (slog.Warn) and skipped — partial fan-in is preferable to total failure.
type cdpFrameSource struct {
	host string
	// kbDir is the per-target KBOutputDir; when non-empty, captured frames
	// are appended to <kbDir>/frames.ndjson via AppendFrame. Set by the
	// production factory wrapper at construction time (factory.go).
	kbDir string
}

// newCDPFrameSource constructs a cdpFrameSource. host is "127.0.0.1:<port>".
// If host is empty at Capture time, it is derived from the port arg.
func newCDPFrameSource(host string) *cdpFrameSource {
	return &cdpFrameSource{host: host}
}

// newCDPFrameSourceForTarget constructs a cdpFrameSource bound to the given
// kbDir for frames.ndjson sidecar emission (P64-05). host is "127.0.0.1:<port>".
func newCDPFrameSourceForTarget(host, kbDir string) *cdpFrameSource {
	return &cdpFrameSource{host: host, kbDir: kbDir}
}

// Capture implements frameSource. It returns the total frame count across
// all attached page targets within dur. A non-nil error indicates a
// terminal failure (no targets, no host); per-target attach failures are
// logged and silently skipped.
func (s *cdpFrameSource) Capture(ctx context.Context, port int, dur time.Duration) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	host := s.host
	if host == "" {
		if port == 0 {
			return 0, fmt.Errorf("cdp source: host empty and port=0")
		}
		host = fmt.Sprintf("127.0.0.1:%d", port)
	}

	log := slog.With("phase", "p63-cdp-source", "host", host)

	// Discovery client — used only for /json HTTP enumeration; not WS-connected.
	discovery := cdp.New(host, nil, func() int { return 0 })
	targets, err := discovery.DiscoverTargets(ctx)
	if err != nil {
		return 0, fmt.Errorf("cdp source: discover: %w", err)
	}
	pages := make([]cdp.Target, 0, len(targets))
	for _, t := range targets {
		if t.Type == "page" {
			pages = append(pages, t)
		}
	}
	if len(pages) == 0 {
		return 0, fmt.Errorf("cdp source: no page targets on %s (have %d total)", host, len(targets))
	}

	// Bound the capture window. Cancellation cascades through every
	// per-target Listen pump and SubscribeWebSocketFrames goroutine.
	pumpCtx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()

	var total int64
	// capture.Event sink is unused by this path but Client.New requires the
	// channel arg; size 1 is fine since nothing is ever Emit'd in this flow.
	events := make(chan capture.Event, 1)

	for _, t := range pages {
		c := cdp.New(host, events, func() int { return 0 })
		if t.WebSocketDebugURL == "" {
			log.Warn("cdp target has no webSocketDebuggerUrl", "target", t.ID)
			continue
		}
		if cerr := c.Connect(pumpCtx, t.WebSocketDebugURL); cerr != nil {
			log.Warn("cdp connect failed", "target", t.ID, "url", trimURL(t.URL), "err", cerr)
			_ = c.Close()
			continue
		}
		// CRITICAL: spawn Listen BEFORE issuing any SendAndWait. SendAndWait
		// blocks on a pending-channel keyed by message id; that channel is
		// only fed by Client.dispatchFrame which runs inside Client.Listen.
		// If Listen has not started, SendAndWait deadlocks until pumpCtx
		// expires.
		go func(cli *cdp.Client) {
			_ = cli.Listen(pumpCtx)
			_ = cli.Close()
		}(c)
		// Now Network.enable via SendAndWait — Listen is running so the
		// response demux can resolve the pending channel.
		if _, eerr := c.SendAndWait(pumpCtx, "Network.enable", nil); eerr != nil {
			log.Warn("cdp Network.enable failed", "target", t.ID, "err", eerr)
			// Listen will exit when pumpCtx expires; nothing else to clean.
			continue
		}
		ch, serr := cdp.SubscribeWebSocketFramesWithPayload(pumpCtx, c)
		if serr != nil {
			log.Warn("cdp subscribe failed", "target", t.ID, "err", serr)
			continue
		}
		// Counter pump — drains the typed frame channel and (when kbDir is
		// configured) appends each frame to frames.ndjson via AppendFrame.
		// Per T-64-03: AppendFrame handles its own per-kbDir mutex; this
		// goroutine does not need to serialize across targets externally.
		targetID := t.ID
		go func(in <-chan cdp.WSFrameWithPayload) {
			for f := range in {
				atomic.AddInt64(&total, 1)
				if s.kbDir != "" {
					dir := "recv"
					if f.Direction == "sent" {
						dir = "sent"
					}
					ev := NewFrameEvent(targetID, dir, f.OpCode, f.Masked, f.Payload)
					if _, err := AppendFrame(s.kbDir, ev); err != nil {
						log.Warn("frames.ndjson append failed", "target", targetID, "err", err)
					}
				}
			}
		}(ch)
	}

	<-pumpCtx.Done()
	// 100ms grace to allow in-flight frames the pump goroutines have already
	// read but not yet incremented to land in the counter. Exceeding this
	// window does not affect correctness — frame count is monotonic and the
	// threshold-vs-cap decision is robust to a missed frame or two.
	time.Sleep(100 * time.Millisecond)
	return int(atomic.LoadInt64(&total)), nil
}

// trimURL truncates a URL for log readability without leaking long path tails.
func trimURL(s string) string {
	const max = 60
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}
