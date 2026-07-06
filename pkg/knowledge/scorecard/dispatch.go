/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P57 weak-dim deepening dispatcher.
//
// The dispatcher takes a list of weak dimensions (score < threshold) and runs
// the appropriate deepening pass for each. In P57 the only runtime pass is
// CDP webSocket frame capture, used for wire/auth/state_machines/ipc. The
// behavior dim has no deepening pass available in P57 (P59 corpus playbooks
// will close it) — its DispatchResult carries a canonical no-op note.
//
// INTEGER-ONLY (B2): no floating-point types in this file.
//
// Bump caps (W-13b parity, applied by the caller in iterate.go):
//   - wire           → 85
//   - auth           → 80
//   - state_machines → 80
//   - ipc            → 80
package scorecard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// frameSource is the interface seam for dispatch — production wires it to
// pkg/capture/cdp.SubscribeWebSocketFrames; tests inject a deterministic mock.
type frameSource interface {
	Capture(ctx context.Context, port int, dur time.Duration) (frames int, err error)
}

// frameSeconds is the per-pass capture window in seconds (W-13b: 180).
const frameSeconds = 180

// noOpBehaviorNote is the canonical Note string for the behavior dim's
// no-deepening DispatchResult (B3 — caller appends the missing-evidence
// marker on the DimScore separately).
const noOpBehaviorNote = "no deepening pass available for behavior in P57"

// capFor returns the integer post-hoc bump cap for the given dim. Returns 0
// for dims that are not in the P57 dispatch table (caller skips bump).
func capFor(dim string) int {
	switch dim {
	case "wire":
		return 85
	case "auth", "state_machines", "ipc":
		return 80
	default:
		return 0
	}
}

// dispatch runs the deepening pass for each weak dim and returns one
// DispatchResult per dim. A nil ctx error is treated as ctx.Background.
//
// On context cancel mid-loop the function returns the partial results
// collected so far plus a wrapped ctx.Err().
func dispatch(ctx context.Context, target *DissectTarget, dims []string, src frameSource) ([]DispatchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if src == nil {
		return nil, fmt.Errorf("dispatch: nil frameSource")
	}
	out := make([]DispatchResult, 0, len(dims))
	log := slog.With("phase", "p57-dispatch")

	for _, dim := range dims {
		if err := ctx.Err(); err != nil {
			return out, fmt.Errorf("dispatch ctx: %w", err)
		}
		switch dim {
		case "wire", "auth", "state_machines", "ipc":
			start := time.Now()
			frames, err := src.Capture(ctx, target.CDPPort, time.Duration(frameSeconds)*time.Second)
			dur := time.Since(start).Milliseconds()
			if err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
					return out, fmt.Errorf("dispatch %s: %w", dim, err)
				}
				log.Warn("capture failed", "dim", dim, "err", err)
				out = append(out, DispatchResult{
					Pass: dim, TargetDims: []string{dim},
					DurationMs: dur, FramesCaptured: 0, OK: false,
					Note: fmt.Sprintf("capture error: %v", err),
				})
				continue
			}
			res := DispatchResult{
				Pass: dim, TargetDims: []string{dim},
				DurationMs: dur, FramesCaptured: frames, OK: frames > 0,
			}
			if frames == 0 {
				res.Note = "no frames"
			}
			out = append(out, res)
		case "behavior":
			out = append(out, DispatchResult{
				Pass: "behavior", TargetDims: []string{"behavior"},
				DurationMs: 0, FramesCaptured: 0, OK: false,
				Note: noOpBehaviorNote,
			})
		default:
			// dim not in dispatch table — skip silently
			log.Debug("skip dim not in dispatch table", "dim", dim)
		}
	}
	return out, nil
}
