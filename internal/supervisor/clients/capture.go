/*
Copyright (c) 2026 Security Research
*/
package clients

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// ErrCaptureUnsupported is returned when a capture verb is invoked but
// the supervisor reports the operation is not available in this build /
// on this OS (CodeUnavailable).
var ErrCaptureUnsupported = errors.New("capture: operation unsupported on this build")

// ErrCaptureNotFound is the typed sentinel for CodeNotFound from
// capture.* verbs (missing capture file, missing state directory,
// missing CDP target, etc.).
var ErrCaptureNotFound = errors.New("capture: target not found")

// translateCaptureErr layers capture-specific sentinel mapping on top of
// translateErr. CodeUnavailable maps to ErrCaptureUnsupported (joined
// with the wire-level ipc.ErrorBody so callers can drill into details).
func translateCaptureErr(err error) error {
	if err == nil {
		return nil
	}
	var eb *ipc.ErrorBody
	if errors.As(err, &eb) && eb.Code == ipc.CodeUnavailable {
		return errors.Join(ErrCaptureUnsupported, eb)
	}
	return translateErr(err, ErrCaptureNotFound)
}

// CaptureClient wraps the capture.* verbs. Construct one per ipc.Bus.
type CaptureClient struct {
	bus ipc.Bus
}

// NewCaptureClient returns a wrapper over bus for the capture.* verb group.
func NewCaptureClient(bus ipc.Bus) *CaptureClient {
	return &CaptureClient{bus: bus}
}

// List calls capture.list.
func (c *CaptureClient) List(ctx context.Context, directory string) (*supervisor.CaptureListResult, error) {
	p := supervisor.CaptureListParams{Directory: directory}
	raw, err := c.bus.Call(ctx, "capture.list", p)
	if err != nil {
		return nil, translateCaptureErr(err)
	}
	var out supervisor.CaptureListResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Diff calls capture.diff.
func (c *CaptureClient) Diff(ctx context.Context, beforeFile, afterFile string) (*supervisor.CaptureDiffResult, error) {
	p := supervisor.CaptureDiffParams{BeforeFile: beforeFile, AfterFile: afterFile}
	raw, err := c.bus.Call(ctx, "capture.diff", p)
	if err != nil {
		return nil, translateCaptureErr(err)
	}
	var out supervisor.CaptureDiffResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Visual calls capture.visual. Long-running: pass a context with an
// appropriate deadline (visual orchestration commonly runs 10-60s).
func (c *CaptureClient) Visual(ctx context.Context, p supervisor.CaptureVisualParams) (*supervisor.CaptureVisualResult, error) {
	raw, err := c.bus.Call(ctx, "capture.visual", p)
	if err != nil {
		return nil, translateCaptureErr(err)
	}
	var out supervisor.CaptureVisualResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// VisualDiff calls capture.visual_diff.
func (c *CaptureClient) VisualDiff(ctx context.Context, oldRunDir, newRunDir string) (*supervisor.CaptureVisualDiffResult, error) {
	p := supervisor.CaptureVisualDiffParams{OldRunDir: oldRunDir, NewRunDir: newRunDir}
	raw, err := c.bus.Call(ctx, "capture.visual_diff", p)
	if err != nil {
		return nil, translateCaptureErr(err)
	}
	var out supervisor.CaptureVisualDiffResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// StateReplay calls capture.state_replay.
func (c *CaptureClient) StateReplay(ctx context.Context, p supervisor.CaptureStateReplayParams) (*supervisor.CaptureStateReplayResult, error) {
	raw, err := c.bus.Call(ctx, "capture.state_replay", p)
	if err != nil {
		return nil, translateCaptureErr(err)
	}
	var out supervisor.CaptureStateReplayResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Webview2Attach calls capture.webview2_attach. Windows-only in practice
// (the underlying webview2.Ensure is a no-op stub on non-Windows builds).
func (c *CaptureClient) Webview2Attach(ctx context.Context, p supervisor.CaptureWebView2AttachParams) (*supervisor.CaptureWebView2AttachResult, error) {
	raw, err := c.bus.Call(ctx, "capture.webview2_attach", p)
	if err != nil {
		return nil, translateCaptureErr(err)
	}
	var out supervisor.CaptureWebView2AttachResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
