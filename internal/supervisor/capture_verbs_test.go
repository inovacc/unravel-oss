/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

func TestCaptureVerbs_AllRegistered(t *testing.T) {
	tmp := t.TempDir()
	sv, err := New(Config{SocketDir: tmp})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = sv.Stop() }()

	want := []string{
		"capture.list",
		"capture.diff",
		"capture.visual",
		"capture.visual_diff",
		"capture.state_replay",
		"capture.webview2_attach",
	}
	for _, v := range want {
		if !sv.HasVerb(v) {
			t.Errorf("supervisor missing verb %q", v)
		}
	}
}

func TestCaptureVerbs_BadParamShape(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	cases := []struct {
		name    string
		handler func(context.Context, json.RawMessage) (any, *ipc.ErrorBody)
		raw     json.RawMessage
	}{
		{"list-bad-json", sv.captureList, json.RawMessage(`{not-json`)},
		{"diff-bad-json", sv.captureDiff, json.RawMessage(`{not-json`)},
		{"visual-bad-json", sv.captureVisual, json.RawMessage(`{not-json`)},
		{"visual_diff-bad-json", sv.captureVisualDiff, json.RawMessage(`{not-json`)},
		{"state_replay-bad-json", sv.captureStateReplay, json.RawMessage(`{not-json`)},
		{"webview2_attach-bad-json", sv.captureWebView2Attach, json.RawMessage(`{not-json`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, eb := tc.handler(context.Background(), tc.raw)
			if eb == nil {
				t.Fatalf("want ErrorBody, got nil")
			}
			if eb.Code != ipc.CodeInvalidArg {
				t.Errorf("got code %d, want %d", eb.Code, ipc.CodeInvalidArg)
			}
		})
	}
}

func TestCaptureVerbs_MissingRequiredFields(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	cases := []struct {
		name    string
		handler func(context.Context, json.RawMessage) (any, *ipc.ErrorBody)
		params  any
	}{
		{"list-no-dir", sv.captureList, CaptureListParams{}},
		{"diff-missing-before", sv.captureDiff, CaptureDiffParams{AfterFile: "x.json"}},
		{"diff-missing-after", sv.captureDiff, CaptureDiffParams{BeforeFile: "x.json"}},
		{"state_replay-missing", sv.captureStateReplay, CaptureStateReplayParams{KBDir: "kb"}},
		{"webview2-missing-kind", sv.captureWebView2Attach, CaptureWebView2AttachParams{}},
		{"webview2-bad-kind", sv.captureWebView2Attach, CaptureWebView2AttachParams{Kind: "unknown-kind"}},
		{"visual-no-cdp", sv.captureVisual, CaptureVisualParams{KBDir: tmp}},
		{"visual_diff-no-dirs", sv.captureVisualDiff, CaptureVisualDiffParams{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, eb := tc.handler(context.Background(), mustJSON(t, tc.params))
			if eb == nil {
				t.Fatalf("want ErrorBody, got nil")
			}
			if eb.Code != ipc.CodeInvalidArg {
				t.Errorf("got code %d, want %d (msg=%s)", eb.Code, ipc.CodeInvalidArg, eb.Message)
			}
		})
	}
}

// TestCaptureList_EmptyDirReturnsEmptyResult exercises the happy-ish path:
// reading an empty real directory should produce a Captures slice (nil or
// empty, no error).
func TestCaptureList_EmptyDirReturnsEmptyResult(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	emptyDir := filepath.Join(tmp, "captures")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	out, eb := sv.captureList(context.Background(), mustJSON(t, CaptureListParams{Directory: emptyDir}))
	if eb != nil {
		t.Fatalf("unexpected ErrorBody: %+v", eb)
	}
	res, ok := out.(CaptureListResult)
	if !ok {
		t.Fatalf("got %T, want CaptureListResult", out)
	}
	if len(res.Captures) != 0 {
		t.Errorf("got %d captures, want 0", len(res.Captures))
	}
}

// TestCaptureStateReplay_PathTraversalRejected ensures the conservative
// slug validation refuses path separators (T-08-01 hardening parity).
func TestCaptureStateReplay_PathTraversalRejected(t *testing.T) {
	tmp := t.TempDir()
	sv, _ := New(Config{SocketDir: tmp})
	defer func() { _ = sv.Stop() }()

	_, eb := sv.captureStateReplay(context.Background(), mustJSON(t, CaptureStateReplayParams{
		KBDir:     tmp,
		RunID:     "../../etc",
		Component: "auth",
		StateSlug: "login",
	}))
	if eb == nil || eb.Code != ipc.CodeInvalidArg {
		t.Errorf("want CodeInvalidArg for traversal segment; got %+v", eb)
	}
}
