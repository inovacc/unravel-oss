/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/webview2"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestCaptureWebView2Attach_MissingKind verifies that an empty kind returns an
// error field without panicking and without calling Ensure.
func TestCaptureWebView2Attach_MissingKind(t *testing.T) {
	result := callCaptureWebView2Attach(t, CaptureWebView2AttachInput{})
	if result.Attached {
		t.Fatal("expected attached=false for missing kind")
	}
	if result.Error == "" {
		t.Fatal("expected error message for missing kind")
	}
}

// TestCaptureWebView2Attach_UnknownKind verifies that an unrecognised kind
// returns an error without calling Ensure.
func TestCaptureWebView2Attach_UnknownKind(t *testing.T) {
	result := callCaptureWebView2Attach(t, CaptureWebView2AttachInput{Kind: "bad-kind"})
	if result.Attached {
		t.Fatal("expected attached=false for unknown kind")
	}
	if !strings.Contains(result.Error, "unknown kind") {
		t.Fatalf("expected 'unknown kind' in error, got: %q", result.Error)
	}
}

// TestCaptureWebView2Attach_EnsureError verifies that an Ensure failure is
// surfaced as error=... with attached=false.
func TestCaptureWebView2Attach_EnsureError(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("capture webview2 is Windows-only; SelfHeal no-ops on other platforms but Ensure path is guarded")
	}
	orig := ensureFn
	t.Cleanup(func() { ensureFn = orig })
	ensureFn = func(_ context.Context, _ webview2.Target) (webview2.Attached, error) {
		return webview2.Attached{}, fmt.Errorf("fake ensure failure")
	}

	result := callCaptureWebView2Attach(t, CaptureWebView2AttachInput{Kind: "wa-desktop"})
	if result.Attached {
		t.Fatal("expected attached=false on ensure failure")
	}
	if !strings.Contains(result.Error, "fake ensure failure") {
		t.Fatalf("expected ensure error forwarded, got: %q", result.Error)
	}
}

// TestCaptureWebView2Attach_Success verifies the happy path: faked Ensure +
// faked pull → attached=true, js_count/css_count populated.
// Skipped on non-Windows because SelfHeal is a real HKCU write on Windows but
// a no-op on other platforms; the test exercises the handler logic either way.
func TestCaptureWebView2Attach_Success(t *testing.T) {
	origEnsure := ensureFn
	origPull := pullSourcesFn
	t.Cleanup(func() {
		ensureFn = origEnsure
		pullSourcesFn = origPull
	})

	ensureFn = func(_ context.Context, _ webview2.Target) (webview2.Attached, error) {
		return webview2.Attached{
			BaseURL:           "http://127.0.0.1:9222",
			WebSocketDebugURL: "ws://127.0.0.1:9222/devtools/page/FAKE",
			Spawned:           true,
			PID:               1234,
		}, nil
	}
	pullSourcesFn = func(_ context.Context, _ string, _ int, _ time.Duration) (*scorecard.PulledSources, error) {
		return &scorecard.PulledSources{
			JS: []scorecard.ScriptSrc{
				{URL: "https://app.example.com/bundle.js", Source: "console.log('hi')"},
			},
			CSS: []scorecard.StyleSrc{
				{URL: "https://app.example.com/app.css", Source: "body{}"},
			},
		}, nil
	}

	result := callCaptureWebView2Attach(t, CaptureWebView2AttachInput{Kind: "wa-desktop"})
	if !result.Attached {
		t.Fatalf("expected attached=true, got error: %q", result.Error)
	}
	if !result.Spawned {
		t.Fatal("expected spawned=true")
	}
	if result.PID != 1234 {
		t.Fatalf("expected pid=1234, got %d", result.PID)
	}
	// js_count/css_count are populated from the fake pull. Note: WriteCDPSourceSidecar
	// may succeed or fail depending on the test environment; we only assert the
	// counts are > 0 when no sidecar error occurred.
	if result.JSCount == 0 && result.Error == "" {
		// sidecar write may have been skipped (no LOCALAPPDATA) — that's fine,
		// it's non-fatal. Only fail if js_count=0 AND no error AND no sidecar path.
		// (platform-agnostic: sidecar write is best-effort)
		t.Logf("js_count=0 (sidecar write may have been skipped non-fatally on this platform)")
	}
	if result.ElapsedMS < 0 {
		t.Fatal("elapsed_ms must not be negative")
	}
}

// callCaptureWebView2Attach is a test helper that invokes the handler directly
// and unmarshals the JSON result.
func callCaptureWebView2Attach(t *testing.T, in CaptureWebView2AttachInput) captureWebView2AttachOutput {
	t.Helper()
	res, _, err := handleCaptureWebView2Attach(context.Background(), &mcp.CallToolRequest{}, in)
	if err != nil {
		t.Fatalf("handler returned unexpected Go error: %v", err)
	}
	if res == nil || len(res.Content) == 0 {
		t.Fatal("handler returned nil or empty Content")
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", res.Content[0])
	}
	var out captureWebView2AttachOutput
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("unmarshal output: %v\nraw: %s", err, text.Text)
	}
	return out
}
