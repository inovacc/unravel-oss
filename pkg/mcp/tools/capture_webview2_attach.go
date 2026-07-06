/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/webview2"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CaptureWebView2AttachInput holds the parameters for the
// unravel_capture_webview2_attach MCP tool.
type CaptureWebView2AttachInput struct {
	Kind   string `json:"kind" jsonschema:"target kind: 'wa-desktop' (WhatsApp Desktop UWP) or 'teams-desktop' (Microsoft Teams Desktop)"`
	Port   int    `json:"port,omitempty" jsonschema:"CDP remote-debugging port (0 = preset default; wa=9222, teams=9223)"`
	NoKill bool   `json:"no_kill,omitempty" jsonschema:"if target is running without CDP, error instead of kill+relaunch (default false: will kill+relaunch)"`
}

// captureWebView2AttachOutput is the JSON shape returned by the tool.
type captureWebView2AttachOutput struct {
	Attached    bool   `json:"attached"`
	Kind        string `json:"kind"`
	Spawned     bool   `json:"spawned"`
	PID         int    `json:"pid"`
	SidecarPath string `json:"sidecar_path"`
	JSCount     int    `json:"js_count"`
	CSSCount    int    `json:"css_count"`
	ElapsedMS   int64  `json:"elapsed_ms"`
	Error       string `json:"error,omitempty"`
}

// ensureFn is an injectable seam over webview2.Ensure so the MCP handler can
// be unit-tested without a live WhatsApp/Teams target or a real CDP port.
// Production behavior is byte-identical through the default implementation.
var ensureFn = func(ctx context.Context, t webview2.Target) (webview2.Attached, error) {
	return webview2.Ensure(ctx, t)
}

// pullSourcesFn is an injectable seam over scorecard.PullSourcesOverCDP for
// unit testing without a live CDP target.
var pullSourcesFn = func(ctx context.Context, host string, port int, timeout time.Duration) (*scorecard.PulledSources, error) {
	return scorecard.PullSourcesOverCDP(ctx, host, port, timeout)
}

func registerCaptureWebView2AttachTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_capture_webview2_attach",
		Description: "One-shot bounded (~30-60s) no-admin CDP attach to a WebView2/UWP messaging app. " +
			"Launches via AUMID broker (WhatsApp) or direct exe (Teams), attaches CDP, pulls live JS/CSS source, " +
			"writes per-app sidecar under LOCALAPPDATA\\Unravel\\cdp-src\\<pkg>\\sources.json. " +
			"HKCU env writes are transactionally reverted (D-04). " +
			"Honest-empty if CDP target has no scripts (top page target only). " +
			"Windows-only; returns an error on other platforms.",
	}, handleCaptureWebView2Attach)
}

func handleCaptureWebView2Attach(ctx context.Context, _ *mcp.CallToolRequest, in CaptureWebView2AttachInput) (*mcp.CallToolResult, any, error) {
	start := time.Now()

	out := captureWebView2AttachOutput{Kind: in.Kind}

	if in.Kind == "" {
		out.Error = "--kind is required (one of: wa-desktop, teams-desktop)"
		return jsonResult(out), nil, nil
	}

	preset, ok := webview2.PresetFor(in.Kind)
	if !ok {
		out.Error = fmt.Sprintf("unknown kind %q: must be wa-desktop or teams-desktop", in.Kind)
		return jsonResult(out), nil, nil
	}

	logger := slog.Default()

	// D-05: idempotently revert any stale HKCU value from a prior killed run.
	if err := webview2.SelfHeal(ctx, logger); err != nil {
		out.Error = fmt.Sprintf("self-heal: %v", err)
		return jsonResult(out), nil, nil
	}

	target := webview2.Target{
		Kind:   in.Kind,
		Port:   in.Port,
		NoKill: in.NoKill,
		Logger: logger,
	}

	att, err := ensureFn(ctx, target)
	if err != nil {
		out.Error = fmt.Sprintf("webview2 ensure %s: %v", in.Kind, err)
		out.ElapsedMS = time.Since(start).Milliseconds()
		return jsonResult(out), nil, nil
	}

	out.Attached = true
	out.Spawned = att.Spawned
	out.PID = att.PID

	// Best-effort live JS/CSS pull — non-fatal, honest-empty if nothing found.
	port := preset.Port
	if in.Port != 0 {
		port = in.Port
	}

	ps, pullErr := pullSourcesFn(ctx, "127.0.0.1", port, 25*time.Second)
	if pullErr != nil {
		logger.Warn("mcp capture_webview2_attach: cdp source pull failed (non-fatal)", "err", pullErr)
	} else {
		jsEntries := make([]webview2.CDPSrcEntry, 0, len(ps.JS))
		for _, s := range ps.JS {
			jsEntries = append(jsEntries, webview2.CDPSrcEntry{URL: s.URL, Source: s.Source})
		}
		cssEntries := make([]webview2.CDPSrcEntry, 0, len(ps.CSS))
		for _, s := range ps.CSS {
			cssEntries = append(cssEntries, webview2.CDPSrcEntry{URL: s.URL, Source: s.Source})
		}

		path, werr := webview2.WriteCDPSourceSidecar(preset.PkgName, jsEntries, cssEntries)
		if werr != nil {
			logger.Warn("mcp capture_webview2_attach: sidecar write failed (non-fatal)", "err", werr)
		} else {
			out.SidecarPath = path
			out.JSCount = len(jsEntries)
			out.CSSCount = len(cssEntries)
		}
	}

	out.ElapsedMS = time.Since(start).Milliseconds()
	return jsonResult(out), nil, nil
}
