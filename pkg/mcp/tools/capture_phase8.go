/*
Copyright (c) 2026 Security Research

Phase 8 plan 04: visual capture user-facing surface. Three new MCP tools:

	unravel_capture_visual         - Run visual capture pipeline against a CDP endpoint
	unravel_capture_visual_diff    - Compare visual artifacts between two KB run directories
	unravel_capture_state_replay   - Read scenario steps that produced a captured state

Threats mitigated:
  - T-08-01: path-traversal at every kb_dir / scenario_path / target_path / run_id input
  - T-08-04: CDP loopback validation (host must be localhost/127.0.0.1/::1 unless allow_remote_cdp)
  - T-08-06: per-run --user-data-dir already enforced by pkg/capture/launch (Wave 1)

Known limitation: auto-launch from `target_path` is not wired through MCP — operators
must run `unravel capture start --visual --target ...` from the CLI for auto-launch flows.
The MCP path requires a pre-attached CDP endpoint via `cdp_url`.
*/
package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	gonet "net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	visualdiff "github.com/inovacc/unravel-oss/pkg/capture/diff"
	"github.com/inovacc/unravel-oss/pkg/capture/visual"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// captureVisualInput is the wire shape of unravel_capture_visual.
type captureVisualInput struct {
	CDPURL         string `json:"cdp_url" jsonschema:"CDP endpoint URL (loopback only unless allow_remote_cdp)"`
	KBDir          string `json:"kb_dir" jsonschema:"Knowledge base output directory"`
	Mode           string `json:"mode,omitempty" jsonschema:"auto|interactive|scripted (default auto)"`
	Scenario       string `json:"scenario,omitempty" jsonschema:"Path to scenario JSON when mode=scripted"`
	Viewports      string `json:"viewports,omitempty" jsonschema:"Comma-separated WxH list, e.g., 1920x1080,1280x720"`
	MaxStates      int    `json:"max_states,omitempty" jsonschema:"Cap state captures (default 50)"`
	ModalSettleMs  int    `json:"modal_settle_ms,omitempty" jsonschema:"Settle delay (ms) after modal_open before capture (default 300)"`
	PHashThreshold int    `json:"phash_threshold,omitempty" jsonschema:"dHash Hamming threshold for diff PASS bucket (default 5)"`
	AllowRemoteCDP bool   `json:"allow_remote_cdp,omitempty" jsonschema:"Allow non-loopback cdp_url (T-08-04 opt-out)"`
}

// captureVisualResult is the JSON shape returned by handleCaptureVisual.
type captureVisualResult struct {
	RunID    string                  `json:"run_id"`
	KBDir    string                  `json:"kb_dir"`
	States   int                     `json:"states_captured"`
	Captures []capture.CapturedState `json:"captures"`
}

// captureVisualDiffInput is the wire shape of unravel_capture_visual_diff.
type captureVisualDiffInput struct {
	OldRunDir string `json:"old_run_dir" jsonschema:"Path to older <kb>/visual/<run-id> directory"`
	NewRunDir string `json:"new_run_dir" jsonschema:"Path to newer <kb>/visual/<run-id> directory"`
}

// captureVisualDiffResult is the JSON shape returned by handleCaptureVisualDiff.
type captureVisualDiffResult struct {
	Visual *visualdiff.VisualResult `json:"visual"`
}

// captureStateReplayInput is the wire shape of unravel_capture_state_replay.
type captureStateReplayInput struct {
	KBDir     string `json:"kb_dir" jsonschema:"Knowledge base directory"`
	RunID     string `json:"run_id" jsonschema:"Run ID slug (ISO-8601, e.g., 2026-04-27T12-34-56Z)"`
	Component string `json:"component" jsonschema:"Component bucket (auth, api, ipc, telemetry, ui, persistence, crypto, update, unknown)"`
	StateSlug string `json:"state_slug" jsonschema:"State slug, e.g., login or login+modal-mfa"`
}

// captureStateReplayResult is the JSON shape returned by handleCaptureStateReplay.
type captureStateReplayResult struct {
	Mode      string          `json:"mode"`
	Steps     json.RawMessage `json:"steps,omitempty"`
	StatePath string          `json:"state_path"`
	Note      string          `json:"note,omitempty"`
}

// validateCDPLoopbackMCP mirrors cmd/capture.go's loopback validator (T-08-04).
// Duplicated here to keep cmd/ → pkg/mcptools dependency direction clean.
func validateCDPLoopbackMCP(rawURL string, allowRemote bool) error {
	if rawURL == "" {
		return errors.New("cdp_url is required (auto-launch from MCP not supported; use CLI for --target flows)")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse cdp_url: %w", err)
	}
	host := u.Hostname()
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return nil
	}
	if ip := gonet.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	if allowRemote {
		return nil
	}
	return fmt.Errorf("cdp_url host %q is not loopback (127.0.0.1, ::1, localhost); set allow_remote_cdp=true to opt in", host)
}

// registerCapturePhase8Tools registers the 3 Phase 8 plan 04 tools onto s.
// Sibling-file pattern from registerKnowledgePhase7Tools.
func registerCapturePhase8Tools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_capture_visual",
		Description: "Capture screenshot + DOM tree + computed-style layout per state from a running Electron/Tauri/WebView2 app via CDP. KB-resident output.",
	}, handleCaptureVisual)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_capture_visual_diff",
		Description: "Compare visual artifacts (screenshot dHash + tree + bounds) between two run directories. Emits BLOCK/FLAG/PASS regression list.",
	}, handleCaptureVisualDiff)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_capture_state_replay",
		Description: "Return the scenario steps that produced a captured state. Returns note when state was captured in auto/interactive mode (no steps recorded).",
	}, handleCaptureStateReplay)
}

func handleCaptureVisual(ctx context.Context, _ *mcp.CallToolRequest, in captureVisualInput) (*mcp.CallToolResult, any, error) {
	if err := validateCDPLoopbackMCP(in.CDPURL, in.AllowRemoteCDP); err != nil {
		return errorResult(err), nil, nil
	}
	kbAbs, err := rejectTraversal(in.KBDir)
	if err != nil {
		return errorResult(fmt.Errorf("kb_dir: %w", err)), nil, nil
	}
	if err := os.MkdirAll(kbAbs, 0o755); err != nil {
		return errorResult(fmt.Errorf("mkdir kb: %w", err)), nil, nil
	}

	scenarioAbs := ""
	if in.Scenario != "" {
		abs, err := rejectTraversal(in.Scenario)
		if err != nil {
			return errorResult(fmt.Errorf("scenario: %w", err)), nil, nil
		}
		st, err := os.Lstat(abs)
		if err != nil {
			return errorResult(fmt.Errorf("scenario stat: %w", err)), nil, nil
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errorResult(fmt.Errorf("scenario refuses symlink: %s", abs)), nil, nil
		}
		if !st.Mode().IsRegular() {
			return errorResult(fmt.Errorf("scenario must be a regular file: %s", abs)), nil, nil
		}
		scenarioAbs = abs
	}

	viewports, err := visual.ParseViewports(in.Viewports)
	if err != nil {
		return errorResult(fmt.Errorf("viewports: %w", err)), nil, nil
	}

	u, err := url.Parse(in.CDPURL)
	if err != nil {
		return errorResult(fmt.Errorf("parse cdp_url: %w", err)), nil, nil
	}
	host := u.Host
	if host == "" {
		return errorResult(fmt.Errorf("cdp_url missing host:port in %q", in.CDPURL)), nil, nil
	}

	events := make(chan capture.Event, 256)
	var seq int64
	seqFn := func() int { return int(atomic.AddInt64(&seq, 1)) }
	cli := cdp.New(host, events, seqFn)

	targets, err := cli.DiscoverTargets(ctx)
	if err != nil {
		return errorResult(fmt.Errorf("discover CDP targets at %s: %w", host, err)), nil, nil
	}
	var ws string
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebugURL != "" {
			ws = t.WebSocketDebugURL
			break
		}
	}
	if ws == "" {
		return errorResult(fmt.Errorf("no debuggable page target at %s", host)), nil, nil
	}
	if err := cli.Connect(ctx, ws); err != nil {
		return errorResult(fmt.Errorf("connect CDP ws: %w", err)), nil, nil
	}
	defer func() { _ = cli.Close() }()

	mode := visual.Mode(strings.ToLower(strings.TrimSpace(in.Mode)))
	switch mode {
	case visual.ModeAuto, visual.ModeInteractive, visual.ModeScripted, "":
	default:
		return errorResult(fmt.Errorf("mode %q invalid (auto|interactive|scripted)", in.Mode)), nil, nil
	}

	runID := time.Now().UTC().Format("2006-01-02T15-04-05Z")

	orch, err := visual.New(cli, visual.Options{
		Mode:           mode,
		KBDir:          kbAbs,
		RunID:          runID,
		Viewports:      viewports,
		MaxStates:      in.MaxStates,
		ScenarioPath:   scenarioAbs,
		ModalSettleMs:  in.ModalSettleMs,
		PHashThreshold: in.PHashThreshold,
	})
	if err != nil {
		return errorResult(fmt.Errorf("orchestrator: %w", err)), nil, nil
	}
	if err := orch.Run(ctx); err != nil {
		return errorResult(fmt.Errorf("run: %w", err)), nil, nil
	}
	if err := visual.WriteLatestPointer(kbAbs, runID); err != nil {
		// Non-fatal — run succeeded.
		_ = err
	}

	caps := orch.Captures()
	return jsonResult(captureVisualResult{
		RunID:    runID,
		KBDir:    kbAbs,
		States:   len(caps),
		Captures: caps,
	}), nil, nil
}

func handleCaptureVisualDiff(_ context.Context, _ *mcp.CallToolRequest, in captureVisualDiffInput) (*mcp.CallToolResult, any, error) {
	oldAbs, err := rejectTraversal(in.OldRunDir)
	if err != nil {
		return errorResult(fmt.Errorf("old_run_dir: %w", err)), nil, nil
	}
	newAbs, err := rejectTraversal(in.NewRunDir)
	if err != nil {
		return errorResult(fmt.Errorf("new_run_dir: %w", err)), nil, nil
	}
	res, err := visualdiff.CompareVisual(oldAbs, newAbs)
	if err != nil {
		return errorResult(fmt.Errorf("compare visual: %w", err)), nil, nil
	}
	return jsonResult(captureVisualDiffResult{Visual: res}), nil, nil
}

func handleCaptureStateReplay(_ context.Context, _ *mcp.CallToolRequest, in captureStateReplayInput) (*mcp.CallToolResult, any, error) {
	if in.RunID == "" || in.Component == "" || in.StateSlug == "" {
		return errorResult(errors.New("run_id, component, and state_slug are required")), nil, nil
	}
	for _, seg := range []string{in.RunID, in.Component, in.StateSlug} {
		if strings.Contains(seg, "..") || strings.Contains(seg, "/") || strings.Contains(seg, "\\") {
			return errorResult(fmt.Errorf("path-traversal segment rejected: %q", seg)), nil, nil
		}
	}
	kbAbs, err := rejectTraversal(in.KBDir)
	if err != nil {
		return errorResult(fmt.Errorf("kb_dir: %w", err)), nil, nil
	}
	stateDir := filepath.Join(kbAbs, "visual", in.RunID, in.Component, in.StateSlug)
	metaPath := filepath.Join(stateDir, "_meta.json")
	body, err := os.ReadFile(metaPath)
	if err != nil {
		return errorResult(fmt.Errorf("read state meta: %w", err)), nil, nil
	}
	var meta struct {
		Mode         string          `json:"mode"`
		ScenarioPath string          `json:"scenario_path,omitempty"`
		Steps        json.RawMessage `json:"steps,omitempty"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return errorResult(fmt.Errorf("parse state meta: %w", err)), nil, nil
	}
	res := captureStateReplayResult{
		Mode:      meta.Mode,
		StatePath: stateDir,
		Steps:     meta.Steps,
	}
	if meta.Mode != "scripted" {
		res.Note = fmt.Sprintf("state was captured in %q mode; no scenario steps recorded", meta.Mode)
	}
	return jsonResult(res), nil, nil
}
