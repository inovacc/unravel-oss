/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/pkg/capture"
	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
	capturediff "github.com/inovacc/unravel-oss/pkg/capture/diff"
	"github.com/inovacc/unravel-oss/pkg/capture/visual"
	"github.com/inovacc/unravel-oss/pkg/capture/webview2"
)

// ---------- request / response shapes ----------

// CaptureListParams is the request body for capture.list.
type CaptureListParams struct {
	Directory string `json:"directory"`
}

// CaptureFileInfo mirrors the per-file entry returned by capture.list.
type CaptureFileInfo struct {
	File       string `json:"file"`
	AppName    string `json:"app_name"`
	Framework  string `json:"framework"`
	EventCount int    `json:"event_count"`
	DurationMs int64  `json:"duration_ms"`
}

// CaptureListResult is the response body for capture.list.
type CaptureListResult struct {
	Captures []CaptureFileInfo `json:"captures"`
}

// CaptureDiffParams is the request body for capture.diff.
type CaptureDiffParams struct {
	BeforeFile string `json:"before_file"`
	AfterFile  string `json:"after_file"`
}

// CaptureDiffResult aliases capturediff.Result.
type CaptureDiffResult = capturediff.Result

// CaptureVisualParams is the request body for capture.visual. Mirrors
// captureVisualInput in pkg/mcp/tools/capture_phase8.go.
type CaptureVisualParams struct {
	CDPURL         string `json:"cdp_url"`
	KBDir          string `json:"kb_dir"`
	Mode           string `json:"mode,omitempty"`
	Scenario       string `json:"scenario,omitempty"`
	Viewports      string `json:"viewports,omitempty"`
	MaxStates      int    `json:"max_states,omitempty"`
	ModalSettleMs  int    `json:"modal_settle_ms,omitempty"`
	PHashThreshold int    `json:"phash_threshold,omitempty"`
	AllowRemoteCDP bool   `json:"allow_remote_cdp,omitempty"`
}

// CaptureVisualResult mirrors captureVisualResult in the MCP tool.
type CaptureVisualResult struct {
	RunID    string                  `json:"run_id"`
	KBDir    string                  `json:"kb_dir"`
	States   int                     `json:"states_captured"`
	Captures []capture.CapturedState `json:"captures"`
}

// CaptureVisualDiffParams is the request body for capture.visual_diff.
type CaptureVisualDiffParams struct {
	OldRunDir string `json:"old_run_dir"`
	NewRunDir string `json:"new_run_dir"`
}

// CaptureVisualDiffResult wraps the VisualResult from pkg/capture/diff.
type CaptureVisualDiffResult struct {
	Visual *capturediff.VisualResult `json:"visual"`
}

// CaptureStateReplayParams is the request body for capture.state_replay.
type CaptureStateReplayParams struct {
	KBDir     string `json:"kb_dir"`
	RunID     string `json:"run_id"`
	Component string `json:"component"`
	StateSlug string `json:"state_slug"`
}

// CaptureStateReplayResult mirrors captureStateReplayResult in the MCP tool.
type CaptureStateReplayResult struct {
	Mode      string          `json:"mode"`
	Steps     json.RawMessage `json:"steps,omitempty"`
	StatePath string          `json:"state_path"`
	Note      string          `json:"note,omitempty"`
}

// CaptureWebView2AttachParams is the request body for capture.webview2_attach.
type CaptureWebView2AttachParams struct {
	Kind   string `json:"kind"`
	Port   int    `json:"port,omitempty"`
	NoKill bool   `json:"no_kill,omitempty"`
}

// CaptureWebView2AttachResult mirrors captureWebView2AttachOutput.
type CaptureWebView2AttachResult struct {
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

// ---------- registration ----------

// registerCaptureVerbs wires the capture.* verb group. Called from New().
func (sv *Supervisor) registerCaptureVerbs() {
	sv.RegisterVerb("capture.list", sv.captureList)
	sv.RegisterVerb("capture.diff", sv.captureDiff)
	sv.RegisterVerb("capture.visual", sv.captureVisual)
	sv.RegisterVerb("capture.visual_diff", sv.captureVisualDiff)
	sv.RegisterVerb("capture.state_replay", sv.captureStateReplay)
	sv.RegisterVerb("capture.webview2_attach", sv.captureWebView2Attach)
}

// ---------- helpers (mirror pkg/mcp/tools/knowledge_phase7.go:rejectTraversal) ----------

// rejectTraversal rejects any raw path containing a `..` segment and
// returns the cleaned absolute path on success. T-07-01 hardening shared
// with the MCP tool layer; duplicated here to keep the supervisor free
// of an import cycle into pkg/mcp/tools/.
func rejectTraversal(p string) (string, error) {
	if p == "" {
		return "", errors.New("path is required")
	}
	for _, seg := range strings.Split(filepath.ToSlash(p), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal rejected: %s", p)
		}
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", fmt.Errorf("resolve abs: %w", err)
	}
	return abs, nil
}

// validateCDPLoopback mirrors validateCDPLoopbackMCP from the MCP tool
// (T-08-04: refuse non-loopback unless allow_remote_cdp is set).
func validateCDPLoopback(rawURL string, allowRemote bool) error {
	if rawURL == "" {
		return errors.New("cdp_url is required")
	}
	if allowRemote {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parse cdp_url: %w", err)
	}
	host := u.Hostname()
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return nil
	default:
		return fmt.Errorf("cdp_url host %q is not loopback (set allow_remote_cdp=true to opt out)", host)
	}
}

// ---------- handlers ----------

func (sv *Supervisor) captureList(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p CaptureListParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.list: " + err.Error()}
		}
	}
	if p.Directory == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.list: directory is required"}
	}
	entries, err := os.ReadDir(p.Directory)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.list: read directory: %w", err).Error()}
	}
	var files []CaptureFileInfo
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(p.Directory, entry.Name())
		session, err := capture.ReadFile(path)
		if err != nil {
			// Skip unreadable entries — non-fatal, matches MCP tool behavior.
			continue
		}
		files = append(files, CaptureFileInfo{
			File:       entry.Name(),
			AppName:    session.App.Name,
			Framework:  session.App.Framework,
			EventCount: len(session.Events),
			DurationMs: session.Capture.DurationMs,
		})
	}
	return CaptureListResult{Captures: files}, nil
}

func (sv *Supervisor) captureDiff(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p CaptureDiffParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.diff: " + err.Error()}
	}
	if p.BeforeFile == "" || p.AfterFile == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.diff: before_file and after_file are required"}
	}
	before, err := capture.ReadFile(p.BeforeFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: fmt.Errorf("capture.diff: read before file: %w", err).Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.diff: read before file: %w", err).Error()}
	}
	after, err := capture.ReadFile(p.AfterFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: fmt.Errorf("capture.diff: read after file: %w", err).Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.diff: read after file: %w", err).Error()}
	}
	res := capturediff.Compare(before, after, p.BeforeFile, p.AfterFile)
	return res, nil
}

func (sv *Supervisor) captureVisualDiff(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p CaptureVisualDiffParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.visual_diff: " + err.Error()}
	}
	oldAbs, err := rejectTraversal(p.OldRunDir)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual_diff: old_run_dir: %w", err).Error()}
	}
	newAbs, err := rejectTraversal(p.NewRunDir)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual_diff: new_run_dir: %w", err).Error()}
	}
	res, err := capturediff.CompareVisual(oldAbs, newAbs)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.visual_diff: %w", err).Error()}
	}
	return CaptureVisualDiffResult{Visual: res}, nil
}

func (sv *Supervisor) captureStateReplay(_ context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p CaptureStateReplayParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.state_replay: " + err.Error()}
	}
	if p.RunID == "" || p.Component == "" || p.StateSlug == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.state_replay: run_id, component, and state_slug are required"}
	}
	// Conservative slug check mirrors the MCP tool (no `..` or path separators).
	for _, seg := range []string{p.RunID, p.Component, p.StateSlug} {
		if strings.ContainsAny(seg, "/\\") || seg == ".." {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("capture.state_replay: segment rejected: %q", seg)}
		}
	}
	kbAbs, err := rejectTraversal(p.KBDir)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.state_replay: kb_dir: %w", err).Error()}
	}
	stateDir := filepath.Join(kbAbs, "visual", p.RunID, p.Component, p.StateSlug)
	metaPath := filepath.Join(stateDir, "_meta.json")
	body, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: fmt.Errorf("capture.state_replay: read state meta: %w", err).Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.state_replay: read state meta: %w", err).Error()}
	}
	var meta struct {
		Mode         string          `json:"mode"`
		ScenarioPath string          `json:"scenario_path,omitempty"`
		Steps        json.RawMessage `json:"steps,omitempty"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.state_replay: parse state meta: %w", err).Error()}
	}
	res := CaptureStateReplayResult{Mode: meta.Mode, StatePath: stateDir, Steps: meta.Steps}
	if meta.Mode != "scripted" {
		res.Note = fmt.Sprintf("state was captured in %q mode; no scripted steps available", meta.Mode)
	}
	return res, nil
}

func (sv *Supervisor) captureVisual(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p CaptureVisualParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.visual: " + err.Error()}
	}
	if err := validateCDPLoopback(p.CDPURL, p.AllowRemoteCDP); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual: %w", err).Error()}
	}
	kbAbs, err := rejectTraversal(p.KBDir)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual: kb_dir: %w", err).Error()}
	}
	if err := os.MkdirAll(kbAbs, 0o755); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.visual: mkdir kb: %w", err).Error()}
	}

	scenarioAbs := ""
	if p.Scenario != "" {
		abs, err := rejectTraversal(p.Scenario)
		if err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual: scenario: %w", err).Error()}
		}
		st, err := os.Lstat(abs)
		if err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: fmt.Errorf("capture.visual: scenario stat: %w", err).Error()}
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("capture.visual: scenario refuses symlink: %s", abs)}
		}
		if !st.Mode().IsRegular() {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("capture.visual: scenario must be a regular file: %s", abs)}
		}
		scenarioAbs = abs
	}

	viewports, err := visual.ParseViewports(p.Viewports)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual: viewports: %w", err).Error()}
	}

	u, err := url.Parse(p.CDPURL)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("capture.visual: parse cdp_url: %w", err).Error()}
	}
	host := u.Host
	if host == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("capture.visual: cdp_url missing host:port in %q", p.CDPURL)}
	}

	events := make(chan capture.Event, 256)
	var seq int64
	seqFn := func() int { return int(atomic.AddInt64(&seq, 1)) }
	cli := cdp.New(host, events, seqFn)

	targets, err := cli.DiscoverTargets(ctx)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeUpstream, Message: fmt.Errorf("capture.visual: discover CDP targets at %s: %w", host, err).Error()}
	}
	var ws string
	for _, t := range targets {
		if t.Type == "page" && t.WebSocketDebugURL != "" {
			ws = t.WebSocketDebugURL
			break
		}
	}
	if ws == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: fmt.Sprintf("capture.visual: no debuggable page target at %s", host)}
	}
	if err := cli.Connect(ctx, ws); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeUpstream, Message: fmt.Errorf("capture.visual: connect CDP ws: %w", err).Error()}
	}
	defer func() { _ = cli.Close() }()

	mode := visual.Mode(strings.ToLower(strings.TrimSpace(p.Mode)))
	switch mode {
	case visual.ModeAuto, visual.ModeInteractive, visual.ModeScripted, "":
	default:
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("capture.visual: mode %q invalid (auto|interactive|scripted)", p.Mode)}
	}

	runID := time.Now().UTC().Format("2006-01-02T15-04-05Z")
	orch, err := visual.New(cli, visual.Options{
		Mode:           mode,
		KBDir:          kbAbs,
		RunID:          runID,
		Viewports:      viewports,
		MaxStates:      p.MaxStates,
		ScenarioPath:   scenarioAbs,
		ModalSettleMs:  p.ModalSettleMs,
		PHashThreshold: p.PHashThreshold,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.visual: orchestrator: %w", err).Error()}
	}
	if err := orch.Run(ctx); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("capture.visual: run: %w", err).Error()}
	}
	_ = visual.WriteLatestPointer(kbAbs, runID) // non-fatal

	caps := orch.Captures()
	return CaptureVisualResult{
		RunID:    runID,
		KBDir:    kbAbs,
		States:   len(caps),
		Captures: caps,
	}, nil
}

func (sv *Supervisor) captureWebView2Attach(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	start := time.Now()
	var p CaptureWebView2AttachParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.webview2_attach: " + err.Error()}
	}
	out := CaptureWebView2AttachResult{Kind: p.Kind}
	if p.Kind == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "capture.webview2_attach: kind is required (wa-desktop or teams-desktop)"}
	}
	preset, ok := webview2.PresetFor(p.Kind)
	if !ok {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("capture.webview2_attach: unknown kind %q (wa-desktop or teams-desktop)", p.Kind)}
	}
	logger := slog.Default()
	if err := webview2.SelfHeal(ctx, logger); err != nil {
		out.Error = fmt.Sprintf("self-heal: %v", err)
		out.ElapsedMS = time.Since(start).Milliseconds()
		return out, nil
	}
	port := p.Port
	if port == 0 {
		port = preset.Port
	}
	target := webview2.Target{
		Kind:   p.Kind,
		Port:   port,
		NoKill: p.NoKill,
	}
	att, err := webview2.Ensure(ctx, target)
	if err != nil {
		out.Error = fmt.Sprintf("webview2 ensure %s: %v", p.Kind, err)
		out.ElapsedMS = time.Since(start).Milliseconds()
		return out, nil
	}
	out.Attached = true
	out.Spawned = att.Spawned
	out.PID = att.PID
	out.ElapsedMS = time.Since(start).Milliseconds()
	return out, nil
}
