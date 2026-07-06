/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P57 iteration types.
//
// All scores are integers per D-10 byte-shape (B2): no floating-point types
// anywhere in iterate*.go or dispatch.go. The reported `mean` is the truncated
// integer mean across the 12 canonical dims (e.g. raw 78.4 → 78).
//
// This file holds pure type declarations only — no behavior, no init().
// Behavior lives in iterate.go, dispatch.go, iterate_log.go.
package scorecard

import (
	"time"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// DissectTarget bundles everything Rubric.Iterate needs to score and deepen a
// target. Result is the P56 DissectResult handle; AppDir is used by the
// framework gate (W1) before any CDP probe; KBOutputDir is where
// iterations.jsonl is written; CDPPort=0 means "no probe".
type DissectTarget struct {
	Result        *dissect.DissectResult // P56 result handle
	AnalysisSet   *analysis.ResultSet    // passed through to Score
	AppDir        string                 // for framework detection (W1)
	KBOutputDir   string                 // e.g. out/whatsapp-kb
	CDPPort       int                    // 0 = no probe
	FrameworkHint string                 // "electron" | "webview2" | ""
}

// IterateOptions configures the loop. INTEGER-ONLY per B2.
type IterateOptions struct {
	MaxIter        int           `json:"max_iter"`
	Threshold      int           `json:"threshold"` // INTEGER, default 80
	RequireAll12   bool          `json:"require_all_12"`
	PerIterTimeout time.Duration `json:"per_iter_timeout"`
}

// DefaultIterateOptions returns Q7/Q8 canonical defaults.
func DefaultIterateOptions() IterateOptions {
	return IterateOptions{
		MaxIter:        5,
		Threshold:      80,
		RequireAll12:   true,
		PerIterTimeout: 4 * time.Minute,
	}
}

// DispatchResult is the structured outcome of a single weak-dim deepening
// pass (B1 — NOT a bare string).
type DispatchResult struct {
	Pass           string   `json:"pass"`
	TargetDims     []string `json:"target_dims"`
	DurationMs     int64    `json:"duration_ms"`
	FramesCaptured int      `json:"frames_captured"`
	OK             bool     `json:"ok"`
	Note           string   `json:"note"`
}

// IterationRecord is the canonical RESEARCH.md JSONL shape, one record per
// loop iteration. Rich shape per B1; INTEGER-only per B2.
type IterationRecord struct {
	ID                        string           `json:"id"`   // "iter-N"
	Iter                      int              `json:"iter"` // 1-based
	TS                        string           `json:"ts"`   // RFC3339
	WeakDims                  []string         `json:"weak_dims"`
	Dispatched                []DispatchResult `json:"dispatched"`
	Bumps                     map[string]int   `json:"bumps"`
	Mean                      int              `json:"mean"`          // pre-bump truncated int
	Coverage                  int              `json:"coverage"`      // pre-bump
	PostMean                  int              `json:"post_mean"`     // after-bump
	PostCoverage              int              `json:"post_coverage"` // after-bump
	RuntimeCaptureUnavailable bool             `json:"runtime_capture_unavailable"`
	CitationsOK               bool             `json:"citations_ok"` // P58 hook; default false in P57
}

// IterationLog is the in-memory accumulation of records emitted by one
// Rubric.Iterate call. The on-disk JSONL file is append-mode across runs (W2).
type IterationLog struct {
	Records []IterationRecord `json:"records"`
}
