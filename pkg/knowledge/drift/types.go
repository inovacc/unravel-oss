/*
Copyright (c) 2026 Security Research
*/
// Package drift detects baseline-vs-recent regressions in the kb-enrich
// pipeline. Pure SQL + arithmetic; no LLM calls.
//
// Spec: docs/superpowers/specs/2026-05-27-phase-g-drift-detection-design.md
package drift

import "time"

// RunMetrics is the metric set computed from a single enrich_runs row.
// All rate metrics are in [0, 1]. MeanCostMicroUSD is integer-ish (micro-USD)
// stored as float64 for arithmetic uniformity with the rates.
type RunMetrics struct {
	RunID            string // uuid from enrich_runs.run_id
	App              string
	SuccessRate      float64 // modules with summary AND !needs_human_verification / total
	EscalationRate   float64 // modules with escalated_to = 'opus' / total
	HumanReviewRate  float64 // modules with needs_human_verification = true / total
	MeanCostMicroUSD float64 // SUM(enrich_attempts.cost_micro_usd) / total
	ModulesProcessed int     // min-run-size guard input
}

// MetricDelta is one metric's drift verdict.
type MetricDelta struct {
	Metric        string // matches drift_alerts.metric CHECK values
	BaselineValue float64
	RecentValue   float64
	RelativeDelta float64 // (recent - baseline) / max(baseline, 0.01)
	Drifted       bool    // |RelativeDelta| >= Opts.ThresholdRelative
}

// DriftVerdict is the orchestrator's combined output.
type DriftVerdict struct {
	Drifted           bool
	Deltas            []MetricDelta
	BaselineRunID     string // uuid from enrich_runs.run_id
	RecentRunID       string // uuid from enrich_runs.run_id
	ThresholdRelative float64
	Skipped           bool
	SkipReason        string // "no_baseline" | "run_too_small" | ""
}

// Opts controls drift.Check behaviour.
type Opts struct {
	ThresholdRelative float64
	MinRunSize        int
	Now               func() time.Time // injectable for tests
}

// DefaultOpts returns the production defaults: 20% relative threshold,
// 25 modules minimum, time.Now.
func DefaultOpts() Opts {
	return Opts{
		ThresholdRelative: 0.20,
		MinRunSize:        25,
		Now:               time.Now,
	}
}
