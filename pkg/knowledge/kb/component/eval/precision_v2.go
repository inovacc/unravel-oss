/*
Copyright (c) 2026 Security Research

precision_v2.go: P40 — gate runner for v2 corpus (Pass-B human-relabeled).
Mirrors RunCorpus signature footprint so Plan 40-03 atomic flip is a single
constant swap.

Deterministic: same corpus → same PrecisionResult. No map iteration in calc,
no time.Now, no randomness.

Path remap (Plan 40-02 deviation): planner referenced fictional
pkg/knowledge/kb/classify/. Actual layout puts this alongside
component/eval/eval.go (RunCorpus v1 sibling).

License: BSD-3-Clause.
*/
package eval

import "fmt"

// PrecisionResult records counts + computed precision.
//
// Precision excludes "pending" entries from BOTH numerator and denominator
// (only reviewed entries count toward the gate). Rejected entries count toward
// Reviewed but never toward the correct numerator.
//
// Precision = (entries with predicted == human AND status in {accepted, edited}) / Reviewed
type PrecisionResult struct {
	Precision float64 `json:"precision"`
	Total     int     `json:"total"`
	Reviewed  int     `json:"reviewed"`
	Accepted  int     `json:"accepted"`
	Rejected  int     `json:"rejected"`
	Edited    int     `json:"edited"`
	Pending   int     `json:"pending"`
}

// PrecisionV2 computes precision against a Pass-B relabeled corpus.
// Returns error when corpus is nil OR has zero reviewed entries.
func PrecisionV2(c *CorpusV2) (PrecisionResult, error) {
	if c == nil {
		return PrecisionResult{}, fmt.Errorf("nil corpus")
	}
	var r PrecisionResult
	r.Total = len(c.Entries)
	var correct int
	for _, e := range c.Entries {
		switch e.ReviewStatus {
		case "accepted":
			r.Accepted++
			r.Reviewed++
			if e.PredictedLabel == e.HumanLabel {
				correct++
			}
		case "edited":
			r.Edited++
			r.Reviewed++
			if e.PredictedLabel == e.HumanLabel {
				correct++
			}
		case "rejected":
			r.Rejected++
			r.Reviewed++
		case "pending":
			r.Pending++
		default:
			return PrecisionResult{}, fmt.Errorf("entry %s: unknown review_status %q", e.ID, e.ReviewStatus)
		}
	}
	if r.Reviewed == 0 {
		return r, fmt.Errorf("no reviewed entries (all %d pending)", r.Pending)
	}
	r.Precision = float64(correct) / float64(r.Reviewed)
	return r, nil
}

// RunCorpusV2 reads a v2 corpus from disk and runs PrecisionV2. Mirrors the
// RunCorpus(path) entry point used by the v1 gate.
func RunCorpusV2(path string) (*PrecisionResult, error) {
	c, err := LoadCorpusV2(path)
	if err != nil {
		return nil, err
	}
	r, err := PrecisionV2(c)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
