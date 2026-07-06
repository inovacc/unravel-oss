/*
Copyright (c) 2026 Security Research
*/

// Package depth provides per-dimension coverage scoring for KnowledgeResult.
//
// A Dimension records how many items a sub-extractor produced (Total)
// versus how many reached the published KnowledgeResult JSON (Covered).
// Ratio == 0 with Total > 0 is the loud-failure signal per D-37 in
// .planning/phases/37-knowledge-extractor-coverage-android/37-CONTEXT.md.
package depth

// Dimension reports per-platform extractor coverage.
type Dimension struct {
	Name    string  `json:"dimension"`
	Covered int     `json:"covered"`
	Total   int     `json:"total"`
	Ratio   float64 `json:"ratio"`
}

// NewDimension constructs a Dimension and computes Ratio.
// Ratio is 0.0 when Total == 0 (no signal absent != defect).
//
// Negative inputs are clamped to 0 per T-37-01: a manipulated DissectResult
// must not produce a negative Ratio that masks a coverage defect.
func NewDimension(name string, covered, total int) Dimension {
	if covered < 0 {
		covered = 0
	}
	if total < 0 {
		total = 0
	}
	var ratio float64
	if total > 0 {
		ratio = float64(covered) / float64(total)
	}
	return Dimension{Name: name, Covered: covered, Total: total, Ratio: ratio}
}

// RatioOK returns true when the dimension does not signal a coverage defect.
// Per D-37: Total == 0 is OK (dimension absent); Total > 0 with Ratio == 0
// is the failure signal.
func RatioOK(d Dimension) bool {
	if d.Total == 0 {
		return true
	}
	return d.Ratio > 0
}
