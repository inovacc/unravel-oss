/*
Copyright (c) 2026 Security Research

gate.go: precision gate dispatcher + stability invariant.
defaultGateVersion is the single-constant active gate; "v2" per
D-40-ATOMIC-FLIP-WITH-GUARD.

License: BSD-3-Clause.
*/
package eval

import (
	"fmt"
)

// defaultGateVersion is the active classifier-precision gate.
const defaultGateVersion = "v2"

// RunGate dispatches to the named precision runner against a v2 corpus path.
// Empty version uses defaultGateVersion.
func RunGate(corpusPath string, version string) (*PrecisionResult, error) {
	if version == "" {
		version = defaultGateVersion
	}
	switch version {
	case "v2":
		return RunCorpusV2(corpusPath)
	default:
		return nil, fmt.Errorf("unknown gate version %q (want v2)", version)
	}
}

// StabilityCheck returns true when len(results) >= 3 AND every result.Precision >= threshold.
// Used as the gate-flip stability invariant per D-40-ATOMIC-FLIP-WITH-GUARD.
// Boundary semantics: Precision == threshold passes (>= not >).
func StabilityCheck(results []PrecisionResult, threshold float64) bool {
	if len(results) < 3 {
		return false
	}
	for _, r := range results {
		if r.Precision < threshold {
			return false
		}
	}
	return true
}
