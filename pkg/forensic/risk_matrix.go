/*
Copyright (c) 2026 Security Research
*/
package forensic

import "fmt"

// Likelihood is the rough chance a finding is exploitable in practice.
type Likelihood int

// Impact is the rough blast-radius of the finding if exploited.
type Impact int

const (
	// LowL is the lowest likelihood bucket.
	LowL Likelihood = iota + 1
	// MedL is the medium likelihood bucket.
	MedL
	// HighL is the highest likelihood bucket.
	HighL
)

const (
	// LowI is the lowest impact bucket.
	LowI Impact = iota + 1
	// MedI is the medium impact bucket.
	MedI
	// HighI is the highest impact bucket.
	HighI
)

// riskMatrix is the canonical, code-not-config lookup (D-07).
// Per D-10: BLOCK severity overrides to (HighL, HighI); FLAG overrides to
// (MedL, MedI); PASS is excluded.
var riskMatrix = map[string]struct {
	L Likelihood
	I Impact
}{
	"csp_relaxation":        {MedL, HighI},
	"eval_or_unsafe_inline": {HighL, HighI},
	"dangerous_permission":  {MedL, HighI},
	"sandbox_removed":       {HighL, HighI},
	"hardcoded_credential":  {HighL, HighI},
	"telemetry_sdk_added":   {LowL, MedI},
	"content_protection":    {HighL, MedI},
	"module_count_delta_50": {MedL, LowI},
}

// RiskFor returns the (Likelihood, Impact, ok) tuple for a finding.
// Severity-override per D-10:
//
//	"PASS"  -> excluded (returns false)
//	"BLOCK" -> (HighL, HighI)
//	"FLAG"  -> (MedL,  MedI)
//
// Otherwise the per-finding-type lookup wins.
func RiskFor(findingType, severity string) (Likelihood, Impact, bool) {
	switch severity {
	case "PASS":
		return 0, 0, false
	case "BLOCK":
		return HighL, HighI, true
	case "FLAG":
		return MedL, MedI, true
	}
	if v, ok := riskMatrix[findingType]; ok {
		return v.L, v.I, true
	}
	return 0, 0, false
}

// MatrixCell returns a stable cell label "L<n>I<n>" for template rendering.
func MatrixCell(l Likelihood, i Impact) string {
	return fmt.Sprintf("L%dI%d", l, i)
}
