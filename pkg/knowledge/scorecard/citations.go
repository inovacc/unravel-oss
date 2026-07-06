/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P58 citations gate walker.
//
// ComputeCitationsOK applies the lenient citation rule (decision 4):
//
//	citations_ok = ∀ Evidence e in Scorecard.Dimensions:
//	                 e.Kind == "missing"  ∨  e.Citation != nil
//
// Lenient-rule rationale (decision 4): static-only analysis targets always
// produce missing-kind Evidence for runtime-gap dimensions (wire, auth,
// state_machines, behavior). A strict rule would break the P57 W1 contract
// ("static-only short-circuit emits a non-converged scorecard, not a
// gate-failed one"). The behavior dim's missing marker (applyBehaviorMissingMarker
// in iterate.go) is also exempt by the same rule.
//
// Blast radius: this rule trusts that "missing"-kind Evidence is legitimately
// missing — verified for the behavior dim per P57 Q6 review. P58's
// DimScore.MissingCitations counter (CITE-02) surfaces uncited non-missing
// Evidence so reviewers can audit each iteration. P59 renders that counter
// in SCORECARD.md so missing citations are visible to operators.
//
// W1 contract preservation: the static-only short-circuit at iterate.go:179
// remains independent of CitationsOK. Static-only targets exit on
// runtime_capture_unavailable=true, not on citations_ok=false — they emit a
// non-converged scorecard by design (P57 W1 docstring).
package scorecard

// ComputeCitationsOK walks every dim in the scorecard, sets each dim's
// MissingCitations counter from zero, and returns the scorecard-level gate
// value. Side effect: writes sc.CitationsOK = result.
//
// Idempotent: calling twice on the same scorecard yields identical
// MissingCitations values (counters are reset to zero before counting).
//
// nil-safe: ComputeCitationsOK(nil) returns true (vacuously satisfied) so
// callers never NPE on early-loop paths.
func ComputeCitationsOK(sc *Scorecard) bool {
	if sc == nil {
		return true
	}
	ok := true
	for i := range sc.Dimensions {
		d := &sc.Dimensions[i]
		miss := 0
		for _, e := range d.Evidence {
			if e.Kind == "missing" {
				continue
			}
			if e.Citation == nil || e.Citation.File == "" {
				miss++
			}
		}
		d.MissingCitations = miss
		if miss > 0 {
			ok = false
		}
	}
	sc.CitationsOK = ok
	return ok
}
