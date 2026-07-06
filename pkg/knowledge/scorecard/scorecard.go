/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// Evidence is an opaque pointer into the DissectResult or ResultSet that
// justifies a DimScore. Kind is one of "field", "result_set", "file",
// "missing", "runtime".
//
// Citation (P58, additive) — pointer at the source artifact this Evidence
// was derived from, relative to the target's KBOutputDir. nil for
// Kind:"missing" (lenient rule, see citations.go) and for pre-P58 callers
// (omitempty preserves D-10 byte-shape).
type Evidence struct {
	Kind     string    `json:"kind"`
	Source   string    `json:"source,omitempty"`
	Path     string    `json:"path,omitempty"`
	Detail   string    `json:"detail,omitempty"`
	Citation *Citation `json:"citation,omitempty"`
}

// DimScore is the result for a single dimension. Score is integer 0..100.
//
// MissingCitations (P58) — count of non-missing Evidence entries on this
// dim that lack a Citation. Populated by ComputeCitationsOK; omitempty so
// dims with zero missing-citations stay byte-identical to pre-P58.
type DimScore struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Score            int        `json:"score"`
	Evidence         []Evidence `json:"evidence,omitempty"`
	MissingCitations int        `json:"missing_citations,omitempty"`
}

// Scorecard is the aggregated rubric output. NEVER stored on DissectResult
// (D-10). Dimensions is an ordered slice in canonical dim order (dims.go).
// Coverage counts dimensions with Score >= 80 (mirrors W-## dims_at_80).
//
// CitationsOK (P58) — gate state computed by ComputeCitationsOK. ALWAYS
// emitted (no omitempty per decision 5) so consumers can rely on the field
// being present.
type Scorecard struct {
	KbID        string     `json:"kb_id"`
	Dimensions  []DimScore `json:"dimensions"`
	Coverage    int        `json:"coverage"`
	CitationsOK bool       `json:"citations_ok"`
}

// Scorer scores a single dimension from a DissectResult and ResultSet.
type Scorer interface {
	ID() string
	Name() string
	Score(r *dissect.DissectResult, rs *analysis.ResultSet) DimScore
}
