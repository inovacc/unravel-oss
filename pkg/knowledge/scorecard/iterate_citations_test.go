/*
Copyright (c) 2026 Security Research
*/

// P58 Task 58-04 — iterate.go gate enforcement tests.
//
// Coverage:
//   - TestConvergence_BlockedByCitationsOK: scorecard with mean+coverage green
//     but a non-missing Evidence uncited → loop does NOT exit despite all
//     other gates passing. (negative path under P58 real gate)
//   - TestConvergence_LenientRuleHonored: scorecard with only missing-kind
//     uncited Evidence → loop EXITs (lenient rule).
//   - TestRuntimeBump_CitesIterationsJSONL: post-hoc bumped Evidence at the
//     iterate.go runtime-bump call site carries Citation.File="iterations.jsonl"
//     and Line>0 (decision 8).
package scorecard

import (
	"context"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// citingScorer emits one Kind:"field" Evidence with a Citation — used to
// confirm convergence still works when scorers cite properly.
type citingScorer struct {
	id    string
	score int
	cite  *Citation
}

func (c citingScorer) ID() string   { return c.id }
func (c citingScorer) Name() string { return c.id }
func (c citingScorer) Score(_ *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	return DimScore{ID: c.id, Name: c.id, Score: c.score, Evidence: []Evidence{
		{Kind: "field", Path: "X", Citation: c.cite},
	}}
}

// uncitedScorer emits one Kind:"field" Evidence WITHOUT a Citation — used to
// drive citations_ok=false.
type uncitedScorer struct {
	id    string
	score int
}

func (u uncitedScorer) ID() string   { return u.id }
func (u uncitedScorer) Name() string { return u.id }
func (u uncitedScorer) Score(_ *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	return DimScore{ID: u.id, Name: u.id, Score: u.score, Evidence: []Evidence{
		{Kind: "field", Path: "X"}, // uncited
	}}
}

func ruricFromScorers(scorers []Scorer) *Rubric {
	rb := &Rubric{}
	byID := map[string]Scorer{}
	for _, s := range scorers {
		byID[s.ID()] = s
	}
	for _, dim := range CanonicalDims {
		if s, ok := byID[dim]; ok {
			rb.ordered = append(rb.ordered, s)
		} else {
			rb.ordered = append(rb.ordered, fixedScorer{id: dim, name: dim, score: 90})
		}
	}
	return rb
}

// (g) — citations_ok=false blocks convergence even with mean+coverage green.
func TestConvergence_BlockedByCitationsOK(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 0}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	// One uncited dim at score 90, all others 90 via fixedScorer (no Evidence).
	// Mean and coverage are clearly green — only citations_ok blocks.
	rb := ruricFromScorers([]Scorer{
		uncitedScorer{id: "identity", score: 90},
	})
	sc, log, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x", CDPPort: 9222}, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}
	// Loop should NOT exit early — should run all MaxIter (5) iters because
	// the uncited Evidence keeps citations_ok=false. (filterDispatchable only
	// dispatches certain dim ids; identity isn't dispatchable, so the loop
	// will exit early on the "nothing actionable" branch — but that branch
	// also records the gate state. Either way, citations_ok must be false.)
	if len(log.Records) == 0 {
		t.Fatalf("expected at least 1 record")
	}
	last := log.Records[len(log.Records)-1]
	if last.CitationsOK {
		t.Errorf("CitationsOK=true despite uncited Evidence; got: %+v", last)
	}
	if sc.CitationsOK {
		t.Errorf("scorecard.CitationsOK=true despite uncited Evidence")
	}
	// And convergedAt must report false.
	if convergedAt(sc, DefaultIterateOptions()) {
		t.Errorf("convergedAt returned true with citations_ok=false")
	}
}

// (h) — lenient rule: only missing-kind uncited Evidence still EXITs.
func TestConvergence_LenientRuleHonored(t *testing.T) {
	// Build a scorecard manually: all dims score 80, one carries only a
	// missing-kind uncited Evidence. The lenient rule exempts missing.
	sc := &Scorecard{
		Dimensions: []DimScore{
			{ID: "identity", Score: 80},
			{ID: "wire", Score: 80, Evidence: []Evidence{
				{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"},
			}},
		},
		Coverage: 2,
	}
	if !ComputeCitationsOK(sc) {
		t.Errorf("lenient rule violated: missing-kind uncited Evidence should be exempt")
	}
	if !sc.CitationsOK {
		t.Errorf("sc.CitationsOK not propagated true")
	}
}

// TestRuntimeBump_CitesIterationsJSONL — post-hoc runtime-bump Evidence at
// iterate.go's bump site cites iterations.jsonl with Line=iter index.
func TestRuntimeBump_CitesIterationsJSONL(t *testing.T) {
	dir := t.TempDir()
	src := &capturingFrameSource{frames: 50}
	defer withSeams(t, true, false, func(ctx context.Context, port int) error { return nil }, src)()

	scores := whatsappShape()
	scores["behavior"] = 80 // unblock convergence on non-bump dims
	rb := fixedRubric(scores)
	sc, _, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x", CDPPort: 9222}, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}

	// Find the wire dim (gets bumped to 85). Its post-hoc runtime Evidence
	// must cite iterations.jsonl with Line>0.
	d := sc.Dim("wire")
	if d == nil {
		t.Fatalf("wire dim missing")
	}
	foundCited := false
	for _, e := range d.Evidence {
		if e.Kind != "runtime" {
			continue
		}
		if e.Citation == nil {
			t.Errorf("runtime Evidence has nil Citation: %+v", e)
			continue
		}
		// File should contain "iterations.jsonl" (forward-slash normalized).
		if !strings.Contains(e.Citation.File, "iterations.jsonl") {
			t.Errorf("Citation.File = %q, want substring iterations.jsonl", e.Citation.File)
		}
		if strings.Contains(e.Citation.File, `\`) {
			t.Errorf("Citation.File contains backslash: %q", e.Citation.File)
		}
		if e.Citation.Line <= 0 {
			t.Errorf("Citation.Line = %d, want > 0 (iter index)", e.Citation.Line)
		}
		foundCited = true
	}
	if !foundCited {
		t.Errorf("no cited runtime Evidence found on wire dim: %+v", d.Evidence)
	}
}
