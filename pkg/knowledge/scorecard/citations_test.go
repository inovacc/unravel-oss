/*
Copyright (c) 2026 Security Research
*/

// P58 Task 58-03 — ComputeCitationsOK (lenient rule) tests.
package scorecard

import (
	"testing"
)

func TestComputeCitationsOK_AllCited(t *testing.T) {
	sc := &Scorecard{
		Dimensions: []DimScore{
			{ID: "identity", Evidence: []Evidence{
				{Kind: "field", Citation: &Citation{File: "a.md"}},
				{Kind: "field", Citation: &Citation{File: "b.md"}},
			}},
			{ID: "wire", Evidence: []Evidence{
				{Kind: "field", Citation: &Citation{File: "c.md"}},
				{Kind: "missing", Source: "runtime"}, // exempt
			}},
		},
	}
	if !ComputeCitationsOK(sc) {
		t.Errorf("expected true; got false")
	}
	if !sc.CitationsOK {
		t.Errorf("sc.CitationsOK not set true")
	}
	for _, d := range sc.Dimensions {
		if d.MissingCitations != 0 {
			t.Errorf("dim %s MissingCitations=%d, want 0", d.ID, d.MissingCitations)
		}
	}
}

func TestComputeCitationsOK_PartialMissing(t *testing.T) {
	sc := &Scorecard{
		Dimensions: []DimScore{
			{ID: "identity", Evidence: []Evidence{
				{Kind: "field", Citation: &Citation{File: "a.md"}},
			}},
			{ID: "auth", Evidence: []Evidence{
				{Kind: "field"}, // uncited!
				{Kind: "field"}, // uncited!
				{Kind: "missing", Source: "runtime"},
			}},
		},
	}
	if ComputeCitationsOK(sc) {
		t.Errorf("expected false")
	}
	if sc.CitationsOK {
		t.Errorf("sc.CitationsOK not set false")
	}
	if sc.Dimensions[0].MissingCitations != 0 {
		t.Errorf("identity MissingCitations=%d, want 0", sc.Dimensions[0].MissingCitations)
	}
	if sc.Dimensions[1].MissingCitations != 2 {
		t.Errorf("auth MissingCitations=%d, want 2", sc.Dimensions[1].MissingCitations)
	}
}

func TestComputeCitationsOK_OnlyMissingKind_Exempt(t *testing.T) {
	// Lenient rule: a dim with only Kind:"missing" Evidence is gate-compliant.
	sc := &Scorecard{
		Dimensions: []DimScore{
			{ID: "behavior", Evidence: []Evidence{
				{Kind: "missing", Source: "runtime"},
				{Kind: "missing", Source: "loop", Detail: "no deepening pass available for behavior in P57"},
			}},
		},
	}
	if !ComputeCitationsOK(sc) {
		t.Errorf("expected true under lenient rule")
	}
	if sc.Dimensions[0].MissingCitations != 0 {
		t.Errorf("MissingCitations=%d, want 0", sc.Dimensions[0].MissingCitations)
	}
}

func TestComputeCitationsOK_EmptyScorecard(t *testing.T) {
	sc := &Scorecard{}
	if !ComputeCitationsOK(sc) {
		t.Errorf("expected true for empty scorecard")
	}
}

func TestComputeCitationsOK_Nil(t *testing.T) {
	if !ComputeCitationsOK(nil) {
		t.Errorf("expected true for nil scorecard")
	}
}

func TestComputeCitationsOK_Idempotent(t *testing.T) {
	sc := &Scorecard{
		Dimensions: []DimScore{
			{ID: "auth", Evidence: []Evidence{
				{Kind: "field"}, // uncited
				{Kind: "field"}, // uncited
			}},
		},
	}
	first := ComputeCitationsOK(sc)
	firstMiss := sc.Dimensions[0].MissingCitations
	second := ComputeCitationsOK(sc)
	secondMiss := sc.Dimensions[0].MissingCitations
	if first != second {
		t.Errorf("non-idempotent: %v -> %v", first, second)
	}
	if firstMiss != secondMiss {
		t.Errorf("counter doubled: %d -> %d", firstMiss, secondMiss)
	}
	if firstMiss != 2 {
		t.Errorf("MissingCitations=%d, want 2", firstMiss)
	}
}

func TestComputeCitationsOK_EmptyFileTreatedAsUncited(t *testing.T) {
	// A Citation with empty File is treated as uncited (validity rule).
	sc := &Scorecard{
		Dimensions: []DimScore{
			{ID: "x", Evidence: []Evidence{
				{Kind: "field", Citation: &Citation{File: ""}},
			}},
		},
	}
	if ComputeCitationsOK(sc) {
		t.Errorf("expected false; empty Citation.File should not satisfy gate")
	}
	if sc.Dimensions[0].MissingCitations != 1 {
		t.Errorf("MissingCitations=%d, want 1", sc.Dimensions[0].MissingCitations)
	}
}
