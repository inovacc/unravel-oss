/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"encoding/json"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func TestRubric_EmptyDissectResultProducesAllZeros(t *testing.T) {
	rb := New()
	sc := rb.Score(&dissect.DissectResult{}, nil)
	if got, want := len(sc.Dimensions), len(CanonicalDims); got != want {
		t.Fatalf("Dimensions len = %d, want %d", got, want)
	}
	for i, d := range sc.Dimensions {
		if d.ID != CanonicalDims[i] {
			t.Errorf("Dimensions[%d].ID = %q, want %q", i, d.ID, CanonicalDims[i])
		}
		if d.Score < 0 || d.Score > 100 {
			t.Errorf("Dimensions[%d].Score = %d out of [0,100]", i, d.Score)
		}
	}
}

type mockScorer struct {
	id    string
	name  string
	score int
}

func (m mockScorer) ID() string   { return m.id }
func (m mockScorer) Name() string { return m.name }
func (m mockScorer) Score(_ *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	return DimScore{ID: m.id, Name: m.name, Score: m.score}
}

type panickyScorer struct{}

func (panickyScorer) ID() string   { return "identity" }
func (panickyScorer) Name() string { return "Identity" }
func (panickyScorer) Score(_ *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	panic("boom")
}

func withScorers(t *testing.T, scs []Scorer, fn func()) {
	t.Helper()
	saved := append([]Scorer(nil), scorers...)
	resetScorersForTest()
	for _, s := range scs {
		Register(s)
	}
	defer func() {
		resetScorersForTest()
		for _, s := range saved {
			Register(s)
		}
	}()
	fn()
}

func TestRubric_RegistryEmpty_ReturnsAllPlaceholders(t *testing.T) {
	withScorers(t, nil, func() {
		sc := New().Score(&dissect.DissectResult{}, nil)
		if len(sc.Dimensions) != len(CanonicalDims) {
			t.Fatalf("len = %d, want %d", len(sc.Dimensions), len(CanonicalDims))
		}
		for _, d := range sc.Dimensions {
			if d.Score != 0 {
				t.Errorf("dim %s score = %d, want 0", d.ID, d.Score)
			}
		}
		if sc.Coverage != 0 {
			t.Errorf("Coverage = %d, want 0", sc.Coverage)
		}
	})
}

func TestRubric_PreservesCanonicalOrderAcrossInitOrdering(t *testing.T) {
	scs := []Scorer{
		mockScorer{id: "behavior", name: "Behavior", score: 90},
		mockScorer{id: "identity", name: "Identity", score: 90},
		mockScorer{id: "filesystem", name: "Filesystem", score: 95},
		mockScorer{id: "binary_surface", name: "Binary surface", score: 70},
		mockScorer{id: "source_layer", name: "Source layer", score: 90},
		mockScorer{id: "ipc", name: "IPC", score: 50},
		mockScorer{id: "api", name: "API", score: 75},
		mockScorer{id: "wire", name: "Wire", score: 65},
		mockScorer{id: "storage", name: "Storage", score: 90},
		mockScorer{id: "auth", name: "Auth", score: 70},
		mockScorer{id: "crypto", name: "Crypto", score: 85},
		mockScorer{id: "state_machines", name: "State machines", score: 80},
	}
	withScorers(t, scs, func() {
		sc := New().Score(&dissect.DissectResult{}, nil)
		for i, d := range sc.Dimensions {
			if d.ID != CanonicalDims[i] {
				t.Errorf("Dimensions[%d].ID = %q, want %q", i, d.ID, CanonicalDims[i])
			}
		}
		// Coverage = count >= 80: identity(90) filesystem(95) source_layer(90)
		// storage(90) crypto(85) state_machines(80) behavior(90) = 7
		if sc.Coverage != 7 {
			t.Errorf("Coverage = %d, want 7", sc.Coverage)
		}
	})
}

func TestRubric_PanicRecovery(t *testing.T) {
	withScorers(t, []Scorer{panickyScorer{}}, func() {
		sc := New().Score(&dissect.DissectResult{}, nil)
		if got := sc.Dimensions[0]; got.ID != "identity" || got.Score != 0 {
			t.Errorf("identity dim = %+v, want id=identity score=0", got)
		}
		if len(sc.Dimensions[0].Evidence) == 0 || sc.Dimensions[0].Evidence[0].Kind != "missing" {
			t.Errorf("expected missing-evidence note on panic, got %+v", sc.Dimensions[0].Evidence)
		}
	})
}

func TestScorecard_JSONRoundTripUsesSnakeCase(t *testing.T) {
	// no-float CI hint: package source must keep RUBR-04 (integer scores
	// only) — `grep float[36][24] pkg/knowledge/scorecard/*.go` excluding
	// _test.go files must return zero hits.
	in := Scorecard{
		KbID: "kb-x",
		Dimensions: []DimScore{
			{ID: "identity", Name: "Identity", Score: 90, Evidence: []Evidence{{Kind: "field", Path: "Detection"}}},
		},
		Coverage: 1,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{`"kb_id"`, `"dimensions"`, `"coverage"`, `"score"`, `"evidence"`, `"kind"`, `"path"`} {
		if !contains(s, want) {
			t.Errorf("snake_case key %s missing in %s", want, s)
		}
	}
	var out Scorecard
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.KbID != in.KbID || len(out.Dimensions) != 1 || out.Dimensions[0].Score != 90 {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) <= len(haystack) && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestComputeCoverage(t *testing.T) {
	cases := []struct {
		name string
		in   []DimScore
		want int
	}{
		{"empty", nil, 0},
		{"all-zero", []DimScore{{Score: 0}, {Score: 0}}, 0},
		{"all-eighty", []DimScore{{Score: 80}, {Score: 80}, {Score: 80}}, 3},
		{"mixed", []DimScore{{Score: 79}, {Score: 80}, {Score: 81}, {Score: 100}}, 3},
		{"twelve-mixed", []DimScore{
			{Score: 90}, {Score: 95}, {Score: 70}, {Score: 90},
			{Score: 50}, {Score: 75}, {Score: 65}, {Score: 90},
			{Score: 70}, {Score: 85}, {Score: 80}, {Score: 85},
		}, 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := computeCoverage(tc.in); got != tc.want {
				t.Errorf("computeCoverage = %d, want %d", got, tc.want)
			}
		})
	}
}
