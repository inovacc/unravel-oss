package rearm

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/garble"
)

func TestCollectCandidates_JSHighObfuscation(t *testing.T) {
	r := &dissect.DissectResult{
		JSAnalysis:   &dissect.JSAnalysisResult{ObfuscationScore: 80, File: "app.js"},
		BeautifiedJS: "function a(){return 1}var b=2;",
	}
	got := CollectCandidates(r)
	if len(got) != 1 || got[0].Lang != "js" {
		t.Fatalf("want 1 js candidate, got %+v", got)
	}
	if got[0].Signal < 80 || got[0].Source == "" {
		t.Fatalf("signal/source not populated: %+v", got[0])
	}
}

func TestCollectCandidates_BelowThresholdAndEmptyHonest(t *testing.T) {
	if c := CollectCandidates(&dissect.DissectResult{JSAnalysis: &dissect.JSAnalysisResult{ObfuscationScore: 10}}); len(c) != 0 {
		t.Fatalf("below-threshold JS must not be a candidate: %+v", c)
	}
	if c := CollectCandidates(&dissect.DissectResult{}); len(c) != 0 {
		t.Fatalf("empty result must yield no candidates")
	}
	if c := CollectCandidates(nil); len(c) != 0 {
		t.Fatalf("nil must be safe and empty")
	}
}

func TestCollectCandidates_Garble(t *testing.T) {
	r := &dissect.DissectResult{
		GarbleDetect: &garble.DetectionResult{IsGarbled: true},
		GarbleSymbols: &garble.SymbolsResult{
			ObfuscatedCount: 3,
			TopObfuscated:   []string{"aB", "cD"},
		},
	}
	got := CollectCandidates(r)
	if len(got) != 1 || got[0].Lang != "go" {
		t.Fatalf("want 1 go candidate, got %+v", got)
	}
	if got[0].HeuristicHint != "garble" || got[0].Signal != 90 {
		t.Fatalf("garble candidate not populated: %+v", got[0])
	}
}

func TestCollectCandidates_UWPSidecarSource(t *testing.T) {
	bundle := strings.Repeat("var x=1;function f(){};", 20000) // ~460k, >200k
	r := &dissect.DissectResult{
		JSAnalysis:        &dissect.JSAnalysisResult{ObfuscationScore: 0, File: "app.js"},
		RecoveredJSSource: bundle,
	}
	got := CollectCandidates(r)
	js := 0
	for _, c := range got {
		if c.Lang != "js" {
			continue
		}
		js++
		if len(c.Source) > 256*1024 {
			t.Errorf("Source len = %d, want <= %d", len(c.Source), 256*1024)
		}
		if c.Signal < 70 {
			t.Errorf("Signal = %d, want >= 70", c.Signal)
		}
		if c.ModuleRef != "app.js" {
			t.Errorf("ModuleRef = %q, want app.js", c.ModuleRef)
		}
	}
	if js != 1 {
		t.Fatalf("js candidates = %d, want 1", js)
	}

	// Honest-empty: no BeautifiedJS, no RecoveredJSSource, low score => none.
	empty := &dissect.DissectResult{
		JSAnalysis: &dissect.JSAnalysisResult{ObfuscationScore: 0, File: "app.js"},
	}
	for _, c := range CollectCandidates(empty) {
		if c.Lang == "js" {
			t.Fatalf("expected no js candidate for honest-empty input")
		}
	}
}
