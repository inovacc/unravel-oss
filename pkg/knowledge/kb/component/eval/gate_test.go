/*
Copyright (c) 2026 Security Research
*/

package eval_test

import (
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/eval"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime"
)

func TestRunGate_EmptyVersionUsesDefault(t *testing.T) {
	r, err := eval.RunGate(filepath.Join("testdata", "corpus.json"), "")
	if err != nil {
		t.Fatalf("empty version: %v", err)
	}
	if r.Reviewed == 0 {
		t.Errorf("expected v2 dispatch (Reviewed > 0), got %+v", r)
	}
}

func TestRunGate_V2DispatchesToPrecisionV2(t *testing.T) {
	rGate, err := eval.RunGate(filepath.Join("testdata", "corpus.json"), "v2")
	if err != nil {
		t.Fatalf("gate v2: %v", err)
	}
	rDirect, err := eval.RunCorpusV2(filepath.Join("testdata", "corpus.json"))
	if err != nil {
		t.Fatalf("RunCorpusV2: %v", err)
	}
	if *rGate != *rDirect {
		t.Errorf("RunGate v2 differs from RunCorpusV2: %+v vs %+v", *rGate, *rDirect)
	}
}

func TestRunGate_UnknownVersionErrors(t *testing.T) {
	for _, v := range []string{"v1", "v3", "garbage", "V2"} {
		t.Run(v, func(t *testing.T) {
			_, err := eval.RunGate("testdata/corpus.json", v)
			if err == nil {
				t.Fatalf("expected error for version %q", v)
			}
		})
	}
}

func TestStabilityCheck_NeedsThreeResults(t *testing.T) {
	high := eval.PrecisionResult{Precision: 0.95}
	for _, n := range []int{0, 1, 2} {
		results := make([]eval.PrecisionResult, n)
		for i := range results {
			results[i] = high
		}
		if eval.StabilityCheck(results, 0.8) {
			t.Errorf("len=%d should fail stability check", n)
		}
	}
}

func TestStabilityCheck_AllAboveThreshold(t *testing.T) {
	r := []eval.PrecisionResult{{Precision: 0.85}, {Precision: 0.85}, {Precision: 0.85}}
	if !eval.StabilityCheck(r, 0.8) {
		t.Errorf("3@0.85 vs threshold 0.8 should pass")
	}
}

func TestStabilityCheck_OneBelowThreshold(t *testing.T) {
	r := []eval.PrecisionResult{{Precision: 0.9}, {Precision: 0.9}, {Precision: 0.7}}
	if eval.StabilityCheck(r, 0.8) {
		t.Errorf("one below threshold should fail")
	}
}

func TestStabilityCheck_BoundaryEqual(t *testing.T) {
	r := []eval.PrecisionResult{{Precision: 0.8}, {Precision: 0.8}, {Precision: 0.8}}
	if !eval.StabilityCheck(r, 0.8) {
		t.Errorf("equal-to-threshold should pass (>= not >)")
	}
}
