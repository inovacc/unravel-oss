//go:build integration

/*
Copyright (c) 2026 Security Research

P40 integration tests for the v2 precision gate. Build-tag-gated to keep the
default `go test -short ./...` suite Docker-free and fast (CLAUDE.md slow-test
policy). Vet-clean under both default and integration tags.

Path remap: planner referenced fictional pkg/knowledge/kb/classify/. Actual
location is pkg/knowledge/kb/component/eval/.
*/

package cmd

import (
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/eval"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime"
)

func corpusFixturePath() string {
	return filepath.Join("..", "pkg", "knowledge", "kb", "component", "eval", "testdata", "corpus.json")
}

func TestPrecisionV2_StabilityOver3Runs(t *testing.T) {
	corpus, err := eval.LoadCorpusV2(corpusFixturePath())
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	results := make([]eval.PrecisionResult, 3)
	for i := 0; i < 3; i++ {
		r, err := eval.PrecisionV2(corpus)
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		results[i] = r
	}
	for i := 1; i < 3; i++ {
		if results[i] != results[0] {
			t.Errorf("run %d differs from run 0: %+v vs %+v", i, results[i], results[0])
		}
	}
	if !eval.StabilityCheck(results, 0.8) {
		t.Errorf("stability check failed: results=%+v", results)
	}
}

func TestRunGate_DefaultIsV2(t *testing.T) {
	r, err := eval.RunGate(corpusFixturePath(), "")
	if err != nil {
		t.Fatalf("RunGate empty: %v", err)
	}
	if r.Reviewed == 0 {
		t.Errorf("RunGate default returned zero reviewed; expected v2 dispatch")
	}
}
