/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScorecardHeatmap exercises the offline (--in) mode of
// `unravel kb scorecard-heatmap` (P60 / VALD-03). It feeds three
// synthetic *_score.json sidecars through the renderer and asserts
// byte-equality with the golden expected.md.
//
// The golden's LINE 1 is the verbatim v2.9 P52 P53 header captured in
// Wave-0 (60-00); any drift there fails the test fast and signals a
// shape regression vs the v2.9 corpus deliverable.
func TestScorecardHeatmap(t *testing.T) {
	inDir := filepath.Join("testdata", "heatmap_golden", "input")
	outPath := filepath.Join(t.TempDir(), "got.md")

	rows, missing, err := loadSidecarRows(inDir)
	if err != nil {
		t.Fatalf("loadSidecarRows: %v", err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatalf("create out: %v", err)
	}
	if err := renderHeatmap(f, rows, missing); err != nil {
		t.Fatalf("renderHeatmap: %v", err)
	}
	_ = f.Close()

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read got: %v", err)
	}
	wantPath := filepath.Join("testdata", "heatmap_golden", "expected.md")
	want, err := os.ReadFile(wantPath)
	if err != nil {
		// First-run convenience: write got as expected and fail loudly so
		// reviewer can inspect-and-commit.
		_ = os.WriteFile(wantPath+".got", got, 0o644)
		t.Fatalf("missing %s; wrote %s.got for review: %v", wantPath, wantPath, err)
	}
	if string(got) != string(want) {
		_ = os.WriteFile(wantPath+".got", got, 0o644)
		t.Errorf("heatmap drift; wrote %s.got for diff", wantPath)
	}
}
