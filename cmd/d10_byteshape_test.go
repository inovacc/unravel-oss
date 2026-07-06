/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// TestD10ByteShape is the automated D-10 byte-shape guard for P60 (replaces
// the non-existent `task d10:check`). It SHA-256s the frozen
// cmd/testdata/knowledge.golden.json fixture, runs an in-process
// scorecard-emit pipeline (the heatmap renderer here, since it is the only
// P60 surface that touches any json knowledge artifact), and asserts the
// fixture bytes are unchanged.
//
// D-10 mandate: knowledge.json byte shape MUST NOT mutate as a side-effect
// of any scorecard/heatmap pipeline run. A future PR that, e.g., teaches
// the heatmap renderer to rewrite sidecars in place would be caught here.
func TestD10ByteShape(t *testing.T) {
	path := filepath.Join("testdata", "knowledge.golden.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	hBefore := sha256.Sum256(before)

	// Exercise the heatmap pipeline against the synthetic golden input
	// dir; this is the only scorecard surface that writes any knowledge
	// artifact in P60 scope.
	inDir := filepath.Join("testdata", "heatmap_golden", "input")
	rows, missing, err := loadSidecarRows(inDir)
	if err != nil {
		t.Fatalf("loadSidecarRows: %v", err)
	}
	out, err := os.Create(filepath.Join(t.TempDir(), "out.md"))
	if err != nil {
		t.Fatalf("create out: %v", err)
	}
	if err := renderHeatmap(out, rows, missing); err != nil {
		t.Fatalf("renderHeatmap: %v", err)
	}
	_ = out.Close()

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("re-read golden: %v", err)
	}
	hAfter := sha256.Sum256(after)
	if hBefore != hAfter {
		t.Errorf("D-10 breach: knowledge.golden.json mutated by scorecard pipeline\n  before=%s\n  after =%s",
			hex.EncodeToString(hBefore[:]), hex.EncodeToString(hAfter[:]))
	}
}
