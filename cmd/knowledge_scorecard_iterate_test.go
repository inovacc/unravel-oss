/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"
)

// TestEmitScorecardSidecarIterate_WritesJSONLAndMD (P61 CLSR-01 smoke):
// asserts that the iterate-path helper, when run against an empty tmpdir
// (neither electron nor webview2 evidence), short-circuits to the static-
// only path AND writes BOTH iterations.jsonl (≥1 record, parseable as
// IterationRecord) AND SCORECARD.md.
//
// This is the regression that ensures --iterate is wired AND the post-
// Iterate EmitScorecardMD refresh runs. Pre-fix, the flag was advertised
// but never dispatched; post-fix, both files materialize.
func TestEmitScorecardSidecarIterate_WritesJSONLAndMD(t *testing.T) {
	appDir := t.TempDir() // empty: no electron, no webview2 → static-only
	outDir := t.TempDir()

	kr := &knowledge.KnowledgeResult{AppName: "fixture-iterate"}

	opts := scorecard.IterateOptions{
		MaxIter:        1,
		Threshold:      80,
		RequireAll12:   false,
		PerIterTimeout: 30 * time.Second,
	}

	err := emitScorecardSidecarIterate(context.Background(), appDir, outDir, kr, opts, 0)
	if err != nil {
		t.Fatalf("emitScorecardSidecarIterate returned error: %v", err)
	}

	// 1) iterations.jsonl exists and has at least one parseable record.
	jsonlPath := filepath.Join(outDir, "iterations.jsonl")
	jsonlBytes, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("read iterations.jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(jsonlBytes)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("iterations.jsonl empty; want ≥1 record")
	}
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec scorecard.IterationRecord
		if uerr := json.Unmarshal([]byte(line), &rec); uerr != nil {
			t.Fatalf("iterations.jsonl line %d not parseable: %v\nline=%s", i, uerr, line)
		}
		if rec.ID == "" {
			t.Fatalf("iterations.jsonl line %d: empty ID", i)
		}
	}

	// 2) SCORECARD.md exists and contains canonical sections — proving the
	//    post-Iterate EmitScorecardMD refresh ran (B2: not stale static).
	mdPath := filepath.Join(outDir, "SCORECARD.md")
	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read SCORECARD.md: %v", err)
	}
	md := string(mdBytes)
	if !strings.Contains(md, "## Coverage summary") {
		t.Errorf("SCORECARD.md missing 'Coverage summary' heading; got:\n%s", md)
	}
}

// TestEmitScorecardSidecar_SingleShotUnchanged (P61 W1 regression):
// the iterate=false path still calls the existing emitScorecardSidecar
// which produces a SCORECARD.md with the canonical sections. We assert
// structural invariance rather than byte-equality (the static-only render
// includes a Generated timestamp that's expensive to normalise across
// platforms; the byte-equality golden lives in
// pkg/knowledge/scorecard/emit_test.go::TestEmitScorecardMD_Bytes).
func TestEmitScorecardSidecar_SingleShotUnchanged(t *testing.T) {
	appDir := t.TempDir()
	outDir := t.TempDir()

	kr := &knowledge.KnowledgeResult{AppName: "fixture-single"}

	emitScorecardSidecar(appDir, outDir, kr)

	mdPath := filepath.Join(outDir, "SCORECARD.md")
	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read SCORECARD.md: %v", err)
	}
	md := string(mdBytes)
	for _, want := range []string{"## Coverage summary", "## Per-dimension"} {
		if !strings.Contains(md, want) {
			t.Errorf("single-shot SCORECARD.md missing %q; got:\n%s", want, md)
		}
	}
	// iterate-only sidecar must NOT exist on this path.
	if _, err := os.Stat(filepath.Join(outDir, "iterations.jsonl")); err == nil {
		t.Errorf("single-shot path leaked iterations.jsonl — should only exist on --iterate path")
	}
}
