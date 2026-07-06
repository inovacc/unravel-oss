/*
Copyright (c) 2026 Security Research
*/
package scorecard

// P57 must NOT register MCP tools — the canonical 136-tool invariant is
// enforced by pkg/mcptools/TestToolCountInvariant. This sentinel comment is a
// tripwire for future contributors: do not add per-phase grep checks here
// (W4); rely on the canonical invariant instead.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIterateStaticOnly exercises the W1 static-only fallback path — both
// detectors miss → no CDP dial → 1-record IterationLog with rich shape;
// behavior missing marker present (B3); D-10 byte-shape held; cross-run
// append produces 2 records (W2).
func TestIterateStaticOnly(t *testing.T) {
	dir := t.TempDir()

	// Inject mock detectors that both return false (W1 path) — no CDP dial.
	src := &capturingFrameSource{frames: 999}
	dialCalls := 0
	dial := func(ctx context.Context, port int) error { dialCalls++; return nil }
	defer withSeams(t, false, false, dial, src)()

	// Static scorecard with behavior < threshold so the B3 marker fires.
	scores := whatsappShape() // behavior=70
	rb := fixedRubric(scores)

	// Pre-snapshot a synthetic knowledge.json adjacent to the kb dir for
	// D-10 SHA256 compare.
	kbJSON := filepath.Join(dir, "knowledge.json")
	preBytes := []byte(`{"kb_id":"static-fallback","schema":"v2"}`)
	if err := os.WriteFile(kbJSON, preBytes, 0o644); err != nil {
		t.Fatalf("write knowledge.json: %v", err)
	}
	preHash := sha256.Sum256(preBytes)

	sc, log, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x"}, DefaultIterateOptions())
	if err != nil {
		t.Fatalf("iterate: %v", err)
	}

	// W1 — no port dial.
	if dialCalls != 0 {
		t.Errorf("W1 violated: dial called %d times", dialCalls)
	}
	// frameSource untouched.
	if src.calls != 0 {
		t.Errorf("frameSource invoked on static-only path: %d calls", src.calls)
	}

	// Exactly one record with rich shape.
	if len(log.Records) != 1 {
		t.Fatalf("want 1 record, got %d", len(log.Records))
	}
	rec := log.Records[0]
	if !rec.RuntimeCaptureUnavailable {
		t.Error("RuntimeCaptureUnavailable=true expected")
	}
	if rec.Dispatched == nil {
		t.Error("Dispatched must be non-nil empty slice (B1), got nil")
	}
	if len(rec.Dispatched) != 0 {
		t.Errorf("Dispatched must be empty []DispatchResult, got %+v", rec.Dispatched)
	}
	if rec.Bumps == nil {
		t.Error("Bumps must be non-nil empty map (B1), got nil")
	}
	if len(rec.Bumps) != 0 {
		t.Errorf("Bumps must be empty map[string]int, got %+v", rec.Bumps)
	}
	if rec.Mean != rec.PostMean || rec.Coverage != rec.PostCoverage {
		t.Errorf("static-only: pre/post must match: mean=%d/%d cov=%d/%d", rec.Mean, rec.PostMean, rec.Coverage, rec.PostCoverage)
	}
	// P58 — CitationsOK is now real. fixedScorers emit no Evidence, so the
	// lenient walker returns true (vacuously: nothing to cite). Static-only
	// short-circuit is independent of CitationsOK (W1 contract).
	if !rec.CitationsOK {
		t.Errorf("CitationsOK expected true under P58 lenient rule (no non-missing Evidence to cite)")
	}

	// B3 — behavior missing marker.
	if d := sc.Dim("behavior"); d == nil || !hasBehaviorMissing(d.Evidence) {
		t.Errorf("behavior marker missing (B3): %+v", d)
	}

	// File parses back to the same single record (rich-shape fidelity).
	jsonlPath := filepath.Join(dir, "iterations.jsonl")
	b, err := os.ReadFile(jsonlPath)
	if err != nil {
		t.Fatalf("read iterations.jsonl: %v", err)
	}
	line := strings.TrimSpace(string(b))
	var roundTrip IterationRecord
	if err := json.Unmarshal([]byte(line), &roundTrip); err != nil {
		t.Fatalf("decode jsonl: %v", err)
	}
	if roundTrip.ID != rec.ID || !roundTrip.RuntimeCaptureUnavailable {
		t.Errorf("round-trip mismatch: %+v", roundTrip)
	}

	// W2 — second Iterate call produces 2 records in the file.
	if _, _, err := rb.Iterate(context.Background(), &DissectTarget{KBOutputDir: dir, AppDir: "/x"}, DefaultIterateOptions()); err != nil {
		t.Fatalf("second iterate: %v", err)
	}
	b2, _ := os.ReadFile(jsonlPath)
	if cnt := strings.Count(string(b2), "\n"); cnt != 2 {
		t.Errorf("W2 violated: want 2 lines after second Iterate, got %d", cnt)
	}

	// D-10 — knowledge.json byte-shape unchanged.
	postBytes, err := os.ReadFile(kbJSON)
	if err != nil {
		t.Fatalf("post read: %v", err)
	}
	postHash := sha256.Sum256(postBytes)
	if hex.EncodeToString(preHash[:]) != hex.EncodeToString(postHash[:]) {
		t.Error("D-10 violated: knowledge.json bytes changed after Iterate")
	}
}
