//go:build corpus_validation

/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestVALD02_WhatsAppParity is the VALD-02 hard gate. CDP-required: the
// runbook MUST launch WhatsApp with --remote-debugging-port=9222 for the
// W-13 CDP pass to attach; otherwise wire/auth/state_machines stay below
// 80 and this test fails parity.
//
// Acceptance: Coverage >= 11 AND len(Dimensions) == 12, with every
// canonical dim within ±5 of expected_score_w13_final.json.
func TestVALD02_WhatsAppParity(t *testing.T) {
	const pkg = "5319275A.WhatsAppDesktop"
	const dir = "../../../out/reports/scorecards"
	got, path, err := loadSidecarScorecard(dir, pkg)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("VALD-02 skipped: out/reports/scorecards/%s_score.json not found; run .scripts/v2.10-corpus-rescan.ps1 to populate sidecars", pkg)
	}
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}

	// Sanity gates.
	if n := len(got.Dimensions); n != 12 {
		t.Fatalf("VALD-02: len(Dimensions) = %d, want 12", n)
	}
	if got.Coverage < 11 {
		t.Errorf("VALD-02: Coverage = %d, want >= 11", got.Coverage)
	}

	// Load fixture.
	raw, err := os.ReadFile(filepath.Join("testdata", "expected_score_w13_final.json"))
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	var want Scorecard
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Per-dim tolerance via Scorecard.Dim(id). Default ±5; widened for dims
	// with documented static-extraction drift (P64 SCRG-04 / SCRG-05):
	//   crypto   ±10 — PE-import + JS-ref ceiling ~80 vs expected 85
	//
	// behavior: RATCHETED (P74-02 / D-74-03, tighten-only — D-70-DEFER).
	// The v2.12-CARRYOVER-SCRG-05-DEEPENING carryover is CLOSED: the
	// P72-H4 family-keyed scenario-replay seam + the W-10b spec-refresh
	// floor (scorer_behavior.go:65) bring behavior to its expected basis.
	// SCRG-05D Docker-free proof (vald_proof_test.go) measured the
	// spec-refresh-floor ratchet basis = EXACTLY 85, delta vs the
	// (un-rebaselined, D-72-04) expected_score_w13_final.json behavior=85
	// = 0, zero variance across -count=5. The dedicated behavior tolerance
	// entry is therefore REMOVED entirely: behavior now falls through to
	// the default ±5 below — the tightest correct outcome (15 → 5).
	dimTolerance := map[string]int{"crypto": 10}
	for _, id := range CanonicalDims {
		g := got.Dim(id)
		w := want.Dim(id)
		if g == nil || w == nil {
			t.Errorf("VALD-02: Dim(%q) missing (got=%v want=%v)", id, g, w)
			continue
		}
		delta := g.Score - w.Score
		if delta < 0 {
			delta = -delta
		}
		tol := 5
		if t2, ok := dimTolerance[id]; ok {
			tol = t2
		}
		if delta > tol {
			t.Errorf("VALD-02: Dim(%q): got %d, want %d (±%d); delta=%d", id, g.Score, w.Score, tol, delta)
		}
	}
}
