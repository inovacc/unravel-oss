/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestExpectedW13Fixture validates the W-13 final-state fixture used by the
// corpus_validation-gated VALD-02 parity test. It runs in the default test
// suite (no build tag) so any drift in the fixture's shape — wrong dim
// count, missing canonical dim, schema mismatch — fails fast.
//
// Source: out/whatsapp-kb/_score.json (post-W-13 CDP final state).
// Acceptance fixture for VALD-02 (P60).
func TestExpectedW13Fixture(t *testing.T) {
	path := filepath.Join("testdata", "expected_score_w13_final.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	var sc Scorecard
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("unmarshal fixture into *Scorecard: %v", err)
	}

	// VALD-02 absolute gates: 12 dims AND Coverage >= 11.
	if got := len(sc.Dimensions); got != 12 {
		t.Fatalf("len(Dimensions): got %d, want 12", got)
	}
	if sc.Coverage < 11 {
		t.Fatalf("Coverage: got %d, want >= 11", sc.Coverage)
	}

	// Canonical order: each DimScore.ID matches CanonicalDims at its index.
	for i, want := range CanonicalDims {
		if got := sc.Dimensions[i].ID; got != want {
			t.Errorf("Dimensions[%d].ID: got %q, want %q (canonical order drift)", i, got, want)
		}
	}

	// W-13b bump deltas applied (wire>=85, auth>=80, state_machines>=80,
	// crypto>=80) — sanity bounds per RESEARCH.md.
	for _, id := range []string{"wire", "auth", "state_machines", "crypto"} {
		d := sc.Dim(id)
		if d == nil {
			t.Fatalf("Scorecard.Dim(%q) returned nil", id)
		}
		if d.Score < 80 {
			t.Errorf("Dim(%q).Score: got %d, want >= 80 (post-W-13 bump)", id, d.Score)
		}
	}

	// Round-trip Marshal -> Unmarshal -> Marshal yields byte-stable output.
	out1, err := json.Marshal(&sc)
	if err != nil {
		t.Fatalf("marshal #1: %v", err)
	}
	var sc2 Scorecard
	if err := json.Unmarshal(out1, &sc2); err != nil {
		t.Fatalf("unmarshal #2: %v", err)
	}
	out2, err := json.Marshal(&sc2)
	if err != nil {
		t.Fatalf("marshal #2: %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Errorf("round-trip not byte-stable:\n  out1=%s\n  out2=%s", out1, out2)
	}
}
