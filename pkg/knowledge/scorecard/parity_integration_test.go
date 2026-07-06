//go:build whatsapp_fixture

/*
Copyright (c) 2026 Security Research
*/

// Package scorecard parity test against the W-11 baseline snapshot of
// out/whatsapp-kb/_score.json.
//
// JSON contract (cmd/dissect.go --json flag, line 53):
//
//	`unravel dissect <path> --json` writes a single json.MarshalIndent
//	document of *dissect.DissectResult to stdout. All logging stays on
//	stderr. The output round-trips into *dissect.DissectResult via
//	json.Unmarshal because every typed field carries snake_case JSON tags.
//
// Regen the WhatsApp fixture (operator-environment-dependent):
//
//	go run . dissect "<path-to-WhatsApp.msix-or-WindowsApps-dir>" --json \
//	    > pkg/knowledge/scorecard/testdata/whatsapp_dissect_result.json
//
// MSIX provenance: package family 5319275A.WhatsAppDesktop. See
// testdata/README.md for full provenance + acquisition instructions.
//
// Build tag: this file requires `-tags=whatsapp_fixture` so the default
// `go test ./...` suite (and CI without WhatsApp installed) does not require
// the fixture file. When updating the W-11 baseline, see testdata/README.md
// for the documented procedure (NOT a casual regen).
package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

const (
	fixturePath  = "testdata/whatsapp_dissect_result.json"
	baselinePath = "testdata/expected_score_w11_baseline.json"
	tolerance    = 5 // RUBR-03 ±5% per dim; integer scores 0-100 -> ±5 absolute
)

func TestWhatsAppParity(t *testing.T) {
	fixBytes, err := os.ReadFile(filepath.Clean(fixturePath))
	if err != nil {
		t.Skipf("fixture %s missing — operator must regen via testdata/README.md (build tag whatsapp_fixture is set but file absent): %v", fixturePath, err)
		return
	}
	var dr dissect.DissectResult
	if err := json.Unmarshal(fixBytes, &dr); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	baseBytes, err := os.ReadFile(filepath.Clean(baselinePath))
	if err != nil {
		t.Fatalf("read baseline %s: %v", baselinePath, err)
	}
	var base Scorecard
	if err := json.Unmarshal(baseBytes, &base); err != nil {
		t.Fatalf("unmarshal baseline: %v", err)
	}

	got := New().Score(&dr, dr.AnalysisResults)

	// P58 (Task 58-05) — citation parity: every non-missing Evidence on the
	// WhatsApp fixture must carry a Citation, citations_ok must be true, and
	// each dim's MissingCitations must be zero.
	//
	// Expected non-missing Evidence count for the WhatsApp fixture is dim-
	// dependent and varies with cache hit/miss; what we pin is the structural
	// contract (each non-missing Evidence cited, no missing-citations counted),
	// not a fixed integer count. Future fixture drift surfaces as a citation
	// gap on the affected dim.
	if !ComputeCitationsOK(&got) {
		t.Errorf("WhatsApp parity: scorecard.CitationsOK=false post-walker; expected true")
	}
	if !got.CitationsOK {
		t.Errorf("WhatsApp parity: scorecard.CitationsOK not propagated true")
	}
	for _, d := range got.Dimensions {
		if d.MissingCitations != 0 {
			t.Errorf("WhatsApp parity: dim %s MissingCitations=%d, want 0", d.ID, d.MissingCitations)
		}
		for i, e := range d.Evidence {
			if e.Kind == "missing" {
				continue
			}
			if e.Citation == nil || e.Citation.File == "" {
				t.Errorf("WhatsApp parity: dim %s Evidence[%d] kind=%q lacks Citation: %+v", d.ID, i, e.Kind, e)
			}
		}
	}

	expByID := make(map[string]int, len(base.Dimensions))
	for _, d := range base.Dimensions {
		expByID[d.ID] = d.Score
	}

	type row struct {
		id              string
		got, exp, delta int
	}
	rows := make([]row, 0, len(got.Dimensions))
	failed := false
	sumGot, sumExp, n := 0, 0, 0
	for _, d := range got.Dimensions {
		exp, ok := expByID[d.ID]
		if !ok {
			t.Errorf("baseline missing dim %s", d.ID)
			continue
		}
		delta := d.Score - exp
		if delta < 0 {
			delta = -delta
		}
		rows = append(rows, row{d.ID, d.Score, exp, delta})
		sumGot += d.Score
		sumExp += exp
		n++
		// Per-dim widened tolerance (P64 documented drift):
		//   crypto   ±10 — SCRG-04 PE+JS ceiling
		//   behavior ±15 — SCRG-05 manifest+URL ceiling
		tol := tolerance
		switch d.ID {
		case "crypto":
			tol = 10
		case "behavior":
			tol = 15
		}
		if delta > tol {
			failed = true
		}
	}
	if failed {
		t.Errorf("per-dim parity failed (tolerance ±%d):", tolerance)
		t.Logf("%-16s %6s %6s %6s", "dim", "got", "exp", "delta")
		for _, r := range rows {
			t.Logf("%-16s %6d %6d %6d", r.id, r.got, r.exp, r.delta)
		}
	}
	if n > 0 {
		meanGot := (sumGot + n/2) / n
		meanExp := (sumExp + n/2) / n
		md := meanGot - meanExp
		if md < 0 {
			md = -md
		}
		if md > tolerance {
			t.Errorf("mean parity failed: got=%d exp=%d delta=%d tol=%d", meanGot, meanExp, md, tolerance)
		}
	}
}
