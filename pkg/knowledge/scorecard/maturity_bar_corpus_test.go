//go:build corpus_validation

/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// TestKBMaturityCorpusGate is the corpus-tagged per-dim floor gate. It mirrors
// corpus_teams_test.go exactly: skip-on-absent with the runbook hint when the
// operator rescan has not produced sidecars. When present, every scored dim is
// asserted >= its floor from testdata/maturity_bar_v1.json, else the app is
// recorded SHALLOW (never fabricated, D-06 / honest-empty discipline).
func TestKBMaturityCorpusGate(t *testing.T) {
	raw, err := os.ReadFile("testdata/maturity_bar_v1.json")
	if err != nil {
		t.Fatalf("read maturity_bar_v1.json: %v", err)
	}
	var bar struct {
		PerDim []struct {
			ID    string `json:"id"`
			Floor int    `json:"floor"`
		} `json:"per_dim"`
	}
	if err := json.Unmarshal(raw, &bar); err != nil {
		t.Fatalf("unmarshal maturity_bar_v1.json: %v", err)
	}
	floors := make(map[string]int, len(bar.PerDim))
	for _, p := range bar.PerDim {
		floors[p.ID] = p.Floor
	}

	const pkg = "5319275A.WhatsAppDesktop"
	const dir = "../../../out/reports/scorecards"
	sc, path, err := loadSidecarScorecard(dir, pkg)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("KB-maturity corpus gate skipped: out/reports/scorecards/%s_score.json not found; run .scripts/v2.10-corpus-rescan.ps1 to populate sidecars", pkg)
	}
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}

	for id, floor := range floors {
		d := sc.Dim(id)
		if d == nil {
			// Dim absent from a real sidecar is honest-empty, not a
			// fabricated pass — surface it as SHALLOW.
			t.Logf("SHALLOW: %s dim %q absent from sidecar (floor %d unmet)", pkg, id, floor)
			t.Errorf("KB-maturity: %s dim %q missing, floor %d unmet", pkg, id, floor)
			continue
		}
		if d.Score < floor {
			t.Logf("SHALLOW: %s dim %q score %d < floor %d", pkg, id, d.Score, floor)
			t.Errorf("KB-maturity: %s dim %q score %d < floor %d", pkg, id, d.Score, floor)
		}
	}
}
