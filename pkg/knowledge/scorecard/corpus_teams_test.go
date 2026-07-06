//go:build corpus_validation

/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"errors"
	"os"
	"testing"
)

// TestVALD01_TeamsHardGate is the VALD-01 hard gate: when the operator
// runbook (.scripts/v2.10-corpus-rescan.ps1) has produced a Teams sidecar
// at out/reports/scorecards/MSTeams_8wekyb3d8bbwe_score.json, every key
// dim (wire/state_machines/auth/crypto/storage) MUST be > 0. On absence,
// the test SKIPs cleanly with a runbook hint.
func TestVALD01_TeamsHardGate(t *testing.T) {
	const pkg = "MSTeams_8wekyb3d8bbwe"
	const dir = "../../../out/reports/scorecards"
	sc, path, err := loadSidecarScorecard(dir, pkg)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("VALD-01 skipped: out/reports/scorecards/%s_score.json not found; run .scripts/v2.10-corpus-rescan.ps1 to populate sidecars", pkg)
	}
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	for _, id := range []string{"wire", "state_machines", "auth", "crypto", "storage"} {
		d := sc.Dim(id)
		if d == nil {
			t.Errorf("VALD-01: Dim(%q) missing in Teams sidecar", id)
			continue
		}
		if d.Score <= 0 {
			t.Errorf("VALD-01: Dim(%q).Score = %d, want > 0", id, d.Score)
		}
	}
}
