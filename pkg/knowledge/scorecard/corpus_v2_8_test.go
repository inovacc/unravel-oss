//go:build corpus_validation

/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"errors"
	"os"
	"sort"
	"testing"
)

// TestVALD03_CorpusMajorityGate is the VALD-03 majority gate: at least
// 7 of the 10 Electron-class corpus apps MUST have a sidecar in
// out/reports/scorecards/. SKIPs when the directory is absent.
func TestVALD03_CorpusMajorityGate(t *testing.T) {
	const dir = "../../../out/reports/scorecards"
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		t.Skipf("VALD-03 skipped: out/reports/scorecards/ not found; run .scripts/v2.10-corpus-rescan.ps1 to populate sidecars")
	}
	present, err := listSidecarPackageIDs(dir)
	if err != nil {
		t.Fatalf("list sidecars: %v", err)
	}
	var captured, missing []string
	for _, id := range corpusPackageIDs {
		if present[id] {
			captured = append(captured, id)
		} else {
			missing = append(missing, id)
		}
	}
	sort.Strings(captured)
	sort.Strings(missing)
	if len(captured) < 7 {
		t.Errorf("VALD-03: %d/10 corpus apps captured, want >= 7; missing: %v", len(captured), missing)
	}
}
