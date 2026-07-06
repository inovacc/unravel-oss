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

// RSCN-03 / VOPR-03 assertion seam.
//
// Two tests live here, with deliberately different honesty postures:
//
//  1. TestVOPR03_CorpusMeanMajorityGate — the REAL-corpus gate. It reads the
//     committed sidecars under out/reports/scorecards/ and asserts >=7/10
//     corpus apps reach a per-app mean >=80 across their scored dims. It
//     SKIPs (never fakes pass/fail) when ANY required sidecar is absent
//     (os.ErrNotExist) — closure requires the operator rescan (D-75-01).
//
//  2. TestVOPR03_MeanMajorityArithmetic — a Docker-free proof of the
//     mean/majority math over SYNTHETIC fixtures in
//     testdata/vopr03_synthetic/. It NEVER asserts "the real corpus
//     passes" (D-75-02 / D-74-01 anti-pattern). It only proves the
//     arithmetic: >=7 PASS, ==6 FAIL, Teams-behavior-exclusion, and the
//     mean==80.0 inclusive boundary.
//
// The per-app mean is computed MANUALLY = sum(scored dim scores) /
// len(scored dims). The sidecar coverage.mean_score field is a SUM
// (0..1200), NOT a mean — it is deliberately never read here (RESEARCH
// Pitfall 1).

const vopr03TeamsID = "MSTeams_8wekyb3d8bbwe"

// vopr03ScoredDims is the single source of truth for which dims feed an
// app's per-app mean. It returns CanonicalDims for every app, EXCEPT
// MSTeams_8wekyb3d8bbwe which drops "behavior" (SC#5; precedent:
// corpus_teams_test.go never asserts behavior for Teams).
func vopr03ScoredDims(id string) []string {
	if id == vopr03TeamsID {
		out := make([]string, 0, len(CanonicalDims)-1)
		for _, d := range CanonicalDims {
			if d == "behavior" {
				continue
			}
			out = append(out, d)
		}
		return out
	}
	return CanonicalDims
}

// meanScoredDims computes the per-app mean = sum(Dim(d).Score) /
// len(scoredDims). A nil Dim (dim absent from the sidecar) contributes 0,
// matching the gate's conservative "missing == not covered" posture.
func meanScoredDims(sc *Scorecard, id string) float64 {
	dims := vopr03ScoredDims(id)
	sum := 0
	for _, d := range dims {
		if ds := sc.Dim(d); ds != nil {
			sum += ds.Score
		}
	}
	return float64(sum) / float64(len(dims))
}

// TestVOPR03_CorpusMeanMajorityGate is the honest real-corpus gate. With
// no committed sidecars it SKIPs (CI treats SKIP as pass). With sidecars
// present it Errorf's iff <7/10 apps reach per-app mean >=80.
func TestVOPR03_CorpusMeanMajorityGate(t *testing.T) {
	const dir = "../../../out/reports/scorecards"
	pass := 0
	for _, id := range corpusPackageIDs {
		sc, _, err := loadSidecarScorecard(dir, id)
		if errors.Is(err, os.ErrNotExist) {
			t.Skipf("VOPR-03 skipped: out/reports/scorecards/%s_score.json not found; run .scripts/v2.10-corpus-rescan.ps1 (see docs/runbooks/corpus-vopr-03-install.md)", id)
		}
		if err != nil {
			t.Fatalf("load %s: %v", id, err)
		}
		if meanScoredDims(sc, id) >= 80.0 {
			pass++
		}
	}
	if pass < 7 {
		t.Errorf("VOPR-03: %d/10 apps at mean>=80, want >=7", pass)
	}
}

// vopr03Fixture mirrors the synthetic sidecar shape: one file = a set of
// apps so the count-based PASS/FAIL math can be proven in a single file.
type vopr03Fixture struct {
	Apps []struct {
		Package    string     `json:"package"`
		Dimensions []DimScore `json:"dimensions"`
	} `json:"apps"`
}

func loadVOPR03Fixture(t *testing.T, name string) vopr03Fixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vopr03_synthetic", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var f vopr03Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal fixture %s: %v", name, err)
	}
	return f
}

// countPassing applies the SAME projection as the real gate (manual mean
// over vopr03ScoredDims, behavior excluded for Teams) to a fixture.
func countPassing(f vopr03Fixture) int {
	pass := 0
	for _, app := range f.Apps {
		sc := &Scorecard{Dimensions: app.Dimensions}
		if meanScoredDims(sc, app.Package) >= 80.0 {
			pass++
		}
	}
	return pass
}

// TestVOPR03_MeanMajorityArithmetic proves the mean/majority math
// Docker-free over synthetic fixtures. It NEVER asserts the real corpus
// passes — only that the arithmetic behaves correctly.
func TestVOPR03_MeanMajorityArithmetic(t *testing.T) {
	t.Run("pass7_majority", func(t *testing.T) {
		f := loadVOPR03Fixture(t, "pass7.json")
		if got := countPassing(f); got < 7 {
			t.Errorf("pass7: count=%d, want >=7 (majority PASS)", got)
		}
	})

	t.Run("fail6_below_majority", func(t *testing.T) {
		f := loadVOPR03Fixture(t, "fail6.json")
		got := countPassing(f)
		if got != 6 {
			t.Errorf("fail6: count=%d, want exactly 6", got)
		}
		if got >= 7 {
			t.Errorf("fail6: count=%d must FAIL the >=7 gate", got)
		}
	})

	t.Run("teams_behavior_excluded", func(t *testing.T) {
		f := loadVOPR03Fixture(t, "teams_excl.json")
		if len(f.Apps) != 1 {
			t.Fatalf("teams_excl: want exactly 1 app, got %d", len(f.Apps))
		}
		app := f.Apps[0]
		if app.Package != vopr03TeamsID {
			t.Fatalf("teams_excl: package=%q, want %q", app.Package, vopr03TeamsID)
		}
		sc := &Scorecard{Dimensions: app.Dimensions}
		// Mean WITH behavior (naive 12-dim) must be <80.
		naiveSum := 0
		for _, d := range CanonicalDims {
			if ds := sc.Dim(d); ds != nil {
				naiveSum += ds.Score
			}
		}
		naiveMean := float64(naiveSum) / float64(len(CanonicalDims))
		// Mean WITHOUT behavior (the SC#5 path) must be >=80.
		exclMean := meanScoredDims(sc, vopr03TeamsID)
		if naiveMean >= 80.0 {
			t.Errorf("teams_excl: naive 12-dim mean=%.4f, want <80 so exclusion is load-bearing", naiveMean)
		}
		if exclMean < 80.0 {
			t.Errorf("teams_excl: behavior-excluded 11-dim mean=%.4f, want >=80", exclMean)
		}
		if len(vopr03ScoredDims(vopr03TeamsID)) != 11 {
			t.Errorf("teams_excl: scored dims=%d, want 11 (behavior dropped)", len(vopr03ScoredDims(vopr03TeamsID)))
		}
	})

	t.Run("boundary80_inclusive", func(t *testing.T) {
		f := loadVOPR03Fixture(t, "boundary80.json")
		if len(f.Apps) != 1 {
			t.Fatalf("boundary80: want exactly 1 app, got %d", len(f.Apps))
		}
		app := f.Apps[0]
		sc := &Scorecard{Dimensions: app.Dimensions}
		m := meanScoredDims(sc, app.Package)
		if m != 80.0 {
			t.Fatalf("boundary80: mean=%.6f, want exactly 80.0", m)
		}
		// >= , not > : an exact-80.0 app counts as PASS.
		if got := countPassing(f); got != 1 {
			t.Errorf("boundary80: count=%d, want 1 (mean==80.0 is inclusive PASS)", got)
		}
	})
}
