/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	elecapp "github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/garble"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

func boolPtr(b bool) *bool { return &b }

func TestBinarySurfaceScorer(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		{"nil", nil, 0},
		{"empty", &dissect.DissectResult{}, 0},
		{"floor_60_when_other_binaries_present", &dissect.DissectResult{
			GarbleInfo: &garble.BinaryInfo{},
		}, 60},
		{"dotnet_only_floor", &dissect.DissectResult{
			DotnetDeps: &dotnet.DepsResult{},
		}, 60},
		{"all_inspected_caps_at_70", &dissect.DissectResult{
			AppAnalysis: &elecapp.Result{
				Binaries: []binary.Info{
					{Name: "a", ProductName: "x", StringsTotal: 1},
					{Name: "b", CertSubject: "x", StringsTotal: 1},
				},
			},
		}, 70},
		{"half_inspected", &dissect.DissectResult{
			AppAnalysis: &elecapp.Result{
				Binaries: []binary.Info{
					{Name: "a"},
					{Name: "b", StringsTotal: 1},
				},
			},
		}, 50}, // 1/2=50, no other-binary floor
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := binarySurfaceScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
		})
	}
}

// TestBinarySurfaceScorer_UWPInstallDir exercises the SCRG-01 UWP install-dir
// branch: 3 PE entries (2 signed) → score >= 80, Evidence count == 3, each
// Evidence.Citation.File equals the corresponding r.MSIXInfo.Files[i].Name
// (NOT r.SourcePath).
func TestBinarySurfaceScorer_UWPInstallDir(t *testing.T) {
	r := &dissect.DissectResult{
		SourcePath: "C:/Program Files/WindowsApps/some.app",
		MSIXInfo: &msix.InfoResult{
			Files: []msix.FileEntry{
				{Name: "App.exe", Size: 1024, Signed: boolPtr(true)},
				{Name: "App.dll", Size: 512, Signed: boolPtr(true)},
				{Name: "Native.dll", Size: 2048, Signed: boolPtr(false)},
				{Name: "asset.png", Size: 100},
			},
		},
	}
	got := binarySurfaceScorer{}.Score(r, nil)
	// Base 70 + per-PE size-depth adder (+5). The old curve added a flat
	// signedPercent/5 bump that was NOT evidence-gated (D-05 violation); it
	// was replaced by cited W-12 adders, so a partially-signed/no-signer set
	// legitimately scores at the 70 base + earned depth only.
	if got.Score < 70 {
		t.Errorf("UWP install-dir Score = %d, want >= 70 (base cap + earned depth)", got.Score)
	}
	// The first 3 Evidence entries remain the per-PE citations (regression
	// guard for SCRG-01). W-12 cap-deepening adders may append additional
	// evidence-gated entries after them.
	if len(got.Evidence) < 3 {
		t.Fatalf("UWP install-dir Evidence count = %d, want >= 3", len(got.Evidence))
	}
	wantFiles := []string{"App.exe", "App.dll", "Native.dll"}
	for i, want := range wantFiles {
		ev := got.Evidence[i]
		if ev.Citation == nil {
			t.Errorf("Evidence[%d].Citation is nil", i)
			continue
		}
		if ev.Citation.File != want {
			t.Errorf("Evidence[%d].Citation.File = %q, want %q (must NOT be r.SourcePath)", i, ev.Citation.File, want)
		}
		if ev.Citation.File == r.SourcePath {
			t.Errorf("Evidence[%d].Citation.File leaked r.SourcePath", i)
		}
	}
}

// TestBinarySurfaceScorer_W12CapDeepening — the explicitly P57-deferred
// W-12 cap-deepening. UWP PEs carrying real inspectable depth (Size>0
// import-depth proxy, Signer cert-depth, signed ratio) lift the score
// above the legacy 70 base cap toward the 85 maturity floor, and every
// increment is backed by a real Evidence citation. No increment without
// Evidence (D-05). Legacy fixtures never enter this branch so they are
// byte/score-identical.
func TestBinarySurfaceScorer_W12CapDeepening(t *testing.T) {
	// Deep, fully-signed PE set with signer attribution → past the old 70
	// cap, toward the 85 floor.
	r := &dissect.DissectResult{
		SourcePath: "C:/Program Files/WindowsApps/deep.app",
		MSIXInfo: &msix.InfoResult{
			Files: []msix.FileEntry{
				{Name: "App.exe", Size: 4096, Signed: boolPtr(true), Signer: "CN=Microsoft"},
				{Name: "App.dll", Size: 8192, Signed: boolPtr(true), Signer: "CN=Microsoft"},
				{Name: "Core.dll", Size: 16384, Signed: boolPtr(true), Signer: "CN=Microsoft"},
				{Name: "Plugin.dll", Size: 2048, Signed: boolPtr(true), Signer: "CN=Microsoft"},
				{Name: "asset.png", Size: 10},
			},
		},
	}
	got := binarySurfaceScorer{}.Score(r, nil)
	if got.Score <= 70 {
		t.Fatalf("W-12 deepening Score = %d, want > 70 (cap lifted by evidence-gated adders)", got.Score)
	}
	if got.Score > 85 {
		t.Errorf("W-12 deepening Score = %d, want <= 85 (binary_surface maturity floor)", got.Score)
	}
	// Every adder must contribute a real Evidence citation: with 4 PEs plus
	// signer-depth + signed-ratio depth adders, evidence must exceed the
	// bare per-PE count.
	if len(got.Evidence) <= 4 {
		t.Errorf("W-12 deepening Evidence count = %d, want > 4 (per-PE + depth adders each cited)", len(got.Evidence))
	}
	for i, ev := range got.Evidence {
		if ev.Kind == "field" && ev.Citation == nil {
			t.Errorf("Evidence[%d] field has nil Citation (no curve bump without evidence, D-05)", i)
		}
	}

	// Shallow PE set (no signer, tiny size) must NOT receive the depth
	// adders — score stays at/below the un-deepened curve. Guards against
	// flat curve inflation.
	shallow := &dissect.DissectResult{
		SourcePath: "C:/Program Files/WindowsApps/shallow.app",
		MSIXInfo: &msix.InfoResult{
			Files: []msix.FileEntry{
				{Name: "a.dll", Signed: boolPtr(false)},
				{Name: "b.dll", Signed: boolPtr(false)},
				{Name: "c.dll", Signed: boolPtr(false)},
			},
		},
	}
	sg := binarySurfaceScorer{}.Score(shallow, nil)
	if sg.Score > got.Score {
		t.Errorf("shallow Score %d exceeded deep Score %d (depth adders leaked to no-depth input)", sg.Score, got.Score)
	}
}

// TestBinarySurfaceScorer_UWPNilSafe — empty/nil MSIXInfo and no other
// signal must not panic and must return Score 0.
func TestBinarySurfaceScorer_UWPNilSafe(t *testing.T) {
	for _, name := range []string{"nil-msix", "empty-files"} {
		r := &dissect.DissectResult{}
		if name == "empty-files" {
			r.MSIXInfo = &msix.InfoResult{}
		}
		got := binarySurfaceScorer{}.Score(r, nil)
		if got.Score != 0 {
			t.Errorf("%s Score = %d, want 0", name, got.Score)
		}
		if len(got.Evidence) != 0 {
			t.Errorf("%s Evidence non-empty: %+v", name, got.Evidence)
		}
	}
}
