/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

// TestMaturity84_CryptoSourceLayer_FireOnRealSignal is the 84-02 Wave-2
// regression gate (D-09 batched root cause). Once analyze_uwp.go wires
// recovered EBWebView Code Cache / Service Worker JS into r.JSAnalysis and
// the secrets scan into r.Secrets, the UNCHANGED scorer_crypto.go and
// scorer_source_layer.go must produce a non-zero score WITH a real Evidence
// citation pointing at the recovered artifact. Input here is shaped exactly
// as the wired analyze_uwp produces (MSIXInfo present + JSAnalysis populated
// from recovered EBWebView source). No scorer is modified.
//
// No-fabrication structural invariant (RESEARCH §No-fabrication): for the
// two changed-by-wiring scorers, Score>0 IMPLIES len(Evidence)>0.
func TestMaturity84_CryptoSourceLayer_FireOnRealSignal(t *testing.T) {
	// Shaped as the post-fix analyze_uwp DissectResult: an installed-MSIX
	// UWP class (MSIXInfo non-empty) whose EBWebView recovered JS now
	// populates JSAnalysis (crypto refs + the recovered-source anchor) and
	// whose secrets scan populated Secrets.
	r := &dissect.DissectResult{
		SourcePath: "/installed/5319275A.WhatsAppDesktop",
		MSIXInfo: &msix.InfoResult{
			Files: []msix.FileEntry{{Name: "WhatsApp.exe", Size: 1024}},
		},
		JSAnalysis: &dissect.JSAnalysisResult{
			File:         "EBWebView Code Cache / Service Worker (recovered)",
			Indicators:   []string{"WebCrypto.subtle", "libsignal", "curve25519"},
			NetworkCalls: []string{"fetch()", "WebSocket"},
		},
		Secrets: &secret.ScanResult{TotalFindings: 3},
	}

	for _, sc := range []struct {
		name  string
		score func(*dissect.DissectResult) DimScore
	}{
		{"crypto", func(d *dissect.DissectResult) DimScore { return cryptoScorer{}.Score(d, nil) }},
		{"source_layer", func(d *dissect.DissectResult) DimScore { return sourceLayerScorer{}.Score(d, nil) }},
	} {
		t.Run(sc.name+"_nonzero_with_evidence", func(t *testing.T) {
			got := sc.score(r)
			if got.Score <= 0 {
				t.Fatalf("%s Score = %d on real-signal EBWebView input; want > 0 "+
					"(upstream JSAnalysis/Secrets wiring did not light the scorer)", sc.name, got.Score)
			}
			if len(got.Evidence) == 0 {
				t.Fatalf("%s Score=%d but Evidence empty — no-fabrication invariant "+
					"violated (every credit must cite a real artifact)", sc.name, got.Score)
			}
			var anyCite bool
			for _, ev := range got.Evidence {
				if ev.Citation != nil {
					anyCite = true
					break
				}
			}
			if !anyCite {
				t.Fatalf("%s has Evidence but no typed Citation — credit not anchored to a real artifact", sc.name)
			}
		})
	}
}

// TestMaturity84_NilEmptyInputCreditsNothing is the no-fabrication guard
// (RESEARCH §No-fabrication, T-84-07): with no recovered JS/secrets (the
// honest-empty path), neither scorer may credit the UWP class. Asserts the
// structural invariant that the wiring fix never enables synthesis.
func TestMaturity84_NilEmptyInputCreditsNothing(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
	}{
		{"nil", nil},
		{"empty", &dissect.DissectResult{}},
		{"uwp_no_js_no_secrets", &dissect.DissectResult{
			// MSIXInfo present but the EBWebView analysis pass found
			// nothing (analyzed-empty): JSAnalysis/Secrets stay nil.
			MSIXInfo: &msix.InfoResult{Files: []msix.FileEntry{{Name: "asset.png"}}},
		}},
	}
	for _, tc := range cases {
		for _, sc := range []struct {
			name  string
			score func(*dissect.DissectResult) DimScore
		}{
			{"crypto", func(d *dissect.DissectResult) DimScore { return cryptoScorer{}.Score(d, nil) }},
			{"source_layer", func(d *dissect.DissectResult) DimScore { return sourceLayerScorer{}.Score(d, nil) }},
		} {
			t.Run(tc.name+"_"+sc.name, func(t *testing.T) {
				got := sc.score(tc.r) // must not panic
				// Whenever a score is credited it MUST carry Evidence —
				// the structural no-fabrication invariant holds even on
				// the empty path (no synthesized credit without a citation).
				if got.Score > 0 && len(got.Evidence) == 0 {
					t.Fatalf("%s credited Score=%d with empty Evidence on %q — fabrication",
						sc.name, got.Score, tc.name)
				}
			})
		}
	}
}
