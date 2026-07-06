/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func TestAPIScorer(t *testing.T) {
	mkURLs := func(n int) []string {
		urls := make([]string, n)
		for i := range urls {
			urls[i] = "https://x"
		}
		return urls
	}
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		// mkURLs emits N *identical* "https://x" strings. Post-P57 the api
		// scorer dedupes by host+path, so any count of identical URLs is a
		// single distinct quality endpoint — the raw-count tiers no longer
		// apply to a degenerate single-endpoint set. These cases now assert
		// the quality-weighted reality (dedupe → 1 distinct endpoint).
		{"nil", nil, 0},
		{"empty", &dissect.DissectResult{}, 20},
		{"low_hits_one_distinct", &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{URLs: mkURLs(5)},
		}, 20}, // 5 raw → tier 20; 1 distinct quality → no adder
		{"mid_hits_one_distinct", &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{URLs: mkURLs(11)},
		}, 50}, // 11 raw → tier 50; 1 distinct quality → no adder
		{"boundary_one_distinct", &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{URLs: mkURLs(50)},
		}, 50},
		{"high_raw_one_distinct_regrounded", &dissect.DissectResult{
			JSAnalysis: &dissect.JSAnalysisResult{URLs: mkURLs(51)},
		}, 50}, // 51 raw → tier 75, but 1 distinct quality regrounds to 50 (T-84-12)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := apiScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
		})
	}
}

// TestAPIScorer_LegacyNilJSAnalysisByteIdentical — legacy fixtures with nil
// JSAnalysis must score on the un-deepened count tiers, byte-identical to
// the pre-P57 curve. The quality-weighted adders are gated behind a
// populated r.JSAnalysis and must never fire here.
func TestAPIScorer_LegacyNilJSAnalysisByteIdentical(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		{"nil-js-empty", &dissect.DissectResult{}, 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := apiScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("legacy Score = %d, want %d (byte-identical, no adders)", got.Score, tc.want)
			}
		})
	}
}

// TestAPIScorer_NoiseClassifiedOut — PKI/CRL/cert endpoints are noise and
// must be classified out before scoring; a set that is ALL noise must not
// inflate the score the way a raw count would (count-as-quality pitfall,
// T-84-12).
func TestAPIScorer_NoiseClassifiedOut(t *testing.T) {
	noise := make([]string, 0, 60)
	for i := 0; i < 60; i++ {
		noise = append(noise, "http://www.microsoft.com/pkiops/crl/microsoft.crl")
	}
	r := &dissect.DissectResult{
		JSAnalysis: &dissect.JSAnalysisResult{File: "app.js", URLs: noise},
	}
	got := apiScorer{}.Score(r, nil)
	// 60 raw hits would be the >50 tier (75). After dropping all-noise the
	// quality count is ~0, so the score must NOT reach the high tier.
	if got.Score >= 75 {
		t.Errorf("all-noise Score = %d, want < 75 (PKI/CRL must not count as quality)", got.Score)
	}
}

// TestAPIScorer_QualityWeightedPast75 — a deduped set of real, distinct
// API endpoints scores past the old 75 step via evidence-gated adders,
// each backed by a real Evidence citation (no curve inflation, D-05).
func TestAPIScorer_QualityWeightedPast75(t *testing.T) {
	urls := make([]string, 0, 120)
	// duplicates + noise that must be classified/deduped away
	for i := 0; i < 40; i++ {
		urls = append(urls, "https://gateway.example.com/v1/resource")    // dup
		urls = append(urls, "http://www.microsoft.com/pkiops/crl/ms.crl") // noise
	}
	// 30 genuinely distinct real API endpoints (> 25 → W-12 +15 tier)
	for i := 0; i < 30; i++ {
		urls = append(urls, "https://api.example.com/v1/resource/"+string(rune('a'+i)))
	}
	r := &dissect.DissectResult{
		JSAnalysis: &dissect.JSAnalysisResult{
			File: "app.js", URLs: urls,
			NetworkCalls: []string{"fetch", "XMLHttpRequest", "WebSocket"},
		},
	}
	got := apiScorer{}.Score(r, nil)
	if got.Score <= 75 {
		t.Fatalf("quality Score = %d, want > 75 (evidence-gated adders on classified endpoints)", got.Score)
	}
	if got.Score > 95 {
		t.Errorf("quality Score = %d, want <= 95 (no runaway curve inflation)", got.Score)
	}
	hasCited := false
	for _, ev := range got.Evidence {
		if ev.Kind == "field" && ev.Citation != nil {
			hasCited = true
		}
	}
	if !hasCited {
		t.Errorf("no cited field Evidence: curve bump without evidence (D-05)")
	}
}
