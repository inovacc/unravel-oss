/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/framework"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	elecapp "github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func TestStateMachinesScorer(t *testing.T) {
	cases := []struct {
		name        string
		r           *dissect.DissectResult
		want        int
		wantMissing bool
	}{
		{"nil", nil, 0, true},
		{"empty", &dissect.DissectResult{}, 0, true},
		{"one_scenario", &dissect.DissectResult{
			FrameworkAnalysis: &framework.ScanResult{},
		}, 0, true}, // 10*1-20 = -10 -> 0
		{"two_scenarios", &dissect.DissectResult{
			FrameworkAnalysis: &framework.ScanResult{},
			AppAnalysis:       &elecapp.Result{},
		}, 0, true}, // 10*2-20=0
		{"three_scenarios", &dissect.DissectResult{
			FrameworkAnalysis: &framework.ScanResult{},
			AppAnalysis:       &elecapp.Result{},
			JSAnalysis:        &dissect.JSAnalysisResult{},
		}, 10, true}, // 10*3-20=10
		{"refresh_floor_80", &dissect.DissectResult{
			FrameworkAnalysis: &framework.ScanResult{},
			CertInfo:          &cert.CertInfo{},
		}, 80, true},
		// SCRG-05 parity (Phase 83 / VALD-01): a real WebView2 capture is a
		// runtime scenario; with CertInfo it earns the spec-refresh floor,
		// mirroring scorer_behavior.go. Reproduces the real Teams rescan that
		// carries WebView2Info (phase-83 EBWebView pass) + CertInfo (crypto=90).
		{"webview2_only_scenario", &dissect.DissectResult{
			WebView2Info: &webview2.Result{},
		}, 0, true}, // 10*1-20 = -10 -> 0 (no CertInfo, no floor)
		{"webview2_plus_cert_floor", &dissect.DissectResult{
			WebView2Info: &webview2.Result{},
			CertInfo:     &cert.CertInfo{},
		}, 80, true}, // SCRG-05 parity spec-refresh floor (Teams VALD-01 case)
		{"webview2_plus_framework_two_scenarios", &dissect.DissectResult{
			FrameworkAnalysis: &framework.ScanResult{},
			WebView2Info:      &webview2.Result{},
		}, 0, true}, // 10*2-20=0 (no CertInfo)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stateMachinesScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
			missing := false
			for _, e := range got.Evidence {
				if e.Kind == "missing" && e.Source == "runtime" {
					missing = true
				}
			}
			if missing != tc.wantMissing {
				t.Errorf("missing = %v, want %v", missing, tc.wantMissing)
			}
		})
	}
}
