/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func TestAuthScorer(t *testing.T) {
	cases := []struct {
		name        string
		r           *dissect.DissectResult
		want        int
		wantMissing bool
	}{
		{"nil", nil, 0, true},
		{"empty", &dissect.DissectResult{}, 0, true},
		{"secrets_only", &dissect.DissectResult{
			Secrets: &secret.ScanResult{TotalFindings: 1},
		}, 25, true},
		{"secrets_plus_profiles_plus_oauth_url", &dissect.DissectResult{
			Secrets:      &secret.ScanResult{TotalFindings: 1},
			WebView2Info: &webview2.Result{Profiles: []webview2.ProfileInfo{{Name: "p"}}},
			JSAnalysis:   &dissect.JSAnalysisResult{URLs: []string{"https://x/oauth/token"}},
		}, 65, true}, // 25+20+20 = 65 cap
		{"refresh_floor_70", &dissect.DissectResult{
			Secrets:      &secret.ScanResult{TotalFindings: 1},
			WebView2Info: &webview2.Result{},
			CertInfo:     &cert.CertInfo{},
		}, 70, true}, // 25+0+0=25, lifted to 70
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := authScorer{}.Score(tc.r, nil)
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
				t.Errorf("missing emit = %v, want %v", missing, tc.wantMissing)
			}
		})
	}
}
