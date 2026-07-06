/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

func TestIdentityScorer(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		{"nil", nil, 0},
		{"empty", &dissect.DissectResult{}, 0},
		{"acquired", &dissect.DissectResult{Detection: &detect.DetectResult{}}, 60},
		{"enumerated", &dissect.DissectResult{
			Detection: &detect.DetectResult{},
			MSIXInfo:  &msix.InfoResult{PackageName: "x"},
		}, 80},
		{"spec_floor", &dissect.DissectResult{
			Detection: &detect.DetectResult{},
			MSIXInfo:  &msix.InfoResult{PackageName: "x"},
			CertInfo:  &cert.CertInfo{HasSignature: true},
		}, 90},
		{"cert-only-without-detection-no-jump", &dissect.DissectResult{
			CertInfo: &cert.CertInfo{},
		}, 90},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := identityScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
			if got.ID != "identity" || got.Name == "" {
				t.Errorf("ID/Name = %q/%q", got.ID, got.Name)
			}
		})
	}
}
