/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

func TestFilesystemScorer(t *testing.T) {
	cases := []struct {
		name string
		r    *dissect.DissectResult
		want int
	}{
		{"nil", nil, 0},
		{"empty", &dissect.DissectResult{}, 0},
		{"msix_files_count_only", &dissect.DissectResult{
			MSIXInfo: &msix.InfoResult{FileCount: 200},
		}, 90},
		{"asar_only", &dissect.DissectResult{
			ASARFiles: []asar.ExtractedFile{{Path: "x"}},
		}, 90},
		{"spec_floor_via_cert", &dissect.DissectResult{
			MSIXInfo: &msix.InfoResult{FileCount: 200},
			CertInfo: &cert.CertInfo{},
		}, 95},
		{"spec_floor_via_signature", &dissect.DissectResult{
			MSIXInfo: &msix.InfoResult{FileCount: 200, HasSignature: true},
		}, 95},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := filesystemScorer{}.Score(tc.r, nil)
			if got.Score != tc.want {
				t.Errorf("Score = %d, want %d", got.Score, tc.want)
			}
		})
	}
}
