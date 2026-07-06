/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func TestWireScorer(t *testing.T) {
	cases := []struct {
		name        string
		r           *dissect.DissectResult
		want        int
		wantMissing bool
	}{
		{"nil", nil, 0, true},
		{"empty", &dissect.DissectResult{}, 20, true},
		{"protobuf_only", &dissect.DissectResult{
			ProtobufAnalysis: &protobuf.ScanResult{},
		}, 20, true}, // hits=5, not >5
		{"protobuf_plus_wss", &dissect.DissectResult{
			ProtobufAnalysis: &protobuf.ScanResult{},
			JSAnalysis: &dissect.JSAnalysisResult{
				URLs: []string{"wss://x", "wss://y"},
			},
		}, 45, true}, // 5+2 = 7 > 5
		{"refresh_floor_65", &dissect.DissectResult{
			ProtobufAnalysis: &protobuf.ScanResult{},
			CertInfo:         &cert.CertInfo{},
		}, 65, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := wireScorer{}.Score(tc.r, nil)
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
