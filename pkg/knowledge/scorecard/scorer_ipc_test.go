/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	elecapp "github.com/inovacc/unravel-oss/pkg/electron/app"
	ipcfind "github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func mkIPC(n int) []ipcfind.Finding {
	out := make([]ipcfind.Finding, n)
	return out
}

func TestIPCScorer(t *testing.T) {
	cases := []struct {
		name        string
		r           *dissect.DissectResult
		want        int
		wantMissing bool
	}{
		{"nil", nil, 0, true},
		{"empty", &dissect.DissectResult{}, 20, true},
		{"low_hits_5", &dissect.DissectResult{
			AppAnalysis: &elecapp.Result{Analysis: elecapp.SecurityResult{IPCCommands: mkIPC(5)}},
		}, 20, true}, // hits=5, not >5
		{"mid_hits_6", &dissect.DissectResult{
			AppAnalysis: &elecapp.Result{Analysis: elecapp.SecurityResult{IPCCommands: mkIPC(6)}},
		}, 45, true},
		{"high_hits_31", &dissect.DissectResult{
			AppAnalysis: &elecapp.Result{Analysis: elecapp.SecurityResult{IPCCommands: mkIPC(31)}},
		}, 70, true},
		{"refresh_floor_50", &dissect.DissectResult{
			WebView2Info: &webview2.Result{IsWebView2: true},
			CertInfo:     &cert.CertInfo{},
		}, 50, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ipcScorer{}.Score(tc.r, nil)
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
				t.Errorf("missing-evidence emitted = %v, want %v", missing, tc.wantMissing)
			}
		})
	}
}
