/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-05-ipc-api.ps1:99, W-08:138, W-10b:202):
//
//	step on total IPC hits (preload, ipcRenderer, host-bridge):
//	  hits > 30 -> 70
//	  hits > 5  -> 45
//	  else      -> 20
//	floor 50 when W-10b spec-refresh marker present (here: WebView2Info present
//	  AND CertInfo present, mirroring the spec refresh gate).
//
//	GAP: requires dynamic IPC capture (W-08 scenarios) for floor 40 lift and
//	     W-13 CDP host-bridge frames for >75. Without runtime data the static
//	     ceiling stays at 70. Always emit Evidence{Kind:"missing",
//	     Source:"runtime", Detail:"no runtime capture (P57)"} when scenarios
//	     are absent — P57's deepening loop reads this marker.
package scorecard

import (
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(ipcScorer{}) }

type ipcScorer struct{}

func (ipcScorer) ID() string   { return "ipc" }
func (ipcScorer) Name() string { return "IPC" }

func (ipcScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "ipc", Name: "IPC"}
	if r == nil {
		out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
		return out
	}
	hits := 0
	if r.AppAnalysis != nil {
		hits += len(r.AppAnalysis.Analysis.IPCCommands)
	}
	if r.WebView2Info != nil {
		hits += len(r.WebView2Info.UDFs)
	}
	if r.ExtAnalysis != nil {
		hits += 1
	}
	switch {
	case hits > 30:
		out.Score = 70
	case hits > 5:
		out.Score = 45
	default:
		out.Score = 20
	}
	if r.WebView2Info != nil && r.CertInfo != nil && out.Score < 50 {
		out.Score = 50
	}
	if hits > 0 {
		// P58C-01 (P64-06): IPC channel discovery site — JSAnalysis.File
		// when present (preload/ipcRenderer source), else SourcePath.
		var cite *Citation
		if r.JSAnalysis != nil && r.JSAnalysis.File != "" {
			cite = &Citation{File: r.JSAnalysis.File}
		} else {
			cite = newCitation("", r.SourcePath, 0)
		}
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "AppAnalysis.IPCCommands|WebView2Info.UDFs", Citation: cite})
	}
	// missing-kind Evidence stays uncited (lenient rule, citations.go)
	out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
	return out
}
