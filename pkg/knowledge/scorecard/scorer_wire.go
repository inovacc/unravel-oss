/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-05-ipc-api.ps1, W-10b:203, W-13b:47):
//
//	step from W-05 api branch using wire-relevant hits:
//	  hits > 30 -> 70
//	  hits > 5  -> 45
//	  else      -> 20
//	floor 65 when W-10b spec-refresh marker present (ProtobufAnalysis present
//	  + CertInfo).
//
//	GAP: CDP frames bump to >=85 (W-13b) requires dynamic capture. Without
//	     runtime evidence ceiling stays at 65/70. Always emit
//	     Evidence{Kind:"missing", Source:"runtime"} when frames are absent.
package scorecard

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(wireScorer{}) }

type wireScorer struct{}

func (wireScorer) ID() string   { return "wire" }
func (wireScorer) Name() string { return "Wire formats" }

func (wireScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "wire", Name: "Wire formats"}
	if r == nil {
		out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
		return out
	}
	hits := 0
	if r.ProtobufAnalysis != nil {
		hits += 5
	}
	if r.JSAnalysis != nil {
		for _, u := range r.JSAnalysis.URLs {
			if strings.HasPrefix(u, "wss://") || strings.HasPrefix(u, "ws://") {
				hits++
			}
		}
	}
	if r.WebView2Info != nil && len(r.WebView2Info.Profiles) > 0 {
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
	if r.ProtobufAnalysis != nil && r.CertInfo != nil && out.Score < 65 {
		out.Score = 65
	}
	if hits > 0 {
		// P58C-01 (P64-06): wire-protocol pattern source — JSAnalysis.File
		// when JS-discovered (wss URLs), otherwise SourcePath fallback.
		var cite *Citation
		if r.JSAnalysis != nil && r.JSAnalysis.File != "" {
			cite = &Citation{File: r.JSAnalysis.File}
		} else {
			cite = newCitation("", r.SourcePath, 0)
		}
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "ProtobufAnalysis|JSAnalysis.URLs(wss)", Citation: cite})
	}
	// missing-kind Evidence stays uncited (lenient rule)
	out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
	return out
}
