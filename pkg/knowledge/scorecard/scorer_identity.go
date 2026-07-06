/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-01-acquire.ps1:70, W-02:92, W-10:381):
//
//	step: 60 (acquired)   -> Detection populated
//	      80 (enumerated) -> + manifest/MSIX/UWP/WebView2 typed field non-nil
//	      90 (spec floor) -> + CertInfo non-nil (W-10 spec-written floor)
//
// Integer; no caps beyond step ceilings.
package scorecard

import (
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(identityScorer{}) }

type identityScorer struct{}

func (identityScorer) ID() string   { return "identity" }
func (identityScorer) Name() string { return "Identity" }

func (identityScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "identity", Name: "Identity"}
	if r == nil {
		return out
	}
	// P58C-01 (P64-06): per-typed-field Citation. Identity binds to
	// MSIXInfo.ManifestPath when present; otherwise falls back to legacy
	// SourcePath citation for non-UWP stacks.
	var cite *Citation
	if r.MSIXInfo != nil && r.MSIXInfo.ManifestPath != "" {
		cite = &Citation{File: r.MSIXInfo.ManifestPath}
	} else {
		cite = newCitation("", r.SourcePath, 0)
	}
	if r.Detection != nil {
		out.Score = 60
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "Detection", Citation: cite})
	}
	enumerated := r.ManifestInfo != nil || r.MSIXInfo != nil || r.UWPInfo != nil ||
		r.WebView2Info != nil || r.IPAInfo != nil || r.NSISInfo != nil || r.MSIInfo != nil ||
		r.DEBInfo != nil || r.RPMInfo != nil
	if enumerated && out.Score < 80 {
		out.Score = 80
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "ManifestInfo|MSIXInfo|UWPInfo|WebView2Info", Citation: cite})
	}
	if r.CertInfo != nil && out.Score < 90 {
		out.Score = 90
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "CertInfo", Citation: cite})
	}
	return out
}
