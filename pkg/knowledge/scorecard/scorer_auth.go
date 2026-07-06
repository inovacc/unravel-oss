/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-09 baseline + W-10b:202, W-13b:48):
//
//	additive from static signals:
//	  Secrets.TotalFindings  > 0  -> +25
//	  WebView2Info.Profiles  > 0  -> +20  (cookie/session jar proxy)
//	  JSAnalysis token-strings    -> +20 if URLs contain auth/oauth/login
//	cap 65
//	floor 70 when W-10b spec-refresh marker present (Secrets present +
//	  WebView2Info present + CertInfo present)
//
//	GAP: CDP-bump auth -> 80 requires runtime capture. Always emit
//	     Evidence{Kind:"missing", Source:"runtime"} when frames are absent.
package scorecard

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(authScorer{}) }

type authScorer struct{}

func (authScorer) ID() string   { return "auth" }
func (authScorer) Name() string { return "Auth surface" }

func (authScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "auth", Name: "Auth surface"}
	if r == nil {
		out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
		return out
	}
	// P58C-01 (P64-06): auth-cap declaration / token-string discovery site.
	// JSAnalysis.File when present (oauth/login URLs surface in JS), else
	// MSIXInfo.ManifestPath when manifest carries auth caps, else SourcePath.
	var cite *Citation
	switch {
	case r.JSAnalysis != nil && r.JSAnalysis.File != "":
		cite = &Citation{File: r.JSAnalysis.File}
	case r.MSIXInfo != nil && r.MSIXInfo.ManifestPath != "":
		cite = &Citation{File: r.MSIXInfo.ManifestPath}
	default:
		cite = newCitation("", r.SourcePath, 0)
	}
	s := 0
	if r.Secrets != nil && r.Secrets.TotalFindings > 0 {
		s += 25
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "Secrets", Citation: cite})
	}
	if r.WebView2Info != nil && len(r.WebView2Info.Profiles) > 0 {
		s += 20
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "WebView2Info.Profiles", Citation: cite})
	}
	if r.JSAnalysis != nil {
		for _, u := range r.JSAnalysis.URLs {
			low := strings.ToLower(u)
			if strings.Contains(low, "oauth") || strings.Contains(low, "login") || strings.Contains(low, "auth") || strings.Contains(low, "token") {
				s += 20
				out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "JSAnalysis.URLs(auth)", Citation: cite})
				break
			}
		}
	}
	if s > 65 {
		s = 65
	}
	if r.Secrets != nil && r.WebView2Info != nil && r.CertInfo != nil && s < 70 {
		s = 70
	}
	out.Score = s
	out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
	return out
}
