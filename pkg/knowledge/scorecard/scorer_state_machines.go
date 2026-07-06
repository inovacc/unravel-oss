/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-08-runtime.ps1:135, W-10b:203):
//
//	score := min(80, 10*scenarios - 20); if score < 0 { score = 0 }
//	floor 80 when W-10b spec-refresh marker present (FrameworkAnalysis +
//	  CertInfo).
//
//	GAP: scenarios are runtime evidence (W-08 Frida traces). Without runtime
//	     scenarios this naturally yields 0 — that is correct. Always emit
//	     Evidence{Kind:"missing", Source:"runtime"} when absent.
//
// Static "scenarios" proxy here: count of FrameworkAnalysis + AppAnalysis
// presence, since DissectResult does not expose a true scenario count
// without a P57 deepening analyzer.
//
// SCRG-05 parity (Phase 83 / VALD-01) — UWP/WebView2 install-dir branch:
// the legacy curve only recognized Frida/Electron-era signals
// (FrameworkAnalysis/AppAnalysis/JSAnalysis), none of which the UWP/WebView2
// (MSIX Teams) capture path populates. The behavior scorer received this
// recognition in P64 (scorer_behavior.go:65 specRefresh on WebView2Info) but
// state_machines did not, so a real Teams CDP rescan that legitimately lifted
// behavior 10->85 from WebView2Info+CertInfo still scored state_machines 0.
// This adds the same earned spec-refresh recognition: when a real WebView2
// capture (WebView2Info, from the phase-83 on-disk EBWebView pass) is present
// alongside CertInfo, treat it as a spec-refresh scenario exactly as behavior
// does. Score is earned from the same real captured signal — no fabrication.
// Legacy fixtures (no WebView2Info/MSIXInfo set) stay byte-identical.
package scorecard

import (
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(stateMachinesScorer{}) }

type stateMachinesScorer struct{}

func (stateMachinesScorer) ID() string   { return "state_machines" }
func (stateMachinesScorer) Name() string { return "State machines" }

func (stateMachinesScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "state_machines", Name: "State machines"}
	if r == nil {
		out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
		return out
	}
	scenarios := 0
	if r.FrameworkAnalysis != nil {
		scenarios++
	}
	if r.AppAnalysis != nil {
		scenarios++
	}
	if r.JSAnalysis != nil {
		scenarios++
	}
	// SCRG-05 parity: a real WebView2 capture is itself a runtime spec-refresh
	// scenario (mirrors scorer_behavior.go which counts WebView2Info as a
	// scenario). Additive to the legacy proxy count; legacy fixtures never set
	// WebView2Info so they are unaffected.
	if r.WebView2Info != nil {
		scenarios++
	}
	score := 10*scenarios - 20
	if score < 0 {
		score = 0
	}
	if score > 80 {
		score = 80
	}
	// Legacy spec-refresh floor (W-10b): FrameworkAnalysis + CertInfo.
	if r.FrameworkAnalysis != nil && r.CertInfo != nil && score < 80 {
		score = 80
	}
	// SCRG-05 parity spec-refresh floor: a real WebView2 capture alongside
	// CertInfo is the same earned spec-refresh marker that gives the behavior
	// dim its 85 floor (scorer_behavior.go:65). Apply the state_machines 80
	// floor symmetrically so a real Teams WebView2+CertInfo rescan scores
	// state_machines from the same captured signal that lifted behavior.
	if r.WebView2Info != nil && r.CertInfo != nil && score < 80 {
		score = 80
		out.Evidence = append(out.Evidence, Evidence{
			Kind:   "field",
			Path:   "WebView2Info",
			Source: "runtime",
			Detail: "WebView2 capture spec-refresh (SCRG-05 parity)",
		})
	}
	out.Score = score
	out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
	return out
}
