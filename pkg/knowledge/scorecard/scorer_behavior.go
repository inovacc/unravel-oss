/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-08-runtime.ps1:134, W-10b:204):
//
//	score := min(100, 10*scenarios)
//	floor 85 when W-10b spec-refresh marker present (Disassembly or
//	  WebView2Info present + CertInfo).
//
//	GAP: scenarios are runtime traces (W-08 Frida + W-13 CDP). Without runtime
//	     scenarios the score is naturally low or 0. Always emit
//	     Evidence{Kind:"missing", Source:"runtime"} when absent.
//
// Static "scenarios" proxy here: presence of Disassembly, WebView2Info, and
// FridaScripts (which P57 will replace with true scenario counts).
//
// SCRG-05 (P64) — UWP install-dir branch: when MSIXInfo carries Capabilities
// or URLs (or JSAnalysis carries URLs), emit per-signal Evidence with
// typed-field Citations:
//   - Capability evidence: Citation.File = r.MSIXInfo.ManifestPath (real after 64-00b)
//   - URL evidence (JSAnalysis.URLs): Citation.File = r.JSAnalysis.File
//   - URL evidence (MSIXInfo.URLs):   Citation.File = r.MSIXInfo.ManifestPath
//   - UI scenario hint (manifest-startup-task or window-class names in
//     MSIXInfo.Files): Citation.File = r.MSIXInfo.Files[i].Name
//
// Documented drift: ceiling ~50–70 vs expected 85; tolerance widens to ±15
// for behavior dim per PLAN-64. Tracked as v2.12-CARRYOVER-SCRG-05-DEEPENING.
package scorecard

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func init() { Register(behaviorScorer{}) }

type behaviorScorer struct{}

func (behaviorScorer) ID() string   { return "behavior" }
func (behaviorScorer) Name() string { return "Behavior" }

func (behaviorScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "behavior", Name: "Behavior"}
	if r == nil {
		out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
		return out
	}
	scenarios := 0
	if r.Disassembly != nil {
		scenarios++
	}
	if r.WebView2Info != nil {
		scenarios++
	}
	if r.FridaScripts != nil {
		scenarios++
	}
	score := 10 * scenarios
	if score > 100 {
		score = 100
	}
	specRefresh := (r.Disassembly != nil || r.WebView2Info != nil) && r.CertInfo != nil
	if specRefresh && score < 85 {
		score = 85
	}
	out.Score = score

	// SCRG-05 — UWP install-dir branch. Triggers when the legacy curve produced
	// a low score AND r.MSIXInfo carries actionable signal. Only kicks in when
	// the legacy floor (85 spec-refresh) did NOT engage, so this is purely
	// additive for UWP install-dir input that lacks runtime scenarios.
	if r.MSIXInfo != nil && score < 85 {
		uwpScore := scoreBehaviorUWP(r, &out)
		if uwpScore > out.Score {
			out.Score = uwpScore
		}
	}

	// Plan 69-02 (SCRG-05D): additive scenario-replay seam. Reads the
	// frames.ndjson sidecar (written by frames_writer.go) under
	// <scorecardBaseDir>/<MSIXInfo.PackageName>/ and contributes 0..30 past the
	// legacy 70 UWP cap. Missing file = 0 (no error), so legacy fixtures stay
	// byte-identical. Additive-only — never reduces out.Score.
	if r.MSIXInfo != nil && r.MSIXInfo.PackageName != "" {
		bonus := scoreBehaviorScenarios(r.MSIXInfo.PackageName)
		if bonus > 0 {
			out.Score += bonus
			if out.Score > 100 {
				out.Score = 100
			}
			out.Evidence = append(out.Evidence, Evidence{
				Kind:   "field",
				Path:   "frames.ndjson (scenario-replay)",
				Source: "runtime",
				Detail: "scenario-replay seam (SCRG-05D)",
			})
		}
	}

	out.Evidence = append(out.Evidence, Evidence{Kind: "missing", Source: "runtime", Detail: "no runtime capture (P57)"})
	return out
}

// scoreBehaviorUWP appends per-signal Evidence with typed-field Citations and
// returns the UWP-curve score. Curve:
//
//	+5 per declared MSIXInfo.Capability (cap at 30)
//	+10 if JSAnalysis.URLs non-empty (URL pattern signal)
//	+10 if MSIXInfo.URLs non-empty (manifest URL signal)
//	+10 if any MSIXInfo.Files entry name matches a UI scenario hint pattern
//	cap 70 (documented drift; expected 85; tolerance ±15)
func scoreBehaviorUWP(r *dissect.DissectResult, out *DimScore) int {
	s := 0
	manifestPath := r.MSIXInfo.ManifestPath
	// Capability evidence — Citation.File = manifest path (real after 64-00b).
	caps := r.MSIXInfo.Capabilities
	capScore := 5 * len(caps)
	if capScore > 30 {
		capScore = 30
	}
	if len(caps) > 0 {
		s += capScore
		out.Evidence = append(out.Evidence, Evidence{
			Kind:     "field",
			Path:     "MSIXInfo.Capabilities",
			Detail:   strings.Join(caps, ","),
			Citation: &Citation{File: manifestPath},
		})
	}
	// URL pattern signal — JSAnalysis source.
	if r.JSAnalysis != nil && len(r.JSAnalysis.URLs) > 0 {
		s += 10
		out.Evidence = append(out.Evidence, Evidence{
			Kind:     "field",
			Path:     "JSAnalysis.URLs",
			Citation: &Citation{File: r.JSAnalysis.File},
		})
	}
	// URL pattern signal — manifest source.
	if len(r.MSIXInfo.URLs) > 0 {
		s += 10
		out.Evidence = append(out.Evidence, Evidence{
			Kind:     "field",
			Path:     "MSIXInfo.URLs",
			Citation: &Citation{File: manifestPath},
		})
	}
	// UI scenario hint — manifest-startup-task or window-class names embedded
	// in MSIXInfo.Files entries (heuristic: known indicator substrings).
	for _, f := range r.MSIXInfo.Files {
		lower := strings.ToLower(f.Name)
		if strings.Contains(lower, "startuptask") || strings.Contains(lower, "background") ||
			strings.HasSuffix(lower, ".xaml") {
			s += 10
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "MSIXInfo.Files[].Name (ui-scenario-hint)",
				Citation: &Citation{File: f.Name},
			})
			break
		}
	}
	if s > 70 {
		s = 70
	}
	return s
}
