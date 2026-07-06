/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-02-enumerate.ps1:94):
//
//	score = min(70, 100*inspected/total) when total > 0
//	cap 70 for the legacy curve; UWP MSIXInfo branch lifts 70->85 via
//	evidence-gated W-12 cap-deepening adders (P57 / Phase 84-04): per-PE
//	size depth, fully-signed ratio, signer attribution — each cited.
//	floor 60 if BinaryInfo or DotnetDeps present but counts unknown
//
// "inspected" is the number of binaries with non-empty per-binary fields
// (ToolResults, CertSubject, ProductName) on AppAnalysis.Binaries; "total"
// is the count of AppAnalysis.Binaries. Falls back to GarbleInfo /
// DotnetDeps presence for non-Electron stacks.
package scorecard

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

func init() { Register(binarySurfaceScorer{}) }

type binarySurfaceScorer struct{}

func (binarySurfaceScorer) ID() string   { return "binary_surface" }
func (binarySurfaceScorer) Name() string { return "Binary surface" }

// filterMSIXFilesByExt returns entries whose Name ends with any of `exts`
// (case-insensitive; exts must be lowercase, dot-prefixed).
func filterMSIXFilesByExt(files []msix.FileEntry, exts ...string) []msix.FileEntry {
	out := make([]msix.FileEntry, 0, len(files))
	for _, f := range files {
		name := strings.ToLower(f.Name)
		for _, ext := range exts {
			if strings.HasSuffix(name, ext) {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// peEntries returns entries whose Name ends with .exe or .dll.
func peEntries(files []msix.FileEntry) []msix.FileEntry {
	return filterMSIXFilesByExt(files, ".exe", ".dll")
}

// signedPercent returns 100*count(Signed!=nil && *Signed) / len(peEntries),
// truncated to integer percent. Returns 0 when there are no PE entries.
// Integer-only per RUBR-04 (no floats in scorecard math).
func signedPercent(files []msix.FileEntry) int {
	pes := peEntries(files)
	if len(pes) == 0 {
		return 0
	}
	signed := 0
	for _, p := range pes {
		if p.Signed != nil && *p.Signed {
			signed++
		}
	}
	return 100 * signed / len(pes)
}

func (binarySurfaceScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "binary_surface", Name: "Binary surface"}
	if r == nil {
		return out
	}
	total, inspected := 0, 0
	if r.AppAnalysis != nil {
		total = len(r.AppAnalysis.Binaries)
		for _, b := range r.AppAnalysis.Binaries {
			if len(b.ToolResults) > 0 || b.CertSubject != "" || b.ProductName != "" || b.StringsTotal > 0 {
				inspected++
			}
		}
	}
	cite := newCitation("", r.SourcePath, 0) // P58
	if total > 0 {
		s := 100 * inspected / total
		if s > 70 {
			s = 70
		}
		out.Score = s
		out.Evidence = append(out.Evidence, Evidence{
			Kind: "field", Path: "AppAnalysis.Binaries", Citation: cite,
		})
	}
	hasOther := r.BinaryInfo != nil || r.GarbleInfo != nil || r.DotnetDeps != nil ||
		r.DotnetRuntime != nil || r.DotNetDecompile != nil
	if hasOther && out.Score < 60 {
		out.Score = 60
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "BinaryInfo|GarbleInfo|Dotnet*", Citation: cite})
	}

	// SCRG-01 — UWP install-dir branch: triggered only when the floor blocks
	// above produced no signal AND r.MSIXInfo carries enumerated PE entries.
	// Per-PE Evidence with typed-field Citation pointing at MSIXInfo.Files[i].Name.
	if out.Score == 0 && r.MSIXInfo != nil && len(r.MSIXInfo.Files) > 0 {
		pes := peEntries(r.MSIXInfo.Files)
		if len(pes) > 0 {
			// Curve: base = min(70, 100*peCount/expectedCount) where expectedCount=3
			// (~3 PE entries is the floor for "extracted enough to inspect").
			const expectedCount = 3
			base := 100 * len(pes) / expectedCount
			if base > 70 {
				base = 70
			}
			score := base
			for i := range pes {
				out.Evidence = append(out.Evidence, Evidence{
					Kind: "field",
					Path: "MSIXInfo.Files[].Name",
					// Typed-field Citation: File = MSIXInfo.Files[i].Name (NOT r.SourcePath).
					// Hash left empty per PLAN — FileEntry has no inline hash field.
					Citation: &Citation{File: pes[i].Name},
				})
			}

			// W-12 cap-deepening (P57-deferred): lift the 70 base cap toward
			// the 85 binary_surface maturity floor ONLY via evidence-gated
			// adders, each backed by a real Evidence citation (D-05 — no flat
			// curve bump). Every adder is gated behind a per-PE depth signal
			// legacy fixtures never produce (they never enter this MSIXInfo
			// branch at all), so expected_score_w13_final.json + Teams VALD
			// stay byte/score-identical. Adders are capped at 85.

			// Adder 1: per-PE binary depth (Size>0 is the inspectable
			// import/section-depth proxy — a zero-size or unwalked entry
			// carries no inspectable surface). +5 when a majority of PEs are
			// depth-bearing.
			depthBearing := 0
			for _, p := range pes {
				if p.Size > 0 {
					depthBearing++
				}
			}
			if depthBearing*2 > len(pes) {
				score += 5
				out.Evidence = append(out.Evidence, Evidence{
					Kind: "field", Path: "MSIXInfo.Files[].Size",
					Source: "binary", Detail: "per-PE inspectable size depth (W-12)",
					// Typed-field Citation (NOT r.SourcePath — W5 invariant).
					Citation: &Citation{File: pes[0].Name},
				})
			}

			// Adder 2: signed-ratio depth — a fully Authenticode-signed PE
			// set is materially deeper attested surface than an unsigned one.
			// +5 when every PE is signed (strict, integer-only per RUBR-04).
			if signedPercent(r.MSIXInfo.Files) == 100 {
				score += 5
				out.Evidence = append(out.Evidence, Evidence{
					Kind: "field", Path: "MSIXInfo.Files[].Signed",
					Source: "binary", Detail: "fully Authenticode-signed PE set (W-12)",
					Citation: &Citation{File: pes[0].Name},
				})
			}

			// Adder 3: signer attribution depth — a recovered signer subject
			// (version-info / publisher analog) is the deepest cap-raise
			// marker. +5 when a majority of PEs carry a non-empty Signer.
			signerAttributed := 0
			for _, p := range pes {
				if p.Signer != "" {
					signerAttributed++
				}
			}
			if signerAttributed*2 > len(pes) {
				score += 5
				out.Evidence = append(out.Evidence, Evidence{
					Kind: "field", Path: "MSIXInfo.Files[].Signer",
					Source: "binary", Detail: "PE signer attribution depth (W-12)",
					Citation: &Citation{File: pes[0].Name},
				})
			}

			if score > 85 {
				score = 85
			}
			out.Score = score
		}
	}
	return out
}
