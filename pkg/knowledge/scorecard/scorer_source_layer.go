/*
Copyright (c) 2026 Security Research
*/

// Curve (port of .scripts/whatsapp-W-04-source.ps1:113-118, W-10:383):
//
//	additive:
//	  web    > 0 -> +30  (JSAnalysis or BeautifiedJS or ASARFiles)
//	  cache  > 0 -> +20  (WebView2 profiles or Cache parse result)
//	  dotnet > 0 -> +20  (DotNetDecompile or DotNetBeautify or SourceMap*)
//	  js     > 0 -> +20  (raw JS surface: BeautifiedJS or ASARFiles only)
//	cap 90
//	floor 90 when spec-written marker present (CertInfo non-nil)
//
// Integer arithmetic; min(sum, 90) before floor.
package scorecard

import (
	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
)

func init() { Register(sourceLayerScorer{}) }

type sourceLayerScorer struct{}

func (sourceLayerScorer) ID() string   { return "source_layer" }
func (sourceLayerScorer) Name() string { return "Source layer" }

func (sourceLayerScorer) Score(r *dissect.DissectResult, _ *analysis.ResultSet) DimScore {
	out := DimScore{ID: "source_layer", Name: "Source layer"}
	if r == nil {
		return out
	}
	// SCRG-02 — UWP install-dir branch takes precedence when MSIX install-dir
	// context is present (MSIXInfo populated with file enumeration). Returns
	// typed-field Citations against MSIXInfo.Files / JSAnalysis.File /
	// DotNetDecompile.Assemblies[i].OutDir — never r.SourcePath.
	if r.MSIXInfo != nil && len(r.MSIXInfo.Files) > 0 {
		return scoreSourceLayerUWP(r, out)
	}

	cite := newCitation("", r.SourcePath, 0) // P58
	s := 0
	web := r.JSAnalysis != nil || r.BeautifiedJS != "" || len(r.ASARFiles) > 0
	if web {
		s += 30
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "JSAnalysis|BeautifiedJS|ASARFiles", Citation: cite})
	}
	cache := (r.WebView2Info != nil && len(r.WebView2Info.Profiles) > 0) || r.Cache != nil
	if cache {
		s += 20
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "WebView2Info.Profiles|Cache", Citation: cite})
	}
	dotnet := r.DotNetDecompile != nil || r.DotNetBeautify != nil ||
		r.SourceMapInfo != nil || r.SourceMapDeps != nil
	if dotnet {
		s += 20
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "DotNetDecompile|DotNetBeautify|SourceMap*", Citation: cite})
	}
	js := r.BeautifiedJS != "" || len(r.ASARFiles) > 0
	if js {
		s += 20
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "BeautifiedJS|ASARFiles", Citation: cite})
	}
	if s > 90 {
		s = 90
	}
	if r.CertInfo != nil && (web || cache || dotnet || js) && s < 90 {
		s = 90
		out.Evidence = append(out.Evidence, Evidence{Kind: "field", Path: "spec_written_floor:CertInfo", Citation: cite})
	}

	out.Score = s
	return out
}

// scoreSourceLayerUWP scores the source_layer dim from a UWP install-dir
// surface (r.MSIXInfo populated). Per-file Evidence with typed-field
// Citations: MSIXInfo.Files[i].Name, JSAnalysis.File, or
// DotNetDecompile.Assemblies[i].OutDir (preferred) / Path (fallback).
// .NET branch skipped silently when DotNetDecompile is nil.
func scoreSourceLayerUWP(r *dissect.DissectResult, out DimScore) DimScore {
	jsHits := filterMSIXFilesByExt(r.MSIXInfo.Files, ".js")
	htmlHits := filterMSIXFilesByExt(r.MSIXInfo.Files, ".html", ".htm")
	cssHits := filterMSIXFilesByExt(r.MSIXInfo.Files, ".css")
	jsonHits := filterMSIXFilesByExt(r.MSIXInfo.Files, ".json")

	s := 0
	if len(jsHits) > 0 {
		s += 30
	}
	if len(htmlHits) > 0 {
		s += 20
	}
	if r.JSAnalysis != nil {
		s += 20
	}
	if r.DotNetDecompile != nil {
		for _, a := range r.DotNetDecompile.Assemblies {
			if a.Decompiled {
				s += 20
				break
			}
		}
	}
	if s > 90 {
		s = 90
	}
	if s == 0 {
		return out
	}
	out.Score = s
	for _, group := range [][]msix.FileEntry{jsHits, htmlHits, cssHits, jsonHits} {
		for _, f := range group {
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "MSIXInfo.Files[].Name",
				Citation: &Citation{File: f.Name},
			})
		}
	}
	if r.JSAnalysis != nil && r.JSAnalysis.File != "" {
		out.Evidence = append(out.Evidence, Evidence{
			Kind:     "field",
			Path:     "JSAnalysis.File",
			Citation: &Citation{File: r.JSAnalysis.File},
		})
	}
	if r.DotNetDecompile != nil {
		for i, a := range r.DotNetDecompile.Assemblies {
			if !a.Decompiled {
				continue
			}
			target := a.OutDir
			if target == "" {
				target = a.Path
			}
			if target == "" {
				continue
			}
			out.Evidence = append(out.Evidence, Evidence{
				Kind:     "field",
				Path:     "DotNetDecompile.Assemblies[].OutDir",
				Detail:   r.DotNetDecompile.Assemblies[i].Name,
				Citation: &Citation{File: target},
			})
		}
	}
	return out
}
