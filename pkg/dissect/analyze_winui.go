/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/winui"
	winuidetect "github.com/inovacc/unravel-oss/pkg/winui/detect"
	_ "github.com/inovacc/unravel-oss/pkg/winui/runtime" // wire orchestrator into winui.Analyze
)

func init() {
	RegisterAnalyzer(analyzeWinUI, detect.TypeWinUIApp)
	// Plan note: the spec listed detect.TypeNETApp, but no such constant
	// exists in pkg/detect (FileType list verified). .NET host binaries
	// surface as TypePE, so registering supplemental on TypePE alone is
	// sufficient — tracked as a Rule 3 deviation in 04-01-SUMMARY.
	RegisterSupplementalAnalyzer(analyzeWinUISupplemental, detect.TypePE)
}

// analyzeWinUI is the PRIMARY WinUI analyzer (registered on TypeWinUIApp).
// Plan 05 upgrade: invoke the full winui.Analyze pipeline (XAML walk,
// XBF decode, PE-embed scan, PRI parse) in addition to the cheap-path
// detectors that plan 01 wired.
func analyzeWinUI(r *DissectResult, path string, opts Options) {
	// Cheap-path first — populates Frameworks/Signals from already-parsed
	// upstream data even when path-level analysis fails (e.g. nonexistent
	// path in tests).
	res := &winui.Result{}
	runWinUIDetect(r, path, res)

	// Full pipeline — only attempt when path exists on disk; silently skip
	// the path-level analysis otherwise (the cheap-path detectors above
	// already populated frameworks from upstream-parsed data).
	var full *winui.Result
	if path != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			res2, err := winui.Analyze(path, winui.Options{
				DecodeXBF:      true,
				ScanPEEmbedded: true,
				ParsePRI:       true,
				RejectSymlinks: true,
			})
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("winui analysis: %v", err))
			}
			full = res2
		}
	}
	if full != nil {
		// Merge full pipeline results into res (which already carries
		// cheap-path frameworks/signals).
		res.Frameworks = winui.MergeFrameworksDedup(res.Frameworks, full.Frameworks)
		res.Signals = append(res.Signals, full.Signals...)
		res.XAMLIndex = full.XAMLIndex
		res.Errors = append(res.Errors, full.Errors...)
	}

	res.IsWinUI = false
	for _, fi := range res.Frameworks {
		if fi.Name == "WinUI 3" {
			res.IsWinUI = true
			break
		}
	}
	r.WinUIInfo = res
	r.Frameworks = winui.MergeFrameworksDedup(r.Frameworks, res.Frameworks)
}

// analyzeWinUISupplemental is the cheap-path tier for hybrid stacks (FRM-09).
// Triggered on TypePE; returns early when no MUX/WUX import or Microsoft.WinUI
// deps reference is found. NEVER overwrites an existing r.WinUIInfo populated
// by the primary analyzer.
func analyzeWinUISupplemental(r *DissectResult, path string, opts Options) {
	if r.WinUIInfo != nil {
		return
	}
	res := &winui.Result{}
	runWinUIDetect(r, path, res)
	if len(res.Frameworks) == 0 && len(res.Signals) == 0 {
		// No cheap signal — short-circuit, do not pollute r.WinUIInfo.
		return
	}
	for _, fi := range res.Frameworks {
		if fi.Name == "WinUI 3" {
			res.IsWinUI = true
			break
		}
	}
	r.WinUIInfo = res
	r.Frameworks = winui.MergeFrameworksDedup(r.Frameworks, res.Frameworks)
}

// runWinUIDetect populates res.Frameworks and res.Signals using whatever
// upstream-parsed data already lives on r (DotnetDeps, BinaryInfo). Never
// touches the filesystem. Demotes MUX confidence to "medium" when no
// deps.json corroboration is present (RESEARCH.md disambiguation).
func runWinUIDetect(r *DissectResult, _ string, res *winui.Result) {
	// 1. deps.json side.
	if r != nil && r.DotnetDeps != nil {
		pkgs := make([]winuidetect.PackageRef, 0, len(r.DotnetDeps.PackageLibs)+len(r.DotnetDeps.ProjectLibs))
		for _, lib := range r.DotnetDeps.PackageLibs {
			pkgs = append(pkgs, winuidetect.PackageRef{Name: lib.Name, Version: lib.Version})
		}
		for _, lib := range r.DotnetDeps.ProjectLibs {
			pkgs = append(pkgs, winuidetect.PackageRef{Name: lib.Name, Version: lib.Version})
		}
		res.Frameworks = append(res.Frameworks, winuidetect.DetectFromDeps(pkgs)...)
	}

	// 2. PE import side. r.BinaryInfo carries the already-parsed import list
	// when upstream binary analysis ran; nil-safe access.
	imports := binaryImports(r)
	if len(imports) > 0 {
		signals := winuidetect.DetectFromImports(imports)
		res.Signals = append(res.Signals, signals...)
		// Promote MUX/WUX signals into FrameworkInfo entries with confidence
		// adjusted by deps.json corroboration.
		hasDepsCorroboration := false
		for _, fi := range res.Frameworks {
			if fi.Source == "dotnet-deps" && (fi.Name == "WinUI 3" || fi.Name == "WindowsAppSDK") {
				hasDepsCorroboration = true
				break
			}
		}
		for _, sig := range signals {
			if sig.Detail == winuidetect.DLLMUX {
				conf := sig.Confidence
				if !hasDepsCorroboration && conf == "high" {
					conf = "medium"
				}
				res.Frameworks = append(res.Frameworks, winui.FrameworkInfo{
					Name:       "WinUI 3",
					Confidence: conf,
					Evidence:   []string{sig.Detail},
					Source:     "pe-import",
				})
			} else if sig.Detail == winuidetect.DLLWUX {
				res.Frameworks = append(res.Frameworks, winui.FrameworkInfo{
					Name:       "UWP/WinUI 2",
					Confidence: sig.Confidence,
					Evidence:   []string{sig.Detail},
					Source:     "pe-import",
				})
			}
		}
	}
}

// binaryImports returns the PE imports already parsed onto r.BinaryInfo,
// or nil when none have been recorded. Defined as a separate helper so the
// access path is mockable from tests via direct r.BinaryInfo population.
func binaryImports(r *DissectResult) []string {
	if r == nil || r.BinaryInfo == nil {
		return nil
	}
	return r.BinaryInfo.Imports
}

// mergeFrameworksDedup is retained as a thin alias for backward
// compatibility within the dissect package; the canonical helper now
// lives in pkg/winui (D-02). Tests call this name directly.
func mergeFrameworksDedup(base, add []winui.FrameworkInfo) []winui.FrameworkInfo {
	return winui.MergeFrameworksDedup(base, add)
}

// Compile-time guards: ensure dotnet result types still expose the fields
// runWinUIDetect depends on. Imports kept here keep the dependency edge
// visible and prevent accidental removal.
var _ = dotnet.DepsResult{}
