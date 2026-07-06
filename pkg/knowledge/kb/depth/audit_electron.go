/*
Copyright (c) 2026 Security Research
*/

// audit_electron.go: Electron extractor coverage audit (D-38-DIMENSIONS-PER-STACK).
package depth

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// AuditElectron returns one Dimension per audited Electron sub-extractor.
// Returns nil when dr is nil OR view is nil.
//
// Dimensions (canonical order):
//
//	electron.asar_files, electron.javascript_imports, electron.electron_main,
//	electron.renderer_processes, electron.ipc_channels, electron.bundled_node_modules,
//	electron.source_maps
func AuditElectron(dr *dissect.DissectResult, view ElectronCoverageView) []Dimension {
	if dr == nil || view == nil {
		return nil
	}
	return []Dimension{
		NewDimension("electron.asar_files", view.ASARFilesCovered(), totalElectronASAR(dr)),
		NewDimension("electron.javascript_imports", view.JavaScriptImportsCovered(), totalElectronJSImports(dr)),
		NewDimension("electron.electron_main", view.ElectronMainCovered(), totalElectronMain(dr)),
		NewDimension("electron.renderer_processes", view.RendererProcessesCovered(), totalElectronRenderers(dr)),
		NewDimension("electron.ipc_channels", view.IPCChannelsCovered(), totalElectronIPC(dr)),
		NewDimension("electron.bundled_node_modules", view.BundledNodeModulesCovered(), totalElectronNodeModules(dr)),
		NewDimension("electron.source_maps", view.SourceMapsCovered(), totalElectronSourceMaps(dr)),
	}
}

// ---- total_electron_* helpers -------------------------------------------

func totalElectronASAR(dr *dissect.DissectResult) int {
	return len(dr.ASARFiles)
}

func totalElectronJSImports(dr *dissect.DissectResult) int {
	if dr.JSAnalysis == nil {
		return 0
	}
	return len(dr.JSAnalysis.Indicators)
}

func totalElectronMain(dr *dissect.DissectResult) int {
	// Count main-process entry signals: package.json main, asar main.js,
	// AppAnalysis.AppInfo.Name (presence of analyzed Electron app).
	if dr.AppAnalysis != nil && dr.AppAnalysis.AppInfo.Name != "" {
		return 1
	}
	for _, f := range dr.ASARFiles {
		base := strings.ToLower(f.Path)
		if strings.HasSuffix(base, "/main.js") || base == "main.js" {
			return 1
		}
	}
	return 0
}

func totalElectronRenderers(dr *dissect.DissectResult) int {
	// Renderer surface = number of distinct preload + index.html signals in
	// ASAR. Coarse upper-bound; AuditElectron measures population coverage.
	if len(dr.ASARFiles) == 0 {
		return 0
	}
	n := 0
	for _, f := range dr.ASARFiles {
		lower := strings.ToLower(f.Path)
		base := lower
		if i := strings.LastIndex(lower, "/"); i >= 0 {
			base = lower[i+1:]
		}
		if strings.HasPrefix(base, "preload") && strings.HasSuffix(base, ".js") {
			n++
		} else if base == "index.html" {
			n++
		}
	}
	return n
}

func totalElectronIPC(dr *dissect.DissectResult) int {
	if dr.AppAnalysis == nil {
		return 0
	}
	return len(dr.AppAnalysis.Analysis.IPCCommands)
}

func totalElectronNodeModules(dr *dissect.DissectResult) int {
	if len(dr.ASARFiles) == 0 {
		return 0
	}
	mods := map[string]struct{}{}
	for _, f := range dr.ASARFiles {
		idx := strings.Index(f.Path, "node_modules/")
		if idx < 0 {
			continue
		}
		rest := f.Path[idx+len("node_modules/"):]
		// First path component after node_modules/ is the module name.
		if slash := strings.Index(rest, "/"); slash > 0 {
			rest = rest[:slash]
		}
		if rest == "" {
			continue
		}
		mods[rest] = struct{}{}
	}
	return len(mods)
}

func totalElectronSourceMaps(dr *dissect.DissectResult) int {
	if dr.SourceMapInfo == nil {
		return 0
	}
	// SourceMapInfo presence == 1 source map parsed; fine-grained per-file
	// expansion lives in pkg/sourcemap and is not surfaced here.
	return 1
}
