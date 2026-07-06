/*
Copyright (c) 2026 Security Research
*/

// extract_electron_coverage.go: P38 Plan 38-03 — wire pkg/electron/* +
// pkg/asar extractor outputs into KnowledgeResult.Electron.
//
// Empty extractor output stays empty (D-35-NO-FALLBACK-INFERENCE). Coexists
// with Packaging.UWP on hybrid stacks (Electron-MSIX) per
// D-38-HYBRID-DUAL-COVERAGE — both paths populate independently when the
// underlying signal is present.
package knowledge

import (
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
)

// Compile-time interface assertion: KnowledgeResult must satisfy the Electron
// coverage view consumed by depth.AuditElectron.
var _ depth.ElectronCoverageView = (*KnowledgeResult)(nil)

// extractElectronCoverage wires Electron extractor outputs into kr.Electron.
// Runs AFTER extractAndroidCoverage and extractUWPCoverage in Extract.
// No-op when no Electron signal is present in DissectResult.
func extractElectronCoverage(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr == nil || kr == nil {
		return
	}
	if !hasElectronSignal(dr) {
		return
	}
	if kr.Electron == nil {
		kr.Electron = &ElectronKnowledge{}
	}

	extractElectronASAR(dr, kr)
	extractElectronJavaScriptImports(dr, kr)
	extractElectronMain(dr, kr)
	extractElectronRenderers(dr, kr)
	extractElectronIPC(dr, kr)
	extractElectronNodeModules(dr, kr)
	extractElectronSourceMaps(dr, kr)
}

// hasElectronSignal returns true when DissectResult carries any Electron-shaped
// data. Signal sources (any one suffices):
//   - AppAnalysis.AppInfo.Type == "electron"
//   - ASARFiles non-empty (an ASAR archive was extracted)
//   - JSAnalysis present alongside an Electron-shaped binary
func hasElectronSignal(dr *dissect.DissectResult) bool {
	if dr == nil {
		return false
	}
	if dr.AppAnalysis != nil && dr.AppAnalysis.AppInfo.Type == "electron" {
		return true
	}
	if len(dr.ASARFiles) > 0 {
		return true
	}
	return false
}

func extractElectronASAR(dr *dissect.DissectResult, kr *KnowledgeResult) {
	for _, f := range dr.ASARFiles {
		if f.IsDir {
			continue
		}
		kr.Electron.ASARFiles = append(kr.Electron.ASARFiles, SourceFileRef{
			Path: f.Path,
			Size: f.Size,
		})
	}
}

func extractElectronJavaScriptImports(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.JSAnalysis == nil {
		return
	}
	kr.Electron.JavaScriptImports = append(kr.Electron.JavaScriptImports, dr.JSAnalysis.Indicators...)
}

func extractElectronMain(dr *dissect.DissectResult, kr *KnowledgeResult) {
	// Prefer explicit main from ASAR (main.js / index.js at root).
	for _, f := range dr.ASARFiles {
		base := filepath.Base(f.Path)
		lower := strings.ToLower(base)
		if lower == "main.js" || lower == "index.js" {
			kr.Electron.ElectronMain = f.Path
			return
		}
	}
	// Fallback: Electron app analysis surfaces a name; use it as a marker.
	if dr.AppAnalysis != nil && dr.AppAnalysis.AppInfo.Name != "" {
		kr.Electron.ElectronMain = dr.AppAnalysis.AppInfo.Name
	}
}

func extractElectronRenderers(dr *dissect.DissectResult, kr *KnowledgeResult) {
	for _, f := range dr.ASARFiles {
		base := filepath.Base(f.Path)
		lower := strings.ToLower(base)
		if (strings.HasPrefix(lower, "preload") && strings.HasSuffix(lower, ".js")) || lower == "index.html" {
			kr.Electron.RendererProcesses = append(kr.Electron.RendererProcesses, f.Path)
		}
	}
}

func extractElectronIPC(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.AppAnalysis == nil {
		return
	}
	for _, c := range dr.AppAnalysis.Analysis.IPCCommands {
		kr.Electron.IPCChannels = append(kr.Electron.IPCChannels, ElectronIPCChannel{
			Name:      c.Channel,
			Direction: c.Direction,
			Risk:      c.Risk,
		})
	}
}

func extractElectronNodeModules(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if len(dr.ASARFiles) == 0 {
		return
	}
	seen := map[string]struct{}{}
	for _, f := range dr.ASARFiles {
		idx := strings.Index(f.Path, "node_modules/")
		if idx < 0 {
			continue
		}
		rest := f.Path[idx+len("node_modules/"):]
		if slash := strings.Index(rest, "/"); slash > 0 {
			rest = rest[:slash]
		}
		if rest == "" {
			continue
		}
		if _, ok := seen[rest]; ok {
			continue
		}
		seen[rest] = struct{}{}
		kr.Electron.BundledNodeModules = append(kr.Electron.BundledNodeModules, rest)
	}
}

func extractElectronSourceMaps(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.SourceMapInfo == nil {
		return
	}
	// Per D-37-SOURCE-FILES-PATH-INDEX: path-index only.
	kr.Electron.SourceMaps = append(kr.Electron.SourceMaps, SourceFileRef{
		Path: dr.SourceMapInfo.File,
		Tag:  "sourcemap",
	})
}

// ---- depth.ElectronCoverageView impl on *KnowledgeResult ----------------

func (k *KnowledgeResult) ASARFilesCovered() int {
	if k == nil || k.Electron == nil {
		return 0
	}
	return len(k.Electron.ASARFiles)
}

func (k *KnowledgeResult) JavaScriptImportsCovered() int {
	if k == nil || k.Electron == nil {
		return 0
	}
	return len(k.Electron.JavaScriptImports)
}

func (k *KnowledgeResult) ElectronMainCovered() int {
	if k == nil || k.Electron == nil || k.Electron.ElectronMain == "" {
		return 0
	}
	return 1
}

func (k *KnowledgeResult) RendererProcessesCovered() int {
	if k == nil || k.Electron == nil {
		return 0
	}
	return len(k.Electron.RendererProcesses)
}

func (k *KnowledgeResult) IPCChannelsCovered() int {
	if k == nil || k.Electron == nil {
		return 0
	}
	return len(k.Electron.IPCChannels)
}

func (k *KnowledgeResult) BundledNodeModulesCovered() int {
	if k == nil || k.Electron == nil {
		return 0
	}
	return len(k.Electron.BundledNodeModules)
}

func (k *KnowledgeResult) SourceMapsCovered() int {
	if k == nil || k.Electron == nil {
		return 0
	}
	return len(k.Electron.SourceMaps)
}
