/*
Copyright (c) 2026 Security Research
*/

package knowledge

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/ipc"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/sourcemap"
	"github.com/inovacc/unravel-oss/pkg/uwp"
)

func electronDR(files []asar.ExtractedFile) *dissect.DissectResult {
	return &dissect.DissectResult{
		ASARFiles: files,
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{Type: "electron", Name: "TestApp"},
		},
	}
}

func TestExtractElectronCoverage_ASARFiles(t *testing.T) {
	dr := electronDR([]asar.ExtractedFile{
		{Path: "main.js", Size: 100},
		{Path: "package.json", Size: 50},
		{Path: "node_modules/react/index.js", Size: 200},
	})
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if kr.Electron == nil {
		t.Fatal("expected Electron populated")
	}
	if got := len(kr.Electron.ASARFiles); got != 3 {
		t.Errorf("expected 3 ASAR files, got %d", got)
	}
}

func TestExtractElectronCoverage_JavaScriptImports(t *testing.T) {
	dr := electronDR(nil)
	dr.JSAnalysis = &dissect.JSAnalysisResult{
		Indicators: []string{"react", "electron", "ipcRenderer"},
	}
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if got := len(kr.Electron.JavaScriptImports); got != 3 {
		t.Errorf("expected 3 JS imports, got %d", got)
	}
}

func TestExtractElectronCoverage_ElectronMain(t *testing.T) {
	dr := electronDR([]asar.ExtractedFile{
		{Path: "main.js"},
		{Path: "renderer.js"},
	})
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if kr.Electron.ElectronMain != "main.js" {
		t.Errorf("expected ElectronMain=main.js, got %q", kr.Electron.ElectronMain)
	}
}

func TestExtractElectronCoverage_RendererProcesses(t *testing.T) {
	dr := electronDR([]asar.ExtractedFile{
		{Path: "preload.js"},
		{Path: "preload-main.js"},
		{Path: "index.html"},
		{Path: "main.js"},
	})
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if got := len(kr.Electron.RendererProcesses); got != 3 {
		t.Errorf("expected 3 renderer processes, got %d", got)
	}
}

func TestExtractElectronCoverage_IPCChannels(t *testing.T) {
	dr := electronDR(nil)
	dr.AppAnalysis.Analysis = app.SecurityResult{
		IPCCommands: []ipc.Finding{
			{Channel: "test-ch-1", Direction: "main->renderer", Risk: "low"},
			{Channel: "test-ch-2", Direction: "renderer->main", Risk: "high"},
		},
	}
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if got := len(kr.Electron.IPCChannels); got != 2 {
		t.Errorf("expected 2 IPC channels, got %d", got)
	}
	if kr.Electron.IPCChannels[1].Risk != "high" {
		t.Errorf("expected risk=high for second channel")
	}
}

func TestExtractElectronCoverage_BundledNodeModules(t *testing.T) {
	dr := electronDR([]asar.ExtractedFile{
		{Path: "node_modules/react/index.js"},
		{Path: "node_modules/react/lib/foo.js"},
		{Path: "node_modules/lodash/index.js"},
		{Path: "node_modules/electron/index.js"},
		{Path: "main.js"},
	})
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if got := len(kr.Electron.BundledNodeModules); got != 3 {
		t.Errorf("expected 3 unique node modules, got %d (%v)", got, kr.Electron.BundledNodeModules)
	}
}

func TestExtractElectronCoverage_SourceMaps(t *testing.T) {
	dr := electronDR([]asar.ExtractedFile{{Path: "main.js"}})
	dr.SourceMapInfo = &sourcemap.ParseResult{File: "main.js.map"}
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if got := len(kr.Electron.SourceMaps); got != 1 {
		t.Errorf("expected 1 source map, got %d", got)
	}
}

func TestExtractElectronCoverage_NoOpOnNoElectronSignal(t *testing.T) {
	dr := &dissect.DissectResult{} // no ASAR, no AppAnalysis
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)
	if kr.Electron != nil {
		t.Errorf("expected Electron nil when no signal present")
	}
}

func TestExtractElectronCoverage_HybridStack_PopulatesBothPaths(t *testing.T) {
	// Hybrid: MSIX wrapper + Electron payload (Microsoft Teams shape).
	dr := &dissect.DissectResult{
		MSIXInfo: &msix.InfoResult{
			PackageName:  "MSTeams_8wekyb3d8bbwe",
			HasSignature: true,
			Capabilities: []string{"internetClient"},
			Dependencies: []msix.Dependency{{Name: "Microsoft.VCLibs"}},
		},
		UWPInfo: &uwp.Result{
			IsUWP: true,
			Manifest: &uwp.ManifestSummary{
				PFN:            "MSTeams_8wekyb3d8bbwe",
				Identity:       uwp.IdentityInfo{Name: "MSTeams"},
				TargetFamilies: []string{"Windows.Desktop"},
				Capabilities: []uwp.CapabilityRef{
					{Name: "internetClient", Namespace: ""},
				},
			},
		},
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{Type: "electron", Name: "Teams"},
			Analysis: app.SecurityResult{
				IPCCommands: []ipc.Finding{{Channel: "teams-ipc"}},
			},
		},
		ASARFiles: []asar.ExtractedFile{
			{Path: "main.js"},
			{Path: "preload.js"},
			{Path: "node_modules/react/index.js"},
		},
	}
	kr := &KnowledgeResult{Platform: "windows"}

	extractUWPCoverage(dr, kr)
	extractElectronCoverage(dr, kr)

	if kr.Packaging == nil || kr.Packaging.UWP == nil {
		t.Fatal("hybrid: expected Packaging.UWP populated")
	}
	if kr.Electron == nil {
		t.Fatal("hybrid: expected Electron populated")
	}

	// Both audits should produce dimensions.
	uwpDims := depth.AuditUWP(dr, kr)
	electronDims := depth.AuditElectron(dr, kr)
	if len(uwpDims) == 0 {
		t.Errorf("hybrid: AuditUWP returned no dimensions")
	}
	if len(electronDims) == 0 {
		t.Errorf("hybrid: AuditElectron returned no dimensions")
	}

	// Append both into a single DepthCovered slice (mirror Extract() shape)
	// and assert BOTH prefixes present per D-38-HYBRID-DUAL-COVERAGE.
	all := append(uwpDims, electronDims...)
	hasUWP, hasElectron := false, false
	for _, d := range all {
		if strings.HasPrefix(d.Name, "uwp.") || strings.HasPrefix(d.Name, "winui.") {
			hasUWP = true
		}
		if strings.HasPrefix(d.Name, "electron.") {
			hasElectron = true
		}
	}
	if !hasUWP {
		t.Errorf("hybrid: expected uwp.* dimension present")
	}
	if !hasElectron {
		t.Errorf("hybrid: expected electron.* dimension present")
	}
}

func TestExtractElectronCoverage_RatioOK_ViaAuditElectron(t *testing.T) {
	dr := &dissect.DissectResult{
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{Type: "electron", Name: "TestApp"},
			Analysis: app.SecurityResult{
				IPCCommands: []ipc.Finding{{Channel: "ch1"}, {Channel: "ch2"}},
			},
		},
		ASARFiles: []asar.ExtractedFile{
			{Path: "main.js"},
			{Path: "preload.js"},
			{Path: "index.html"},
			{Path: "node_modules/react/index.js"},
			{Path: "node_modules/lodash/index.js"},
		},
		JSAnalysis: &dissect.JSAnalysisResult{
			Indicators: []string{"react", "electron"},
		},
	}
	kr := &KnowledgeResult{}
	extractElectronCoverage(dr, kr)

	dims := depth.AuditElectron(dr, kr)
	if len(dims) != 7 {
		t.Fatalf("expected 7 dimensions, got %d", len(dims))
	}
	for _, d := range dims {
		if !depth.RatioOK(d) {
			t.Errorf("dim %q failed RatioOK: covered=%d total=%d ratio=%v",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
	}
}

func TestExtractElectronCoverage_InterfaceCompliance_CompileTime(t *testing.T) {
	var _ depth.ElectronCoverageView = (*KnowledgeResult)(nil)
	kr := &KnowledgeResult{}
	if kr.ASARFilesCovered() != 0 {
		t.Errorf("empty KR ASARFilesCovered should be 0")
	}
	if kr.IPCChannelsCovered() != 0 {
		t.Errorf("empty KR IPCChannelsCovered should be 0")
	}
}
