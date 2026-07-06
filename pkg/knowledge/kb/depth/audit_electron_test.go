/*
Copyright (c) 2026 Security Research
*/

package depth

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/asar"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/electron/app"
	"github.com/inovacc/unravel-oss/pkg/electron/ipc"
)

type mockElectronView struct {
	asarFiles   int
	jsImports   int
	main        int
	renderers   int
	ipcChannels int
	nodeModules int
	sourceMaps  int
}

func (m mockElectronView) ASARFilesCovered() int          { return m.asarFiles }
func (m mockElectronView) JavaScriptImportsCovered() int  { return m.jsImports }
func (m mockElectronView) ElectronMainCovered() int       { return m.main }
func (m mockElectronView) RendererProcessesCovered() int  { return m.renderers }
func (m mockElectronView) IPCChannelsCovered() int        { return m.ipcChannels }
func (m mockElectronView) BundledNodeModulesCovered() int { return m.nodeModules }
func (m mockElectronView) SourceMapsCovered() int         { return m.sourceMaps }

func TestAuditElectron_Empty(t *testing.T) {
	t.Run("nil_dissect_result", func(t *testing.T) {
		if got := AuditElectron(nil, mockElectronView{}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
	t.Run("nil_view", func(t *testing.T) {
		if got := AuditElectron(&dissect.DissectResult{}, nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestAuditElectron_AllZero(t *testing.T) {
	got := AuditElectron(&dissect.DissectResult{}, mockElectronView{})
	if len(got) != 7 {
		t.Fatalf("expected 7 dimensions, got %d", len(got))
	}
	for _, d := range got {
		if d.Total != 0 || d.Covered != 0 || d.Ratio != 0 {
			t.Errorf("dim %q: expected all zero, got %+v", d.Name, d)
		}
		if !RatioOK(d) {
			t.Errorf("dim %q failed RatioOK on absent", d.Name)
		}
	}
}

func TestAuditElectron_PartialCoverage(t *testing.T) {
	dr := &dissect.DissectResult{
		ASARFiles: []asar.ExtractedFile{
			{Path: "main.js"},
			{Path: "preload.js"},
			{Path: "index.html"},
			{Path: "node_modules/react/index.js"},
			{Path: "node_modules/electron/index.js"},
			{Path: "node_modules/lodash/index.js"},
		},
		AppAnalysis: &app.Result{
			AppInfo: app.AppInfoResult{Name: "TestApp"},
			Analysis: app.SecurityResult{
				IPCCommands: []ipc.Finding{
					{Channel: "test-channel-1"},
					{Channel: "test-channel-2"},
				},
			},
		},
	}

	view := mockElectronView{
		asarFiles:   6,
		jsImports:   0,
		main:        1,
		renderers:   2,
		ipcChannels: 2,
		nodeModules: 3,
		sourceMaps:  0,
	}

	got := AuditElectron(dr, view)
	if len(got) != 7 {
		t.Fatalf("expected 7 dimensions, got %d", len(got))
	}

	byName := map[string]Dimension{}
	for _, d := range got {
		byName[d.Name] = d
	}

	if d := byName["electron.asar_files"]; d.Total != 6 || d.Covered != 6 {
		t.Errorf("electron.asar_files: %+v want covered=6 total=6", d)
	}
	if d := byName["electron.electron_main"]; d.Total != 1 || d.Covered != 1 {
		t.Errorf("electron.electron_main: %+v want covered=1 total=1", d)
	}
	if d := byName["electron.renderer_processes"]; d.Total != 2 || d.Covered != 2 {
		t.Errorf("electron.renderer_processes: %+v want covered=2 total=2", d)
	}
	if d := byName["electron.ipc_channels"]; d.Total != 2 || d.Covered != 2 {
		t.Errorf("electron.ipc_channels: %+v want covered=2 total=2", d)
	}
	if d := byName["electron.bundled_node_modules"]; d.Total != 3 || d.Covered != 3 {
		t.Errorf("electron.bundled_node_modules: %+v want covered=3 total=3", d)
	}
}

func TestAuditElectron_DimensionOrderStable(t *testing.T) {
	canonical := []string{
		"electron.asar_files",
		"electron.javascript_imports",
		"electron.electron_main",
		"electron.renderer_processes",
		"electron.ipc_channels",
		"electron.bundled_node_modules",
		"electron.source_maps",
	}
	got := AuditElectron(&dissect.DissectResult{}, mockElectronView{})
	if len(got) != len(canonical) {
		t.Fatalf("expected %d, got %d", len(canonical), len(got))
	}
	for i, want := range canonical {
		if got[i].Name != want {
			t.Errorf("position %d: got %q want %q", i, got[i].Name, want)
		}
	}
	for _, d := range got {
		if !RatioOK(d) {
			t.Errorf("dim %q failed RatioOK", d.Name)
		}
	}
}
