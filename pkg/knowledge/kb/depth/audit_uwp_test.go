/*
Copyright (c) 2026 Security Research
*/

package depth

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	"github.com/inovacc/unravel-oss/pkg/winui"
)

type mockUWPView struct {
	appxManifest    int
	capabilities    int
	xamlResources   int
	priResources    int
	dependencies    int
	signingChain    int
	localization    int
	winuiXAML       int
	winuiXBF        int
	winuiPRI        int
	winuiPEEmbedded int
	// P62 / DEPT-01: 4 methods added to UWPCoverageView post-P38 (extensions,
	// endpoints, source_files, signed_modules). TestAuditUWP_PartialCoverage
	// does not assert these dimensions, so zero stubs are correct (B4).
	extensions    int
	endpoints     int
	sourceFiles   int
	signedModules int
}

func (m mockUWPView) AppxManifestCovered() int    { return m.appxManifest }
func (m mockUWPView) CapabilitiesCovered() int    { return m.capabilities }
func (m mockUWPView) XAMLResourcesCovered() int   { return m.xamlResources }
func (m mockUWPView) PRIResourcesCovered() int    { return m.priResources }
func (m mockUWPView) DependenciesCovered() int    { return m.dependencies }
func (m mockUWPView) SigningChainCovered() int    { return m.signingChain }
func (m mockUWPView) LocalizationCovered() int    { return m.localization }
func (m mockUWPView) WinUIXAMLCovered() int       { return m.winuiXAML }
func (m mockUWPView) WinUIXBFCovered() int        { return m.winuiXBF }
func (m mockUWPView) WinUIPRICovered() int        { return m.winuiPRI }
func (m mockUWPView) WinUIPEEmbeddedCovered() int { return m.winuiPEEmbedded }
func (m mockUWPView) ExtensionsCovered() int      { return m.extensions }
func (m mockUWPView) EndpointsCovered() int       { return m.endpoints }
func (m mockUWPView) SourceFilesCovered() int     { return m.sourceFiles }
func (m mockUWPView) SignedModulesCovered() int   { return m.signedModules }

func TestAuditUWP_Empty(t *testing.T) {
	t.Run("nil_dissect_result", func(t *testing.T) {
		if got := AuditUWP(nil, mockUWPView{}); got != nil {
			t.Errorf("expected nil slice, got %v", got)
		}
	})
	t.Run("nil_view", func(t *testing.T) {
		if got := AuditUWP(&dissect.DissectResult{}, nil); got != nil {
			t.Errorf("expected nil slice, got %v", got)
		}
	})
	t.Run("both_nil", func(t *testing.T) {
		if got := AuditUWP(nil, nil); got != nil {
			t.Errorf("expected nil slice, got %v", got)
		}
	})
}

func TestAuditUWP_AllZero(t *testing.T) {
	got := AuditUWP(&dissect.DissectResult{}, mockUWPView{})
	// P62 / DEPT-01: 15 dimensions (was 11 pre-P38; +4 for extensions, endpoints,
	// source_files, signed_modules added to UWPCoverageView).
	if len(got) != 15 {
		t.Fatalf("expected 15 dimensions, got %d", len(got))
	}
	for _, d := range got {
		if d.Total != 0 || d.Covered != 0 || d.Ratio != 0 {
			t.Errorf("dim %q: covered=%d total=%d ratio=%v want all-zero",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
		if !RatioOK(d) {
			t.Errorf("dim %q failed RatioOK on absent (total=0)", d.Name)
		}
	}
}

func TestAuditUWP_PartialCoverage(t *testing.T) {
	dr := &dissect.DissectResult{
		MSIXInfo: &msix.InfoResult{
			PackageName:  "com.example.app",
			HasSignature: true,
			Capabilities: []string{"internetClient", "videosLibrary", "graphicsCapture"},
			Dependencies: []msix.Dependency{
				{Name: "Microsoft.VCLibs"},
				{Name: "Microsoft.NET.Native"},
			},
		},
		UWPInfo: &uwp.Result{
			IsUWP: true,
			Manifest: &uwp.ManifestSummary{
				PFN:            "com.example.app_8wekyb3d8bbwe",
				TargetFamilies: []string{"Windows.Desktop", "Windows.Mobile"},
				Capabilities: []uwp.CapabilityRef{
					{Name: "internetClient", Namespace: ""},
					{Name: "videosLibrary", Namespace: "uap"},
					{Name: "graphicsCapture", Namespace: "rescap"},
				},
			},
			XAMLIndex: &winui.XAMLIndex{
				Entries: []winui.XAMLEntry{
					{Path: "MainPage.xaml", Kind: "raw"},
					{Path: "App.xaml", Kind: "raw"},
					{Path: "resources.pri", Kind: "pri"},
				},
			},
		},
		WinUIInfo: &winui.Result{
			IsWinUI: true,
			XAMLIndex: &winui.XAMLIndex{
				Entries: []winui.XAMLEntry{
					{Path: "Page1.xaml", Kind: "raw"},
					{Path: "Page2.xaml", Kind: "raw"},
					{Path: "compiled.xbf", Kind: "xbf"},
					{Path: "embedded:RT_RCDATA/1", Kind: "pe-embedded"},
				},
			},
		},
	}

	view := mockUWPView{
		appxManifest:    1,
		capabilities:    2, // 2 of 3 capabilities propagated
		xamlResources:   3,
		priResources:    1,
		dependencies:    2,
		signingChain:    1,
		localization:    2,
		winuiXAML:       2,
		winuiXBF:        1,
		winuiPRI:        0,
		winuiPEEmbedded: 1,
	}

	got := AuditUWP(dr, view)
	// P62 / DEPT-01: 15 dimensions after UWPCoverageView added 4 methods
	// (extensions, endpoints, source_files, signed_modules) post-P38.
	if len(got) != 15 {
		t.Fatalf("expected 15 dimensions, got %d", len(got))
	}
	byName := map[string]Dimension{}
	for _, d := range got {
		byName[d.Name] = d
	}

	if d := byName["uwp.appxmanifest"]; d.Total != 1 || d.Covered != 1 || d.Ratio != 1.0 {
		t.Errorf("uwp.appxmanifest: %+v want covered=1 total=1 ratio=1.0", d)
	}
	if d := byName["uwp.capabilities"]; d.Total != 3 || d.Covered != 2 {
		t.Errorf("uwp.capabilities: %+v want covered=2 total=3", d)
	}
	if d := byName["uwp.dependencies"]; d.Total != 2 || d.Covered != 2 || d.Ratio != 1.0 {
		t.Errorf("uwp.dependencies: %+v want covered=2 total=2 ratio=1.0", d)
	}
	if d := byName["uwp.signing_chain"]; d.Total != 1 || d.Covered != 1 {
		t.Errorf("uwp.signing_chain: %+v want covered=1 total=1", d)
	}
	if d := byName["winui.xaml"]; d.Total != 2 || d.Covered != 2 || d.Ratio != 1.0 {
		t.Errorf("winui.xaml: %+v want covered=2 total=2", d)
	}
	if d := byName["winui.xbf"]; d.Total != 1 || d.Covered != 1 {
		t.Errorf("winui.xbf: %+v want covered=1 total=1", d)
	}
	if d := byName["winui.pe_embedded"]; d.Total != 1 || d.Covered != 1 {
		t.Errorf("winui.pe_embedded: %+v want covered=1 total=1", d)
	}
}

func TestAuditUWP_DimensionOrderStable(t *testing.T) {
	// Canonical order per audit_uwp.go:25-41. P62 / DEPT-01: 4 dimensions added
	// (uwp.extensions, uwp.endpoints, uwp.source_files, uwp.signed_modules)
	// between uwp.localization and winui.xaml — total now 15.
	canonical := []string{
		"uwp.appxmanifest",
		"uwp.capabilities",
		"uwp.xaml_resources",
		"uwp.pri_resources",
		"uwp.dependencies",
		"uwp.signing_chain",
		"uwp.localization",
		"uwp.extensions",
		"uwp.endpoints",
		"uwp.source_files",
		"uwp.signed_modules",
		"winui.xaml",
		"winui.xbf",
		"winui.pri",
		"winui.pe_embedded",
	}
	got := AuditUWP(&dissect.DissectResult{}, mockUWPView{})
	if len(got) != len(canonical) {
		t.Fatalf("expected %d dimensions, got %d", len(canonical), len(got))
	}
	for i, want := range canonical {
		if got[i].Name != want {
			t.Errorf("position %d: got %q want %q", i, got[i].Name, want)
		}
	}
	for _, d := range got {
		if !RatioOK(d) {
			t.Errorf("dim %q failed RatioOK; covered=%d total=%d ratio=%v",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
	}
}
