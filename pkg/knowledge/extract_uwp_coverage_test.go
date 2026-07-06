/*
Copyright (c) 2026 Security Research
*/

package knowledge

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/winui"
)

// helper: build a KR with windows platform and minimal MSIX signal so the
// gate inside extractUWPCoverage allows wiring.
func windowsKR() *KnowledgeResult {
	return &KnowledgeResult{Platform: "windows"}
}

func msixDR(name string, caps ...string) *dissect.DissectResult {
	return &dissect.DissectResult{
		MSIXInfo: &msix.InfoResult{
			PackageName:    name,
			PackageVersion: "1.0.0.0",
			Capabilities:   caps,
		},
	}
}

func uwpDR(caps []uwp.CapabilityRef, xaml []winui.XAMLEntry) *dissect.DissectResult {
	dr := &dissect.DissectResult{
		UWPInfo: &uwp.Result{
			IsUWP: true,
			Manifest: &uwp.ManifestSummary{
				PFN: "com.example_8wekyb3d8bbwe",
				Identity: uwp.IdentityInfo{
					Name:      "com.example",
					Publisher: "CN=Example",
					Version:   "1.0.0.0",
				},
				TargetFamilies: []string{"Windows.Desktop"},
				Capabilities:   caps,
			},
		},
	}
	if len(xaml) > 0 {
		dr.UWPInfo.XAMLIndex = &winui.XAMLIndex{Entries: xaml}
	}
	return dr
}

func TestExtractUWPCoverage_AppxManifest(t *testing.T) {
	dr := uwpDR(nil, nil)
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if kr.Packaging == nil || kr.Packaging.UWP == nil || kr.Packaging.UWP.AppxManifest == nil {
		t.Fatal("expected AppxManifest populated")
	}
	if kr.Packaging.UWP.AppxManifest.PFN == "" {
		t.Errorf("expected PFN populated")
	}
}

func TestExtractUWPCoverage_Capabilities(t *testing.T) {
	caps := []uwp.CapabilityRef{
		{Name: "internetClient", Namespace: ""},
		{Name: "videosLibrary", Namespace: "uap"},
		{Name: "graphicsCaptureWithoutBorder", Namespace: "rescap"},
	}
	dr := uwpDR(caps, nil)
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.Capabilities); got != 3 {
		t.Errorf("expected 3 capabilities, got %d", got)
	}
	// Risk score should be > 0 because rescap capability triggers auto-critical.
	if kr.Packaging.UWP.RiskScore == 0 {
		t.Errorf("expected non-zero RiskScore from pkg/uwp/risk delegation, got 0")
	}
}

func TestExtractUWPCoverage_XAMLResources(t *testing.T) {
	xaml := []winui.XAMLEntry{
		{Path: "MainPage.xaml", Kind: "raw"},
		{Path: "App.xaml", Kind: "raw"},
		{Path: "compiled.xbf", Kind: "xbf"},
	}
	dr := uwpDR(nil, xaml)
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.XAMLResources); got != 2 {
		t.Errorf("expected 2 raw XAML, got %d", got)
	}
}

func TestExtractUWPCoverage_PRIResources(t *testing.T) {
	xaml := []winui.XAMLEntry{
		{Path: "resources.pri", Kind: "pri"},
	}
	dr := uwpDR(nil, xaml)
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.PRIResources); got != 1 {
		t.Errorf("expected 1 PRI, got %d", got)
	}
}

func TestExtractUWPCoverage_Dependencies(t *testing.T) {
	dr := &dissect.DissectResult{
		MSIXInfo: &msix.InfoResult{
			PackageName: "com.example",
			Dependencies: []msix.Dependency{
				{Name: "Microsoft.VCLibs"},
				{Name: "Microsoft.NET.Native"},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.Dependencies); got != 2 {
		t.Errorf("expected 2 deps, got %d", got)
	}
}

func TestExtractUWPCoverage_SigningChain(t *testing.T) {
	dr := &dissect.DissectResult{
		MSIXInfo: &msix.InfoResult{
			PackageName:          "com.example",
			HasSignature:         true,
			PublisherDisplayName: "Example Publisher",
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.SigningChain); got < 1 {
		t.Errorf("expected at least 1 signing chain entry, got %d", got)
	}
}

func TestExtractUWPCoverage_Localization(t *testing.T) {
	dr := uwpDR(nil, nil) // TargetFamilies: Windows.Desktop
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.Localization); got != 1 {
		t.Errorf("expected 1 localization entry, got %d", got)
	}
}

func TestExtractUWPCoverage_WinUIXAML(t *testing.T) {
	dr := &dissect.DissectResult{
		WinUIInfo: &winui.Result{
			IsWinUI: true,
			XAMLIndex: &winui.XAMLIndex{
				Entries: []winui.XAMLEntry{
					{Path: "Page1.xaml", Kind: "raw"},
					{Path: "Page2.xaml", Kind: "raw"},
				},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.WinUIXAML); got != 2 {
		t.Errorf("expected 2 WinUI XAML, got %d", got)
	}
}

func TestExtractUWPCoverage_WinUIXBF(t *testing.T) {
	dr := &dissect.DissectResult{
		WinUIInfo: &winui.Result{
			IsWinUI: true,
			XAMLIndex: &winui.XAMLIndex{
				Entries: []winui.XAMLEntry{
					{Path: "compiled.xbf", Kind: "xbf"},
				},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.WinUIXBF); got != 1 {
		t.Errorf("expected 1 WinUI XBF, got %d", got)
	}
}

func TestExtractUWPCoverage_WinUIPRI(t *testing.T) {
	dr := &dissect.DissectResult{
		WinUIInfo: &winui.Result{
			IsWinUI: true,
			XAMLIndex: &winui.XAMLIndex{
				Entries: []winui.XAMLEntry{
					{Path: "resources.pri", Kind: "pri"},
				},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.WinUIPRI); got != 1 {
		t.Errorf("expected 1 WinUI PRI, got %d", got)
	}
}

func TestExtractUWPCoverage_WinUIPEEmbedded(t *testing.T) {
	dr := &dissect.DissectResult{
		WinUIInfo: &winui.Result{
			IsWinUI: true,
			XAMLIndex: &winui.XAMLIndex{
				Entries: []winui.XAMLEntry{
					{Path: "embedded:RT_RCDATA/1", Kind: "pe-embedded"},
					{Path: "embedded:RT_RCDATA/2", Kind: "pe-embedded-xbf"},
				},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if got := len(kr.Packaging.UWP.WinUIPEEmbedded); got != 2 {
		t.Errorf("expected 2 PE-embedded, got %d", got)
	}
}

func TestExtractUWPCoverage_WebView2(t *testing.T) {
	dr := &dissect.DissectResult{
		WebView2Info: &webview2.Result{
			IsWebView2: true,
			Runtime:    webview2.RuntimeInfo{Mode: "evergreen"},
			UDFs: []webview2.UDFInfo{
				{Path: "C:\\Users\\u\\AppData\\Local\\App\\EBWebView", Source: "default", Exists: true},
			},
			Profiles: []webview2.ProfileInfo{
				{Name: "Default", Path: "Default"},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if kr.WebView2 == nil {
		t.Fatal("expected WebView2 populated")
	}
	if kr.WebView2.UDFPath == "" {
		t.Errorf("expected UDFPath populated")
	}
	if len(kr.WebView2.UDFs) != 1 {
		t.Errorf("expected 1 UDF, got %d", len(kr.WebView2.UDFs))
	}
	if len(kr.WebView2.Profiles) != 1 {
		t.Errorf("expected 1 profile, got %d", len(kr.WebView2.Profiles))
	}
	if kr.WebView2.RuntimeMode != "evergreen" {
		t.Errorf("expected evergreen, got %q", kr.WebView2.RuntimeMode)
	}
}

func TestExtractUWPCoverage_NoOpOnNonWindowsPlatform(t *testing.T) {
	dr := uwpDR(nil, nil)
	kr := &KnowledgeResult{Platform: "android"}
	extractUWPCoverage(dr, kr)
	if kr.Packaging != nil && kr.Packaging.UWP != nil {
		t.Errorf("expected no UWP populated for android platform")
	}
	if kr.WebView2 != nil {
		t.Errorf("expected no WebView2 for android platform")
	}
}

func TestExtractUWPCoverage_NoOpOnNilSignal(t *testing.T) {
	dr := &dissect.DissectResult{} // no MSIX/UWP/WinUI/WebView2 signal
	kr := windowsKR()
	extractUWPCoverage(dr, kr)
	if kr.Packaging != nil && kr.Packaging.UWP != nil {
		t.Errorf("expected no UWP populated when no signal present")
	}
}

func TestExtractUWPCoverage_RatioOK_ViaAuditUWP(t *testing.T) {
	caps := []uwp.CapabilityRef{
		{Name: "internetClient", Namespace: ""},
		{Name: "videosLibrary", Namespace: "uap"},
	}
	xaml := []winui.XAMLEntry{
		{Path: "MainPage.xaml", Kind: "raw"},
		{Path: "resources.pri", Kind: "pri"},
	}
	dr := uwpDR(caps, xaml)
	dr.MSIXInfo = &msix.InfoResult{
		PackageName:  "com.example",
		HasSignature: true,
		Dependencies: []msix.Dependency{{Name: "Microsoft.VCLibs"}},
	}
	dr.WinUIInfo = &winui.Result{
		IsWinUI: true,
		XAMLIndex: &winui.XAMLIndex{
			Entries: []winui.XAMLEntry{
				{Path: "Page1.xaml", Kind: "raw"},
				{Path: "compiled.xbf", Kind: "xbf"},
				{Path: "embedded:1", Kind: "pe-embedded"},
			},
		},
	}
	kr := windowsKR()
	extractUWPCoverage(dr, kr)

	dims := depth.AuditUWP(dr, kr)
	// P62 / DEPT-01: 15 dimensions after UWPCoverageView added 4 methods
	// (extensions, endpoints, source_files, signed_modules) post-P38.
	if len(dims) != 15 {
		t.Fatalf("expected 15 dimensions, got %d", len(dims))
	}
	for _, d := range dims {
		if !depth.RatioOK(d) {
			t.Errorf("dim %q failed RatioOK: covered=%d total=%d ratio=%v",
				d.Name, d.Covered, d.Total, d.Ratio)
		}
	}
}

func TestExtractUWPCoverage_InterfaceCompliance_CompileTime(t *testing.T) {
	// Compile-time guarantee: KnowledgeResult satisfies both coverage views.
	var _ depth.UWPCoverageView = (*KnowledgeResult)(nil)
	var _ depth.WebView2CoverageView = (*KnowledgeResult)(nil)

	// Also exercise at runtime to ensure the methods return zero values
	// without panicking on a fresh KR.
	kr := &KnowledgeResult{}
	if kr.AppxManifestCovered() != 0 {
		t.Errorf("empty KR AppxManifestCovered should be 0")
	}
	if kr.UDFCovered() != 0 {
		t.Errorf("empty KR UDFCovered should be 0")
	}
}
