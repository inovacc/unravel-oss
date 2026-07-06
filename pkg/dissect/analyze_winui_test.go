/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/electron/binary"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	"github.com/inovacc/unravel-oss/pkg/winui"
)

const testManifestConfirmed = `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="X" Version="1.0.0.0" Publisher="CN=X"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/>
  </Dependencies>
</Package>`

func TestFrameworksFieldExists(t *testing.T) {
	rt := reflect.TypeFor[DissectResult]()
	f, ok := rt.FieldByName("Frameworks")
	if !ok {
		t.Fatal("DissectResult.Frameworks field missing")
	}
	want := reflect.TypeFor[[]winui.FrameworkInfo]()
	if f.Type != want {
		t.Errorf("Frameworks type = %v, want %v", f.Type, want)
	}
}

func TestWinUIAnalyzerRegistered(t *testing.T) {
	if !HasAnalyzer(detect.TypeWinUIApp) {
		t.Error("primary analyzer for TypeWinUIApp not registered")
	}
	supp := supplementalTable[detect.TypePE]
	if len(supp) == 0 {
		t.Error("supplemental analyzers for TypePE missing — analyzeWinUISupplemental should be registered")
	}
}

func TestUWPAnalyzerRegistered(t *testing.T) {
	if !HasAnalyzer(detect.TypeUWPApp) {
		t.Error("primary analyzer for TypeUWPApp not registered")
	}
	supp := supplementalTable[detect.TypeMSIX]
	if len(supp) == 0 {
		t.Error("supplemental analyzers for TypeMSIX missing — analyzeUWPSupplemental should be registered")
	}
}

func TestAnalyzeWinUI_DepsOnly(t *testing.T) {
	r := &DissectResult{
		DotnetDeps: &dotnet.DepsResult{
			PackageLibs: []dotnet.LibrarySummary{
				{Name: "Microsoft.WinUI", Version: "1.5.0", Type: "package"},
			},
		},
	}
	analyzeWinUI(r, "/nonexistent", Options{})
	if r.WinUIInfo == nil {
		t.Fatal("WinUIInfo nil")
	}
	if !r.WinUIInfo.IsWinUI {
		t.Error("IsWinUI should be true with WinUI 3 deps")
	}
	if len(r.Frameworks) == 0 {
		t.Fatal("r.Frameworks empty")
	}
	found := false
	for _, fi := range r.Frameworks {
		if fi.Name == "WinUI 3" && fi.Source == "dotnet-deps" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected WinUI 3 / dotnet-deps in r.Frameworks, got %+v", r.Frameworks)
	}
	if len(r.WinUIInfo.Errors) != 0 {
		t.Errorf("unexpected errors: %v", r.WinUIInfo.Errors)
	}
}

func TestAnalyzeWinUISupplemental_NoSignal(t *testing.T) {
	r := &DissectResult{
		BinaryInfo: &binary.Info{Imports: []string{"KERNEL32.dll", "USER32.dll"}},
	}
	analyzeWinUISupplemental(r, "/nonexistent", Options{})
	if r.WinUIInfo != nil {
		t.Errorf("WinUIInfo should remain nil with no MUX signal, got %+v", r.WinUIInfo)
	}
	for _, fi := range r.Frameworks {
		if fi.Name == "WinUI 3" {
			t.Errorf("unexpected WinUI 3 in Frameworks: %+v", fi)
		}
	}
}

func TestAnalyzeWinUISupplemental_PEImportPromotes(t *testing.T) {
	r := &DissectResult{
		BinaryInfo: &binary.Info{Imports: []string{"Microsoft.UI.Xaml.dll"}},
	}
	analyzeWinUISupplemental(r, "/nonexistent", Options{})
	if r.WinUIInfo == nil {
		t.Fatal("WinUIInfo nil after PE-import signal")
	}
	found := false
	for _, fi := range r.Frameworks {
		if fi.Name == "WinUI 3" && fi.Source == "pe-import" {
			found = true
			// Without deps corroboration, MUX should be demoted to medium.
			if fi.Confidence != "medium" {
				t.Errorf("MUX-only confidence = %q, want medium", fi.Confidence)
			}
		}
	}
	if !found {
		t.Errorf("WinUI 3 / pe-import missing from r.Frameworks: %+v", r.Frameworks)
	}
}

// writeAppxArchive constructs a synthetic .msix-like zip with AppxManifest.xml.
func writeAppxArchive(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "sample.msix")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("AppxManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	_ = zw.Close()
	_ = f.Close()
	return p
}

func TestAnalyzeUWP_ManifestPresent_Dir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), []byte(testManifestConfirmed), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &DissectResult{}
	analyzeUWP(r, dir, Options{})
	if r.UWPInfo == nil {
		t.Fatal("UWPInfo nil")
	}
	if !r.UWPInfo.IsUWP {
		t.Error("IsUWP should be true")
	}
	found := false
	for _, fi := range r.Frameworks {
		if fi.Name == "UWP" && fi.Source == "appx-manifest" && fi.Confidence == "confirmed" {
			found = true
		}
	}
	if !found {
		t.Errorf("UWP confirmed entry missing: %+v", r.Frameworks)
	}
}

func TestAnalyzeUWPSupplemental_Archive(t *testing.T) {
	p := writeAppxArchive(t, testManifestConfirmed)
	r := &DissectResult{}
	analyzeUWPSupplemental(r, p, Options{})
	if r.UWPInfo == nil {
		t.Fatal("UWPInfo nil after MSIX peek")
	}
	if !r.UWPInfo.IsUWP {
		t.Error("IsUWP should be true")
	}
}

func TestAnalyzeUWPSupplemental_SkipsWhenPrimaryRan(t *testing.T) {
	p := writeAppxArchive(t, testManifestConfirmed)
	preFrameworks := []winui.FrameworkInfo{{Name: "UWP", Source: "appx-manifest", Confidence: "confirmed"}}
	preInfo := &uwp.Result{IsUWP: true}
	r := &DissectResult{
		UWPInfo:    preInfo,
		Frameworks: preFrameworks,
	}
	analyzeUWPSupplemental(r, p, Options{})
	// Supplemental must not overwrite the existing UWPInfo, and must not
	// re-append duplicate Frameworks entries.
	if r.UWPInfo == nil || !r.UWPInfo.IsUWP {
		t.Error("supplemental wiped pre-existing UWPInfo")
	}
	if len(r.Frameworks) != len(preFrameworks) {
		t.Errorf("Frameworks mutated by supplemental: %v", r.Frameworks)
	}
}

func TestHybridFrameworks(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), []byte(testManifestConfirmed), 0o600); err != nil {
		t.Fatal(err)
	}
	// Simulate full upstream context: deps.json says WinUI 3, PE imports
	// include WebView2Loader.dll, AppxManifest declares uap+Universal.
	r := &DissectResult{
		DotnetDeps: &dotnet.DepsResult{
			PackageLibs: []dotnet.LibrarySummary{
				{Name: "Microsoft.WinUI", Version: "1.5.0", Type: "package"},
			},
		},
		BinaryInfo: &binary.Info{
			Imports: []string{"WebView2Loader.dll", "Microsoft.UI.Xaml.dll"},
		},
	}
	// Run WinUI primary (would be selected when TypeWinUIApp is detected)...
	analyzeWinUI(r, dir, Options{})
	// ...and UWP primary on the directory.
	analyzeUWP(r, dir, Options{})

	// Expect at least 3 distinct (Name, Source) entries:
	//   {WinUI 3, dotnet-deps}, {WinUI 3, pe-import}, {UWP, appx-manifest}.
	got := map[string]bool{}
	for _, fi := range r.Frameworks {
		got[fi.Name+"|"+fi.Source] = true
	}
	for _, want := range []string{"WinUI 3|dotnet-deps", "WinUI 3|pe-import", "UWP|appx-manifest"} {
		if !got[want] {
			t.Errorf("missing %q in Frameworks: %+v", want, r.Frameworks)
		}
	}
	if len(got) < 3 {
		t.Errorf("FRM-09 acceptance: want >=3 distinct entries, got %d (%v)", len(got), got)
	}
}

// TestDissectMSIX_FullPipeline (plan 05): a synthetic .msix archive
// passed to analyzeUWP exercises the full pipeline (extract + manifest
// + score + XAML walk + DPAPI flag) and populates r.UWPInfo with
// non-trivial fields.
func TestDissectMSIX_FullPipeline(t *testing.T) {
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<Package
  xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Demo" Version="1.0.0.0" Publisher="CN=Demo"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/>
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient"/>
  </Capabilities>
</Package>`
	p := writeAppxArchive(t, manifest)
	r := &DissectResult{}
	analyzeUWP(r, p, Options{})
	if r.UWPInfo == nil {
		t.Fatal("UWPInfo nil after full pipeline")
	}
	if !r.UWPInfo.IsUWP {
		t.Error("IsUWP should be true")
	}
	if r.UWPInfo.Manifest == nil {
		t.Error("Manifest summary missing — full pipeline should populate it")
	}
	if r.UWPInfo.Score == nil {
		t.Error("Score missing — full pipeline should compute capability score")
	}
	gotUWP := false
	for _, fi := range r.Frameworks {
		if fi.Name == "UWP" {
			gotUWP = true
		}
	}
	if !gotUWP {
		t.Errorf("UWP framework entry missing from r.Frameworks: %+v", r.Frameworks)
	}
}

// TestDissectWinUI_HybridPE (plan 05 / FRM-09 final acceptance): a
// synthetic input simulating a hybrid stack — deps.json declares
// WinUI 3, BinaryInfo lists both Microsoft.UI.Xaml.dll AND
// WebView2Loader.dll. Layered detection must yield framework entries
// for both WinUI 3 (pe-import) AND WinUI 3 (dotnet-deps).
func TestDissectWinUI_HybridPE(t *testing.T) {
	r := &DissectResult{
		DotnetDeps: &dotnet.DepsResult{
			PackageLibs: []dotnet.LibrarySummary{
				{Name: "Microsoft.WinUI", Version: "1.5.0", Type: "package"},
			},
		},
		BinaryInfo: &binary.Info{
			Imports: []string{"WebView2Loader.dll", "Microsoft.UI.Xaml.dll"},
		},
	}
	analyzeWinUI(r, "/nonexistent", Options{})
	if r.WinUIInfo == nil {
		t.Fatal("WinUIInfo nil")
	}
	wantSources := map[string]bool{
		"WinUI 3|dotnet-deps": false,
		"WinUI 3|pe-import":   false,
	}
	for _, fi := range r.Frameworks {
		key := fi.Name + "|" + fi.Source
		if _, want := wantSources[key]; want {
			wantSources[key] = true
		}
	}
	for k, hit := range wantSources {
		if !hit {
			t.Errorf("expected %q in r.Frameworks: got %+v", k, r.Frameworks)
		}
	}
}

func TestFrameworksDedup_KeyedByNameAndSource(t *testing.T) {
	base := []winui.FrameworkInfo{
		{Name: "WinUI 3", Source: "dotnet-deps", Confidence: "high"},
	}
	add := []winui.FrameworkInfo{
		{Name: "WinUI 3", Source: "dotnet-deps", Confidence: "high"}, // dup
		{Name: "WinUI 3", Source: "pe-import", Confidence: "medium"}, // distinct source
	}
	got := mergeFrameworksDedup(base, add)
	if len(got) != 2 {
		t.Errorf("dedup len = %d, want 2 (Name=Same, Source=Different must be retained)", len(got))
	}
}
