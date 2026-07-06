/*
Copyright (c) 2026 Security Research
*/

package webview2_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"
	"github.com/inovacc/unravel-oss/pkg/webview2/udf"
)

func TestAnalyzeTopLevel(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "Demo.exe")
	if err := os.WriteFile(exePath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	// Sibling .WebView2/EBWebView/Default/
	def := filepath.Join(tmp, "Demo.exe.WebView2", "EBWebView", "Default")
	if err := os.MkdirAll(def, 0o700); err != nil {
		t.Fatal(err)
	}

	res, err := webview2.Analyze(exePath, analyze.DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.IsWebView2 {
		t.Error("IsWebView2=true, want false (no PE check on this path)")
	}
	if len(res.UDFs) == 0 {
		t.Error("UDFs empty")
	}
	var hasDefault bool
	for _, p := range res.Profiles {
		if p.Name == "Default" {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("Default profile missing: %+v", res.Profiles)
	}
}

// TestResolveUWPCandidates_WhatsAppLayout exercises the BUG-01 fix path:
// %LOCALAPPDATA%\Packages\<PFN>\LocalCache\EBWebView (no vendor nesting).
func TestResolveUWPCandidates_WhatsAppLayout(t *testing.T) {
	lad := t.TempDir()
	t.Setenv("LOCALAPPDATA", lad)

	pfn := "5319275A.WhatsAppDesktop_cv1g1gvanyjgm"
	ebw := filepath.Join(lad, "Packages", pfn, "LocalCache", "EBWebView")
	if err := os.MkdirAll(ebw, 0o700); err != nil {
		t.Fatal(err)
	}

	// Synthesize a WindowsApps install path so the resolver detects UWP.
	winapps := t.TempDir()
	installDir := filepath.Join(winapps, "WindowsApps", pfn+"_2.2615.101.0_x64__cv1g1gvanyjgm")
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := udf.DiscoverUDFs(installDir)
	if err != nil {
		t.Fatalf("DiscoverUDFs: %v", err)
	}
	var hit bool
	for _, c := range got {
		if c.Source == "uwp-localcache" && c.Exists && c.Path == ebw {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("uwp-localcache candidate missing for WhatsApp layout: %+v", got)
	}
}

// TestResolveUWPCandidates_VendorNested verifies depth-3 walk catches
// LocalCache\Microsoft\MSTeams\EBWebView.
func TestResolveUWPCandidates_VendorNested(t *testing.T) {
	lad := t.TempDir()
	t.Setenv("LOCALAPPDATA", lad)

	pfn := "MSTeams_8wekyb3d8bbwe"
	ebw := filepath.Join(lad, "Packages", pfn, "LocalCache", "Microsoft", "MSTeams", "EBWebView")
	if err := os.MkdirAll(ebw, 0o700); err != nil {
		t.Fatal(err)
	}

	winapps := t.TempDir()
	installDir := filepath.Join(winapps, "WindowsApps", "MSTeams_26072.521.4595.7966_x64__8wekyb3d8bbwe")
	if err := os.MkdirAll(installDir, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := udf.DiscoverUDFs(installDir)
	if err != nil {
		t.Fatalf("DiscoverUDFs: %v", err)
	}
	var hit bool
	for _, c := range got {
		if c.Source == "uwp-localcache" && c.Exists && c.Path == ebw {
			hit = true
			break
		}
	}
	if !hit {
		t.Fatalf("vendor-nested uwp-localcache candidate missing: %+v", got)
	}
}

// TestUDFOverride_PrependedAndShortCircuits checks that when the override
// path exists, it is the only candidate returned (default resolution skipped).
func TestUDFOverride_PrependedAndShortCircuits(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())

	overrideDir := t.TempDir()
	got, err := udf.DiscoverUDFsWithOptions("C:/some/exe.exe", udf.DiscoverOptions{
		Override: overrideDir,
	})
	if err != nil {
		t.Fatalf("DiscoverUDFsWithOptions: %v", err)
	}
	if len(got) == 0 || got[0].Source != "override" {
		t.Fatalf("override not first or missing: %+v", got)
	}
	if !got[0].Exists {
		t.Fatalf("override exists=false but path was created: %+v", got[0])
	}
	if len(got) != 1 {
		t.Fatalf("override existed but default resolution not short-circuited: %+v", got)
	}
}

// TestUDFOverride_KeptWhenMissing verifies override remains in output even
// when the path doesn't exist on disk (D-02 surface-not-filter).
func TestUDFOverride_KeptWhenMissing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())

	missing := filepath.Join(t.TempDir(), "no-such-dir")
	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "Demo.exe")
	if err := os.WriteFile(exePath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := udf.DiscoverUDFsWithOptions(exePath, udf.DiscoverOptions{
		Override: missing,
	})
	if err != nil {
		t.Fatalf("DiscoverUDFsWithOptions: %v", err)
	}
	if len(got) == 0 || got[0].Source != "override" {
		t.Fatalf("override missing from output: %+v", got)
	}
	if got[0].Exists {
		t.Fatalf("override unexpectedly Exists=true: %+v", got[0])
	}
	// When override does NOT exist, default resolution still runs.
	if len(got) < 2 {
		t.Fatalf("default resolution unexpectedly short-circuited: %+v", got)
	}
}
