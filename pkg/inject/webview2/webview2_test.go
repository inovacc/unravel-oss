/*
Copyright (c) 2026 Security Research
*/
package webview2

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// writeAppxManifestWithWebView2 writes a minimal AppxManifest.xml under dir
// whose Identity Name mentions "WebView2", which is one of the documented
// evidence sources for pkg/webview2/detect.DetectFromDirectory.
func writeAppxManifestWithWebView2(t *testing.T, dir string) {
	t.Helper()
	body := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Acme.WebView2.HostApp" Publisher="CN=Acme" Version="1.0.0.0"/>
  <Properties>
    <DisplayName>Acme WebView2 Host</DisplayName>
    <PublisherDisplayName>Acme</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
</Package>
`
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write AppxManifest.xml: %v", err)
	}
}

// copyFixture copies a testdata fixture into dir.
func copyFixture(t *testing.T, dir, name string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
}

// TestDetect_WebView2Loader_PE verifies Detect returns true when WebView2
// evidence is present. NOTE: a full PE-import fixture (binary that imports
// WebView2Loader.dll) would require fabricating a valid Windows PE on disk;
// instead this test exercises the AppxManifest evidence path which is the
// other documented WebView2 signal in pkg/webview2/detect.DetectFromDirectory.
// Coverage of the PE-import path itself lives in pkg/webview2/detect tests.
func TestDetect_WebView2Loader_PE(t *testing.T) {
	dir := t.TempDir()
	writeAppxManifestWithWebView2(t, dir)

	if !(scanner{}).Detect(dir) {
		t.Fatalf("Detect=false; want true (AppxManifest WebView2 evidence)")
	}
}

func TestDetect_NoSignals(t *testing.T) {
	dir := t.TempDir()
	if (scanner{}).Detect(dir) {
		t.Fatalf("Detect=true on empty dir; want false")
	}
}

// countSeamsByKind returns the number of seams matching kind k.
func countSeamsByKind(seams []inject.Seam, k string) int {
	n := 0
	for _, s := range seams {
		if s.Kind == k {
			n++
		}
	}
	return n
}

func TestScan_NativeAddScript(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "native_addscript.cpp")

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if got := countSeamsByKind(seams, kindAddScript); got != 1 {
		t.Fatalf("want 1 %s seam, got %d (%+v)", kindAddScript, got, seams)
	}
	for _, s := range seams {
		if s.Kind == kindAddScript && s.Confidence != inject.ConfidenceHigh {
			t.Errorf("want high confidence, got %q", s.Confidence)
		}
	}
}

func TestScan_ManagedAddScript(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "managed_addscript.cs")

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if got := countSeamsByKind(seams, kindAddScript); got != 1 {
		t.Fatalf("want 1 %s seam, got %d (%+v)", kindAddScript, got, seams)
	}
}

func TestScan_AdditionalBrowserArgs_RemoteDebugging(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "env_options_args.cs")

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if got := countSeamsByKind(seams, kindBrowserArgs); got != 1 {
		t.Fatalf("want 1 %s seam, got %d (%+v)", kindBrowserArgs, got, seams)
	}
	for _, s := range seams {
		if s.Kind == kindBrowserArgs && s.Confidence != inject.ConfidenceHigh {
			t.Errorf("want high confidence, got %q", s.Confidence)
		}
	}
}

func TestScan_WebMessageHandler(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "web_message_handler.cs")

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if got := countSeamsByKind(seams, kindWebMessage); got != 1 {
		t.Fatalf("want 1 %s seam, got %d (%+v)", kindWebMessage, got, seams)
	}
}

// TestScan_BinaryOnly_DefaultLowConfidence verifies that when no source files
// are found in appDir (e.g., a binary-only deployment), Scan emits exactly one
// low-confidence default-runtime seam. NOTE: A real PE that imports
// WebView2Loader.dll is not fabricated here (would require a hand-crafted
// Windows PE on disk); this test asserts the source-absent branch directly.
func TestScan_BinaryOnly_DefaultLowConfidence(t *testing.T) {
	dir := t.TempDir()
	// Drop a non-source file so the dir is non-empty but has no .cs/.cpp/.h/.hpp.
	if err := os.WriteFile(filepath.Join(dir, "app.exe"), []byte("not-a-real-pe"), 0o644); err != nil {
		t.Fatalf("write app.exe: %v", err)
	}

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if len(seams) != 1 {
		t.Fatalf("want 1 default-runtime seam, got %d (%+v)", len(seams), seams)
	}
	s := seams[0]
	if s.Kind != kindDefaultRuntime {
		t.Errorf("want kind %q, got %q", kindDefaultRuntime, s.Kind)
	}
	if s.Confidence != inject.ConfidenceLow {
		t.Errorf("want low confidence, got %q", s.Confidence)
	}
	if s.Framework != inject.FrameworkWebView2 {
		t.Errorf("want framework webview2, got %q", s.Framework)
	}
}

// TestDetect_AppxManifestOnly_ActivatesScanner — phase 18 (INJ-FOL-01).
// A directory with an AppxManifest declaring Microsoft.WebView2 dependency
// but no PE-imports activates the scanner now that Detect uses the composite
// pkg/webview2.Analyze signal (UDF + AppxManifest + PE-imports).
func TestDetect_AppxManifestOnly_ActivatesScanner(t *testing.T) {
	dir := t.TempDir()
	body := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Test.WebView2OnlyApp" Publisher="CN=Test" Version="1.0.0.0"/>
  <Dependencies>
    <PackageDependency Name="Microsoft.WebView2" MinVersion="1.0.0.0"/>
  </Dependencies>
</Package>
`
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), []byte(body), 0o644); err != nil {
		t.Fatalf("write AppxManifest: %v", err)
	}
	if !(scanner{}).Detect(dir) {
		t.Fatalf("Detect should activate on AppxManifest-only dir")
	}
}

// TestScan_VendorSourceWithoutPatterns_FallbackFires — phase 18 (INJ-FOL-01).
// Directory contains source files (.h, .cpp) that don't match any seam
// pattern. Phase 18 widens the fallback gate from `sourceFilesSeen == 0`
// to `len(seams) == 0`, so the default-runtime seam still emits when
// vendored headers are walked but nothing matches.
func TestScan_VendorSourceWithoutPatterns_FallbackFires(t *testing.T) {
	dir := t.TempDir()
	// Vendored-style header with no WebView2 patterns.
	if err := os.WriteFile(filepath.Join(dir, "vendor.h"), []byte("#pragma once\nint main(void);\n"), 0o644); err != nil {
		t.Fatalf("write vendor.h: %v", err)
	}
	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if len(seams) != 1 {
		t.Fatalf("want 1 fallback seam, got %d (%+v)", len(seams), seams)
	}
	if seams[0].Kind != kindDefaultRuntime {
		t.Errorf("want kind %q, got %q", kindDefaultRuntime, seams[0].Kind)
	}
}
