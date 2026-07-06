/*
Copyright (c) 2026 Security Research
*/
package msix

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// createTestMSIX creates a minimal MSIX package for testing.
func createTestMSIX(t *testing.T, dir string, manifest string, includeSignature bool) string {
	t.Helper()

	path := filepath.Join(dir, "test.msix")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	// AppxManifest.xml
	fw, err := w.Create("AppxManifest.xml")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fw.Write([]byte(manifest))

	// [Content_Types].xml
	fw, err = w.Create("[Content_Types].xml")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fw.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>`))

	// AppxBlockMap.xml
	fw, err = w.Create("AppxBlockMap.xml")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fw.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap"></BlockMap>`))

	if includeSignature {
		fw, err = w.Create("AppxSignature.p7x")
		if err != nil {
			t.Fatal(err)
		}

		_, _ = fw.Write([]byte("fake-signature"))
	}

	// A payload file
	fw, err = w.Create("app.exe")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fw.Write([]byte("MZ-fake-binary"))

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

const testManifest = `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="TestApp" Version="1.2.3.0" Publisher="CN=Test Publisher" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>Test Application</DisplayName>
    <Description>A test MSIX package</Description>
    <PublisherDisplayName>Test Publisher Inc</PublisherDisplayName>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient"/>
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication"/>
  </Applications>
</Package>`

func TestIsMSIX(t *testing.T) {
	dir := t.TempDir()

	t.Run("valid msix", func(t *testing.T) {
		path := createTestMSIX(t, dir, testManifest, false)
		if !IsMSIX(path) {
			t.Error("expected IsMSIX to return true")
		}
	})

	t.Run("not msix", func(t *testing.T) {
		path := filepath.Join(dir, "notmsix.zip")

		f, _ := os.Create(path)
		w := zip.NewWriter(f)

		fw, _ := w.Create("readme.txt")
		_, _ = fw.Write([]byte("hello"))
		_ = w.Close()
		_ = f.Close()

		if IsMSIX(path) {
			t.Error("expected IsMSIX to return false for plain zip")
		}
	})

	t.Run("not a file", func(t *testing.T) {
		if IsMSIX("/nonexistent/path") {
			t.Error("expected IsMSIX to return false for nonexistent file")
		}
	})
}

func TestInfo(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, true)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	tests := []struct {
		name string
		got  string
		want string
	}{
		{"package name", info.PackageName, "TestApp"},
		{"version", info.PackageVersion, "1.2.3.0"},
		{"publisher", info.Publisher, "CN=Test Publisher"},
		{"architecture", info.ProcessorArchitecture, "x64"},
		{"display name", info.DisplayName, "Test Application"},
		{"description", info.Description, "A test MSIX package"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}

	if !info.HasSignature {
		t.Error("expected HasSignature to be true")
	}

	if !info.HasBlockMap {
		t.Error("expected HasBlockMap to be true")
	}

	if !info.HasContentTypes {
		t.Error("expected HasContentTypes to be true")
	}

	if len(info.Applications) != 1 {
		t.Fatalf("expected 1 application, got %d", len(info.Applications))
	}

	if info.Applications[0].Executable != "app.exe" {
		t.Errorf("expected executable app.exe, got %s", info.Applications[0].Executable)
	}

	if len(info.Dependencies) != 1 {
		t.Fatalf("expected 1 dependency, got %d", len(info.Dependencies))
	}

	if info.Dependencies[0].Name != "Windows.Desktop" {
		t.Errorf("expected dependency Windows.Desktop, got %s", info.Dependencies[0].Name)
	}

	if len(info.Capabilities) < 1 {
		t.Error("expected at least 1 capability")
	}
}

// TestInfoStampsManifestPath asserts that Info() (zip walker) populates
// InfoResult.ManifestPath with a non-empty value ending in "AppxManifest.xml".
// For zip input the stamp is the package-relative entry name (the canonical
// reference for files inside the package). Mirrors the install-dir stamp in
// dir.go::InfoFromDir which uses the absolute on-disk path.
//
// Phase 64-00b — added to give SCRG-05 (behavior) a typed-field Citation
// source so r.MSIXInfo.ManifestPath can replace generic r.SourcePath.
func TestInfoStampsManifestPath(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, false)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.ManifestPath == "" {
		t.Fatal("expected ManifestPath to be populated, got empty string")
	}
	if !strings.HasSuffix(info.ManifestPath, "AppxManifest.xml") {
		t.Errorf("expected ManifestPath to end with 'AppxManifest.xml', got %q", info.ManifestPath)
	}
}

// TestInfoFromDirStampsManifestPath asserts that InfoFromDir (install-dir
// walker in dir.go) populates ManifestPath with the absolute on-disk path to
// AppxManifest.xml. This is the load-bearing case for SCRG-05 — UWP install-dir
// inputs use this code path.
func TestInfoFromDirStampsManifestPath(t *testing.T) {
	dir := t.TempDir()

	// Lay out a minimal install-dir layout: <dir>/AppxManifest.xml.
	manifestPath := filepath.Join(dir, "AppxManifest.xml")
	if err := os.WriteFile(manifestPath, []byte(testManifest), 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := InfoFromDir(dir)
	if err != nil {
		t.Fatalf("InfoFromDir() error: %v", err)
	}

	if info.ManifestPath == "" {
		t.Fatal("expected ManifestPath to be populated, got empty string")
	}
	if !strings.HasSuffix(info.ManifestPath, "AppxManifest.xml") {
		t.Errorf("expected ManifestPath to end with 'AppxManifest.xml', got %q", info.ManifestPath)
	}
	// For dir-mode the stamp must be the absolute on-disk path so callers
	// (SCRG-05) can use it directly as Citation.File.
	if info.ManifestPath != manifestPath {
		t.Errorf("expected ManifestPath=%q, got %q", manifestPath, info.ManifestPath)
	}
}

func TestInfoError(t *testing.T) {
	_, err := Info("/nonexistent/file.msix")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtract(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, true)
	outDir := filepath.Join(dir, "extracted")

	report, err := Extract(path, outDir)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if report.Files == 0 {
		t.Error("expected files to be extracted")
	}

	// Check that AppxManifest.xml was extracted
	if _, err := os.Stat(filepath.Join(outDir, "AppxManifest.xml")); err != nil {
		t.Error("expected AppxManifest.xml to be extracted")
	}
}

func TestExtractDefaultDir(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, false)

	report, err := Extract(path, "")
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if report.Output != "test_extracted" {
		t.Errorf("expected default output dir 'test_extracted', got %q", report.Output)
	}

	// Clean up
	_ = os.RemoveAll(report.Output)
}

func TestVerify(t *testing.T) {
	dir := t.TempDir()

	t.Run("signed", func(t *testing.T) {
		path := createTestMSIX(t, dir, testManifest, true)

		result, err := Verify(path)
		if err != nil {
			t.Fatalf("Verify() error: %v", err)
		}

		if !result.HasSignature {
			t.Error("expected HasSignature true")
		}

		if !result.HasBlockMap {
			t.Error("expected HasBlockMap true")
		}
	})

	t.Run("unsigned", func(t *testing.T) {
		unsigned := filepath.Join(dir, "unsigned")
		_ = os.MkdirAll(unsigned, 0o755)

		path := createTestMSIX(t, unsigned, testManifest, false)

		result, err := Verify(path)
		if err != nil {
			t.Fatalf("Verify() error: %v", err)
		}

		if result.HasSignature {
			t.Error("expected HasSignature false")
		}
	})
}

func TestExtractError(t *testing.T) {
	_, err := Extract("/nonexistent/file.msix", "")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestExtractWithDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "withdir.msix")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	// Create a directory entry
	_, err = w.Create("assets/")
	if err != nil {
		t.Fatal(err)
	}

	// File inside directory
	fw, err := w.Create("assets/icon.png")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fw.Write([]byte("fake-png"))

	// AppxManifest.xml (required)
	fw, err = w.Create("AppxManifest.xml")
	if err != nil {
		t.Fatal(err)
	}

	_, _ = fw.Write([]byte(testManifest))

	_ = w.Close()
	_ = f.Close()

	outDir := filepath.Join(dir, "extracted_dirs")

	report, err := Extract(path, outDir)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if report.Directories == 0 {
		t.Error("expected at least one directory to be counted")
	}

	if report.Files < 2 {
		t.Errorf("expected at least 2 files, got %d", report.Files)
	}

	// Check nested file was extracted
	if _, err := os.Stat(filepath.Join(outDir, "assets", "icon.png")); err != nil {
		t.Error("expected assets/icon.png to be extracted")
	}
}

func TestExtractTotalSize(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, true)
	outDir := filepath.Join(dir, "extracted_size")

	report, err := Extract(path, outDir)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if report.TotalSize == 0 {
		t.Error("expected TotalSize > 0")
	}

	if len(report.Errors) != 0 {
		t.Errorf("expected no errors, got %v", report.Errors)
	}
}

func TestInfoNoSignature(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, false)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.HasSignature {
		t.Error("expected HasSignature to be false")
	}

	if info.FileCount == 0 {
		t.Error("expected FileCount > 0")
	}

	if info.TotalSize == 0 {
		t.Error("expected TotalSize > 0")
	}
}

func TestInfoMinimalManifest(t *testing.T) {
	dir := t.TempDir()

	minimal := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="MinimalApp" Version="0.1.0.0" Publisher="CN=Min"/>
</Package>`

	path := createTestMSIX(t, dir, minimal, false)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.PackageName != "MinimalApp" {
		t.Errorf("expected MinimalApp, got %q", info.PackageName)
	}

	if info.DisplayName != "" {
		t.Errorf("expected empty DisplayName, got %q", info.DisplayName)
	}

	if len(info.Applications) != 0 {
		t.Errorf("expected 0 applications, got %d", len(info.Applications))
	}

	if len(info.Dependencies) != 0 {
		t.Errorf("expected 0 dependencies, got %d", len(info.Dependencies))
	}

	if len(info.Capabilities) != 0 {
		t.Errorf("expected 0 capabilities, got %d", len(info.Capabilities))
	}
}

func TestInfoMultipleDependencies(t *testing.T) {
	dir := t.TempDir()

	manifest := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="MultiDep" Version="2.0.0.0" Publisher="CN=Test"/>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.16299.0" MaxVersionTested="10.0.19041.0"/>
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient"/>
    <Capability Name="privateNetworkClientServer"/>
  </Capabilities>
  <Applications>
    <Application Id="App1" Executable="app1.exe" EntryPoint="Windows.FullTrustApplication"/>
    <Application Id="App2" Executable="app2.exe" EntryPoint="Windows.FullTrustApplication"/>
  </Applications>
</Package>`

	path := createTestMSIX(t, dir, manifest, false)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if len(info.Dependencies) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(info.Dependencies))
	}

	// MinOSVersion should be the lowest
	if info.MinOSVersion != "10.0.16299.0" {
		t.Errorf("expected MinOSVersion 10.0.16299.0, got %q", info.MinOSVersion)
	}

	if len(info.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(info.Capabilities))
	}

	if len(info.Applications) != 2 {
		t.Errorf("expected 2 applications, got %d", len(info.Applications))
	}
}

func TestInfoInvalidZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.msix")

	_ = os.WriteFile(path, []byte("not a zip file"), 0o644)

	_, err := Info(path)
	if err == nil {
		t.Error("expected error for invalid zip")
	}
}

func TestVerifyError(t *testing.T) {
	_, err := Verify("/nonexistent/file.msix")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestVerifyInvalidZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.msix")

	_ = os.WriteFile(path, []byte("not a zip"), 0o644)

	_, err := Verify(path)
	if err == nil {
		t.Error("expected error for invalid zip")
	}
}

func TestInfoPublisherDisplayName(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, false)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.PublisherDisplayName != "Test Publisher Inc" {
		t.Errorf("expected 'Test Publisher Inc', got %q", info.PublisherDisplayName)
	}
}

func TestInfoFileList(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, true)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// Should have: AppxManifest.xml, [Content_Types].xml, AppxBlockMap.xml, AppxSignature.p7x, app.exe
	if info.FileCount != 5 {
		t.Errorf("expected 5 files, got %d", info.FileCount)
	}

	// Verify file names are captured
	names := make(map[string]bool)
	for _, f := range info.Files {
		names[f.Name] = true
	}

	for _, expected := range []string{"AppxManifest.xml", "app.exe", "AppxSignature.p7x"} {
		if !names[expected] {
			t.Errorf("expected file %q in file list", expected)
		}
	}
}

func TestInfoRestrictedCapabilities(t *testing.T) {
	dir := t.TempDir()

	manifest := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="RestrictedApp" Version="1.0.0.0" Publisher="CN=Test"/>
  <Capabilities>
    <Capability Name="internetClient"/>
    <rescap:Capability Name="runFullTrust"/>
    <rescap:Capability Name="allowElevation"/>
  </Capabilities>
</Package>`

	path := createTestMSIX(t, dir, manifest, false)

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// All capabilities (normal + restricted namespace) should be captured
	if len(info.Capabilities) < 1 {
		t.Errorf("expected at least 1 capability, got %d: %v", len(info.Capabilities), info.Capabilities)
	}

	hasRunFullTrust := false
	for _, c := range info.Capabilities {
		if c == "runFullTrust" || c == "restricted:runFullTrust" {
			hasRunFullTrust = true
		}
	}

	if !hasRunFullTrust {
		t.Errorf("expected runFullTrust in capabilities: %v", info.Capabilities)
	}
}

func TestInfoInvalidManifestXML(t *testing.T) {
	dir := t.TempDir()

	// Invalid XML that will fail xml.Unmarshal
	badManifest := `<?xml version="1.0"?><Package><Identity Name="Bad"<broken`

	path := createTestMSIX(t, dir, badManifest, false)

	_, err := Info(path)
	if err == nil {
		t.Error("expected error for invalid manifest XML")
	}
}

func TestInfoWithDirectoryEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "withdir.msix")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	// Directory entry (trailing slash)
	_, _ = w.Create("assets/")

	// Manifest
	fw, _ := w.Create("AppxManifest.xml")
	_, _ = fw.Write([]byte(testManifest))

	// File
	fw, _ = w.Create("assets/data.bin")
	_, _ = fw.Write([]byte("data"))

	_ = w.Close()
	_ = f.Close()

	info, err := Info(path)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// Directory entries should be skipped in file count
	// Only AppxManifest.xml and assets/data.bin should be counted
	if info.FileCount != 2 {
		t.Errorf("expected 2 files (dirs skipped), got %d", info.FileCount)
	}
}

func TestExtractPathTraversal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traversal.msix")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	// Normal manifest
	fw, _ := w.Create("AppxManifest.xml")
	_, _ = fw.Write([]byte(testManifest))

	// Path traversal attempt
	fw, _ = w.Create("../../../etc/passwd")
	_, _ = fw.Write([]byte("root:x:0:0"))

	_ = w.Close()
	_ = f.Close()

	outDir := filepath.Join(dir, "safe_extract")

	report, err := Extract(path, outDir)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if len(report.Errors) == 0 {
		t.Error("expected path traversal error in report")
	}

	// The traversal file should NOT exist outside the output dir
	if _, err := os.Stat(filepath.Join(dir, "etc", "passwd")); err == nil {
		t.Error("path traversal was not prevented")
	}
}

func TestExtractReadOnlyTarget(t *testing.T) {
	dir := t.TempDir()
	path := createTestMSIX(t, dir, testManifest, false)

	// Use a path that can't be created (file exists where dir needed)
	blocker := filepath.Join(dir, "blocker")
	_ = os.WriteFile(blocker, []byte("x"), 0o444)

	outDir := filepath.Join(blocker, "subdir")

	_, err := Extract(path, outDir)
	// On Windows MkdirAll through a file fails; on any OS this should error or report errors
	if err != nil {
		return // error at top level is fine
	}
}

func TestParseAppxManifest_FoundationCap(t *testing.T) {
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <Capability Name="internetClient"/>
  </Capabilities>
</Package>`
	m, err := ParseAppxManifest([]byte(manifest))
	if err != nil {
		t.Fatalf("ParseAppxManifest: %v", err)
	}
	if len(m.Capabilities.Capability) != 1 || m.Capabilities.Capability[0].Name != "internetClient" {
		t.Fatalf("foundation capability not parsed: %+v", m.Capabilities)
	}
	if len(m.Capabilities.OrderedRefs) != 1 || m.Capabilities.OrderedRefs[0].Namespace != "" {
		t.Fatalf("ordered refs missing/incorrect: %+v", m.Capabilities.OrderedRefs)
	}
}

func TestParseAppxManifest_UAPCap(t *testing.T) {
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <uap:Capability Name="userDataSystem"/>
  </Capabilities>
</Package>`
	m, err := ParseAppxManifest([]byte(manifest))
	if err != nil {
		t.Fatalf("ParseAppxManifest: %v", err)
	}
	if len(m.Capabilities.UAPCapability) != 1 || m.Capabilities.UAPCapability[0].Name != "userDataSystem" {
		t.Fatalf("uap capability not parsed: %+v", m.Capabilities)
	}
	if len(m.Capabilities.OrderedRefs) != 1 || m.Capabilities.OrderedRefs[0].Namespace != "uap" {
		t.Fatalf("ordered ref namespace wrong: %+v", m.Capabilities.OrderedRefs)
	}
}

func TestParseAppxManifest_UAP3Cap(t *testing.T) {
	manifest := `<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <uap3:Capability Name="userDataAccountsProvider"/>
  </Capabilities>
</Package>`
	m, err := ParseAppxManifest([]byte(manifest))
	if err != nil {
		t.Fatalf("ParseAppxManifest: %v", err)
	}
	if len(m.Capabilities.UAP3Capability) != 1 {
		t.Fatalf("uap3 capability not parsed: %+v", m.Capabilities)
	}
	if m.Capabilities.OrderedRefs[0].Namespace != "uap3" {
		t.Fatalf("expected uap3 namespace, got %q", m.Capabilities.OrderedRefs[0].Namespace)
	}
}

func TestParseAppxManifest_UAP2Cap(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap2="http://schemas.microsoft.com/appx/manifest/uap/windows10/2">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities><uap2:Capability Name="phoneCallHistorySystem"/></Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Capabilities.UAP2Capability) != 1 || m.Capabilities.UAP2Capability[0].Name != "phoneCallHistorySystem" {
		t.Fatalf("uap2 not parsed: %+v", m.Capabilities)
	}
}

func TestParseAppxManifest_UAP8Cap(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap8="http://schemas.microsoft.com/appx/manifest/uap/windows10/8">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities><uap8:Capability Name="screenCapture"/></Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Capabilities.UAP8Capability) != 1 {
		t.Fatalf("uap8 not parsed: %+v", m.Capabilities)
	}
}

func TestParseAppxManifest_UAP6Cap(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap6="http://schemas.microsoft.com/appx/manifest/uap/windows10/6">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities><uap6:Capability Name="backgroundMediaPlayback"/></Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Capabilities.UAP6Capability) != 1 {
		t.Fatalf("uap6 not parsed")
	}
}

func TestParseAppxManifest_Rescap(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities><rescap:Capability Name="runFullTrust"/></Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Capabilities.RestrictedCapability) != 1 || m.Capabilities.RestrictedCapability[0].Name != "runFullTrust" {
		t.Fatalf("rescap not parsed: %+v", m.Capabilities)
	}
	if m.Capabilities.OrderedRefs[0].Namespace != "rescap" {
		t.Fatalf("expected rescap namespace, got %q", m.Capabilities.OrderedRefs[0].Namespace)
	}
}

func TestParseAppxManifest_DeviceCap(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <DeviceCapability Name="webcam">
      <Device Id="any"><Function Type="name:vendorSpecific"/></Device>
    </DeviceCapability>
  </Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Capabilities.DeviceCapability) != 1 || m.Capabilities.DeviceCapability[0].Name != "webcam" {
		t.Fatalf("device capability not parsed: %+v", m.Capabilities)
	}
	dev := m.Capabilities.DeviceCapability[0]
	if len(dev.Device) != 1 || dev.Device[0].Id != "any" {
		t.Fatalf("device child not parsed: %+v", dev)
	}
	if len(dev.Device[0].Function) != 1 || dev.Device[0].Function[0].Type != "name:vendorSpecific" {
		t.Fatalf("device function not parsed: %+v", dev.Device[0])
	}
}

func TestParseAppxManifest_CustomCap(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap4="http://schemas.microsoft.com/appx/manifest/foundation/windows10/4">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <uap4:CustomCapability Name="microsoft.contoso.somecap_8wekyb3d8bbwe"/>
  </Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Capabilities.CustomCapability) != 1 {
		t.Fatalf("custom capability not parsed: %+v", m.Capabilities)
	}
	if m.Capabilities.OrderedRefs[0].Namespace != "custom" {
		t.Fatalf("expected custom namespace, got %q", m.Capabilities.OrderedRefs[0].Namespace)
	}
}

func TestParseAppxManifest_AllNamespaces(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<?xml version="1.0"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap2="http://schemas.microsoft.com/appx/manifest/uap/windows10/2"
         xmlns:uap4="http://schemas.microsoft.com/appx/manifest/foundation/windows10/4"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/>
  <Capabilities>
    <Capability Name="internetClient"/>
    <uap:Capability Name="userDataSystem"/>
    <uap2:Capability Name="phoneCallHistorySystem"/>
    <rescap:Capability Name="runFullTrust"/>
    <DeviceCapability Name="webcam"/>
    <uap4:CustomCapability Name="contoso.cap_xxxx"/>
  </Capabilities>
</Package>`))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		got  int
		want int
		name string
	}{
		{len(m.Capabilities.Capability), 1, "Capability"},
		{len(m.Capabilities.UAPCapability), 1, "UAPCapability"},
		{len(m.Capabilities.UAP2Capability), 1, "UAP2Capability"},
		{len(m.Capabilities.RestrictedCapability), 1, "RestrictedCapability"},
		{len(m.Capabilities.DeviceCapability), 1, "DeviceCapability"},
		{len(m.Capabilities.CustomCapability), 1, "CustomCapability"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}
	if len(m.Capabilities.OrderedRefs) != 6 {
		t.Errorf("expected 6 ordered refs, got %d", len(m.Capabilities.OrderedRefs))
	}
}

func TestParseAppxManifest_BillionLaughs(t *testing.T) {
	manifest := `<?xml version="1.0"?>
<!DOCTYPE Package [
  <!ENTITY a "AAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
]>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="&d;" Version="1.0.0.0" Publisher="CN=X"/>
</Package>`

	done := make(chan struct{})
	var (
		m   *AppxManifest
		err error
	)
	go func() {
		m, err = ParseAppxManifest([]byte(manifest))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("ParseAppxManifest hung on billion-laughs payload (T-04-04 regression)")
	}
	if err == nil {
		t.Fatalf("expected error on DOCTYPE manifest, got %+v", m)
	}
}

func TestParseAppxManifest_TruncatedXML(t *testing.T) {
	m, err := ParseAppxManifest([]byte(`<Package`))
	if err == nil {
		t.Fatalf("expected error on truncated XML, got %+v", m)
	}
	if m != nil {
		t.Fatalf("expected nil manifest on error, got %+v", m)
	}
}

func TestParseAppxManifest_BoundedCapabilities(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="A" Version="1.0.0.0" Publisher="CN=X"/><Capabilities>`)
	for range MaxCapabilityEntries + 10 {
		sb.WriteString(`<Capability Name="cap`)
		sb.WriteString(strings.Repeat("x", 1))
		sb.WriteString(`"/>`)
	}
	sb.WriteString(`</Capabilities></Package>`)
	m, err := ParseAppxManifest([]byte(sb.String()))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Capabilities.Truncated {
		t.Error("expected Truncated=true when over MaxCapabilityEntries")
	}
	if len(m.Capabilities.OrderedRefs) > MaxCapabilityEntries {
		t.Errorf("OrderedRefs exceeded cap: got %d", len(m.Capabilities.OrderedRefs))
	}
}

// TestParseAppxExtensions covers D-69-03: AppxManifest deep-parse must
// populate MSIXInfo.Extensions with Protocol, FileTypeAssociation,
// ShareTarget, BackgroundTasks, AppService, and activatableClass entries.
// Loads pkg/msix/testdata/appx_extensions_full.xml through ParseAppxManifest
// + the dir-mode flatten path (InfoFromDir) so both zip-mode and dir-mode
// flow through flattenApplicationExtensions identically.
func TestParseAppxExtensions(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "appx_extensions_full.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := InfoFromDir(dir)
	if err != nil {
		t.Fatalf("InfoFromDir: %v", err)
	}

	if len(info.Extensions) == 0 {
		t.Fatal("D-69-03: expected MSIXInfo.Extensions to be populated, got empty")
	}

	var sawProto, sawFTA, sawShare, sawAppSvc, sawActivatable bool
	for _, e := range info.Extensions {
		switch {
		case e.Protocol == "whatsapp":
			sawProto = true
		case len(e.FileTypes) > 0:
			sawFTA = true
		case len(e.ShareTargetSupportedTypes) > 0:
			sawShare = true
		case e.AppServiceName != "":
			sawAppSvc = true
		case len(e.ActivatableClassIDs) > 0:
			sawActivatable = true
		}
	}
	if !sawProto {
		t.Error("D-69-03: expected Protocol=\"whatsapp\" entry, got none")
	}
	if !sawFTA {
		t.Error("D-69-03: expected FileTypeAssoc with FileTypes non-empty, got none")
	}
	if !sawShare {
		t.Error("D-69-03: expected ShareTarget with SupportedTypes non-empty, got none")
	}
	if !sawAppSvc {
		t.Error("D-69-03: expected AppServiceName non-empty, got none")
	}
	if !sawActivatable {
		t.Error("D-69-03: expected ActivatableClassIDs non-empty, got none")
	}
}

// TestParseAppxVisualElements covers D-69-03: per-Application VisualElements
// (DisplayName, BackgroundColor, logos) must surface on MSIXInfo.VisualElements.
func TestParseAppxVisualElements(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "appx_visualelements.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := InfoFromDir(dir)
	if err != nil {
		t.Fatalf("InfoFromDir: %v", err)
	}

	if len(info.VisualElements) != 1 {
		t.Fatalf("D-69-03: expected 1 VisualElements entry, got %d", len(info.VisualElements))
	}
	ve := info.VisualElements[0]
	if ve.DisplayName != "Visual Elements Only" {
		t.Errorf("DisplayName: got %q, want %q", ve.DisplayName, "Visual Elements Only")
	}
	if ve.BackgroundColor != "#FF0000" {
		t.Errorf("BackgroundColor: got %q, want %q", ve.BackgroundColor, "#FF0000")
	}
	if ve.Square150x150Logo == "" {
		t.Error("Square150x150Logo: expected non-empty")
	}
	if ve.Square44x44Logo == "" {
		t.Error("Square44x44Logo: expected non-empty")
	}
}

// TestParseAppxSchemaDrift covers D-69-03 + D-69-05: a manifest with no
// <Extensions> and no <VisualElements> must parse without error and yield
// zero-value slices (no panic, no error path).
func TestParseAppxSchemaDrift(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "appx_minimal.xml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "AppxManifest.xml"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := InfoFromDir(dir)
	if err != nil {
		t.Fatalf("InfoFromDir on minimal manifest: %v", err)
	}
	if len(info.Extensions) != 0 {
		t.Errorf("expected zero-value Extensions slice, got %d entries", len(info.Extensions))
	}
	if len(info.VisualElements) != 0 {
		t.Errorf("expected zero-value VisualElements slice, got %d entries", len(info.VisualElements))
	}
	if len(info.Applications) != 1 {
		t.Errorf("expected 1 Application entry, got %d", len(info.Applications))
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		size int64
		want string
	}{
		{0, "0 bytes"},
		{512, "512 bytes"},
		{1024, "1.0 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := FormatBytes(tt.size); got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.size, got, tt.want)
			}
		})
	}
}
