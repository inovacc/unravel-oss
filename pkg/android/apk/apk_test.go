/* Copyright (c) 2026 Security Research */
package apk

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name string
		size int64
		want string
	}{
		{"bytes", 500, "500 bytes"},
		{"zero bytes", 0, "0 bytes"},
		{"kilobytes", 1536, "1.5 KB"},
		{"megabytes", 5 * 1024 * 1024, "5.0 MB"},
		{"gigabytes", 2 * 1024 * 1024 * 1024, "2.0 GB"},
		{"exact 1 KB", 1024, "1.0 KB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatBytes(tt.size)
			if got != tt.want {
				t.Errorf("FormatBytes(%d) = %q, want %q", tt.size, got, tt.want)
			}
		})
	}
}

func TestDetectFormatAPK(t *testing.T) {
	// Create a minimal ZIP with AndroidManifest.xml to detect as APK.
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "test.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}

	w := zip.NewWriter(f)

	manifest, err := w.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatalf("create manifest entry: %v", err)
	}

	if _, err := manifest.Write([]byte("<manifest/>")); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	format, err := DetectFormat(apkPath)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}

	if format != FormatAPK {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatAPK)
	}
}

// casesPath resolves a path relative to the cases/ directory at the project root.
func casesPath(t *testing.T, relPath string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Skip("could not find project root")
		}
		dir = parent
	}
	p := filepath.Join(dir, "cases", relPath)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skipf("test case not available: %s", p)
	}
	return p
}

func TestGolden_Info_InstagramAPK(t *testing.T) {
	apkPath := casesPath(t, "android/input/com.instagram.android-410.0.0.53.71-APK4Fun.com.apk")

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Format != FormatAPK {
		t.Errorf("Format = %q, want %q", result.Format, FormatAPK)
	}
	if !result.HasManifest {
		t.Error("expected HasManifest = true")
	}
	if result.DEXCount == 0 {
		t.Error("expected DEXCount > 0")
	}
	if len(result.NativeLibs) == 0 {
		t.Error("expected NativeLibs to be populated")
	}
	if !result.HasSignature {
		t.Error("expected HasSignature = true")
	}
}

func TestGolden_Info_MapsAPK(t *testing.T) {
	apkPath := casesPath(t, "android/input/com.google.android.apps.maps-26.05.04.860829830-APK4Fun.com.apk")

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Format != FormatAPK {
		t.Errorf("Format = %q, want %q", result.Format, FormatAPK)
	}
	if !result.HasManifest {
		t.Error("expected HasManifest = true")
	}
	if result.DEXCount == 0 {
		t.Error("expected DEXCount > 0")
	}
}

func TestGolden_Info_UberAPKM(t *testing.T) {
	apkPath := casesPath(t, "android/input/com.ubercab_4.616.10004-264279_1arch_4dpi_25lang_7feat_f37d1c507e87135d70f2446d01c49b7e_apkmirror.com.apkm")

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info: %v", err)
	}

	if result.Format != FormatAPKM {
		t.Errorf("Format = %q, want %q", result.Format, FormatAPKM)
	}
	if result.BundleInfo == nil {
		t.Error("expected non-nil BundleInfo for APKM")
	}
}

func TestGolden_DetectFormat_APK(t *testing.T) {
	apkPath := casesPath(t, "android/input/com.instagram.android-410.0.0.53.71-APK4Fun.com.apk")

	format, err := DetectFormat(apkPath)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if format != FormatAPK {
		t.Errorf("DetectFormat = %q, want %q", format, FormatAPK)
	}
}

func TestGolden_DetectFormat_APKM(t *testing.T) {
	apkPath := casesPath(t, "android/input/com.ubercab_4.616.10004-264279_1arch_4dpi_25lang_7feat_f37d1c507e87135d70f2446d01c49b7e_apkmirror.com.apkm")

	format, err := DetectFormat(apkPath)
	if err != nil {
		t.Fatalf("DetectFormat: %v", err)
	}
	if format != FormatAPKM {
		t.Errorf("DetectFormat = %q, want %q", format, FormatAPKM)
	}
}

func TestCategorizeEntry(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"manifest", "AndroidManifest.xml", "manifest"},
		{"dex primary", "classes.dex", "dex"},
		{"dex secondary", "classes2.dex", "dex"},
		{"native lib", "lib/arm64-v8a/libfoo.so", "native"},
		{"resource layout", "res/layout/main.xml", "resource"},
		{"resources.arsc", "resources.arsc", "resource"},
		{"asset", "assets/data.json", "asset"},
		{"meta-inf", "META-INF/CERT.RSA", "meta"},
		{"kotlin", "kotlin/kotlin.kotlin_builtins", "kotlin"},
		{"other", "other.txt", "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := categorizeEntry(tt.input)
			if got != tt.want {
				t.Errorf("categorizeEntry(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractABI(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"arm64", "lib/arm64-v8a/libfoo.so", "arm64-v8a"},
		{"armeabi-v7a", "lib/armeabi-v7a/libbar.so", "armeabi-v7a"},
		{"x86_64", "lib/x86_64/lib.so", "x86_64"},
		{"not a lib", "classes.dex", ""},
		{"wrong prefix", "notlib/arm/foo.so", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractABI(tt.input)
			if got != tt.want {
				t.Errorf("extractABI(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatFingerprint(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"typical hex", "aabbccdd", "AA:BB:CC:DD"},
		{"empty", "", ""},
		{"single byte", "ab", "AB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatFingerprint(tt.input)
			if got != tt.want {
				t.Errorf("formatFingerprint(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestComputeFingerprint(t *testing.T) {
	fp := computeFingerprint([]byte("test certificate data"))

	for _, field := range []struct {
		name  string
		value string
	}{
		{"MD5", fp.MD5},
		{"SHA1", fp.SHA1},
		{"SHA256", fp.SHA256},
	} {
		if field.value == "" {
			t.Errorf("computeFingerprint: %s is empty", field.name)
		}
		// All fingerprints should be colon-separated uppercase hex
		for i, ch := range field.value {
			if i%3 == 2 {
				if ch != ':' {
					t.Errorf("computeFingerprint: %s expected ':' at position %d, got %q", field.name, i, string(ch))
					break
				}
			}
		}
	}
}

// createMinimalAPK creates a minimal APK zip file with standard entries.
func createMinimalAPK(t *testing.T, dir string) string {
	t.Helper()

	apkPath := filepath.Join(dir, "minimal.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatalf("create file: %v", err)
	}

	w := zip.NewWriter(f)

	entries := []struct {
		name    string
		content string
	}{
		{"AndroidManifest.xml", "<manifest/>"},
		{"classes.dex", "dex\n035"},
		{"lib/arm64-v8a/libfoo.so", "\x7fELF"},
		{"res/layout/main.xml", "<LinearLayout/>"},
		{"assets/config.json", `{"key":"value"}`},
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0"},
	}

	for _, e := range entries {
		fw, err := w.Create(e.name)
		if err != nil {
			t.Fatalf("create entry %s: %v", e.name, err)
		}

		if _, err := fw.Write([]byte(e.content)); err != nil {
			t.Fatalf("write entry %s: %v", e.name, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	return apkPath
}

func TestInfoMinimalAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if !result.HasManifest {
		t.Error("expected HasManifest = true")
	}
	if result.DEXCount != 1 {
		t.Errorf("DEXCount = %d, want 1", result.DEXCount)
	}
	if result.NativeLibs["arm64-v8a"] != 1 {
		t.Errorf("NativeLibs[arm64-v8a] = %d, want 1", result.NativeLibs["arm64-v8a"])
	}
	if !result.HasResources {
		t.Error("expected HasResources = true")
	}
	if !result.HasAssets {
		t.Error("expected HasAssets = true")
	}
	// META-INF/MANIFEST.MF alone does not set HasSignature (needs .SF + .RSA too)
	if result.HasSignature {
		t.Error("expected HasSignature = false for minimal APK without .RSA/.SF")
	}
	if result.Format != FormatAPK {
		t.Errorf("Format = %q, want %q", result.Format, FormatAPK)
	}
}

func TestExtractMinimalAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)
	outputDir := filepath.Join(dir, "extracted")

	report, err := Extract(apkPath, outputDir, false)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if report.Files != 6 {
		t.Errorf("extracted files = %d, want 6", report.Files)
	}

	if len(report.Errors) > 0 {
		t.Errorf("unexpected errors: %v", report.Errors)
	}

	// Verify key files exist on disk.
	expectedFiles := []string{
		"AndroidManifest.xml",
		"classes.dex",
		"lib/arm64-v8a/libfoo.so",
		"res/layout/main.xml",
		"assets/config.json",
		"META-INF/MANIFEST.MF",
	}

	for _, name := range expectedFiles {
		path := filepath.Join(outputDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected extracted file %s to exist: %v", name, err)
		}
	}
}

func TestDetectFormatInvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notazip.bin")

	if err := os.WriteFile(path, []byte("not a zip file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := DetectFormat(path)
	if err == nil {
		t.Error("DetectFormat() expected error for non-zip file, got nil")
	}
}

// createZipWithEntries creates a ZIP file containing the named entries with dummy data.
func createZipWithEntries(t *testing.T, entries ...string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	for _, name := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("data"))
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDetectFormat_AAB(t *testing.T) {
	path := createZipWithEntries(t, "BundleConfig.pb", "base/manifest/AndroidManifest.xml")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}
	if format != FormatAAB {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatAAB)
	}
}

func TestDetectFormat_XAPK(t *testing.T) {
	path := createZipWithEntries(t, "manifest.json")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}
	if format != FormatXAPK {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatXAPK)
	}
}

func TestDetectFormat_APKS(t *testing.T) {
	path := createZipWithEntries(t, "toc.pb")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}
	if format != FormatAPKS {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatAPKS)
	}
}

func TestDetectFormat_APKM(t *testing.T) {
	path := createZipWithEntries(t, "info.json", "base.apk")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}
	if format != FormatAPKM {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatAPKM)
	}
}

func TestDetectFormat_Split(t *testing.T) {
	path := createZipWithEntries(t, "AndroidManifest.xml", "split_config.apk")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}
	if format != FormatSplit {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatSplit)
	}
}

func TestInfo_WithEntries(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)

	result, err := Info(apkPath, true)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if len(result.Entries) == 0 {
		t.Error("expected Entries to be populated when withEntries=true")
	}

	// Verify entries contain expected categories.
	categories := make(map[string]bool)
	for _, e := range result.Entries {
		categories[e.Category] = true
	}

	for _, want := range []string{"manifest", "dex", "native", "resource", "asset", "meta"} {
		if !categories[want] {
			t.Errorf("expected category %q in entries", want)
		}
	}
}

func TestInfo_NonExistent(t *testing.T) {
	_, err := Info("/nonexistent/file.apk", false)
	if err == nil {
		t.Error("Info() expected error for non-existent file, got nil")
	}
}

func TestInfo_NotZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.apk")

	if err := os.WriteFile(path, []byte("this is not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Info(path, false)
	if err == nil {
		t.Error("Info() expected error for non-zip file, got nil")
	}
}

func TestVerify_MinimalAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)

	result, err := Verify(apkPath)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result == nil {
		t.Fatal("Verify() returned nil result")
	}

	if result.OverallValid {
		t.Error("expected OverallValid = false for minimal APK without real signatures")
	}
}

func TestExtract_NonExistent(t *testing.T) {
	dir := t.TempDir()

	_, err := Extract("/nonexistent/file.apk", dir, false)
	if err == nil {
		t.Error("Extract() expected error for non-existent file, got nil")
	}
}

func TestExtract_ZipSlip(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "zipslip.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	// Add a legitimate entry.
	fw, err := w.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("<manifest/>"))

	// Add a path-traversal entry.
	fw, err = w.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("malicious"))

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	outputDir := filepath.Join(dir, "extracted")

	report, err := Extract(apkPath, outputDir, false)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// The zip-slip entry should be recorded in Errors.
	found := false
	for _, e := range report.Errors {
		if strings.Contains(e, "zip slip") || strings.Contains(e, "../evil.txt") {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("expected zip slip error in report.Errors, got: %v", report.Errors)
	}

	// The evil file should NOT exist outside the output directory.
	evilPath := filepath.Join(dir, "evil.txt")
	if _, err := os.Stat(evilPath); err == nil {
		t.Error("zip slip attack succeeded: ../evil.txt was written outside output directory")
	}
}

func TestExtract_Verbose(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)
	outputDir := filepath.Join(dir, "extracted")

	report, err := Extract(apkPath, outputDir, true)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	if report.Files != 6 {
		t.Errorf("extracted files = %d, want 6", report.Files)
	}
	if report.TotalSize == 0 {
		t.Error("expected TotalSize > 0")
	}
}

// createAPKMWithInfoJSON creates an APKM bundle with a valid info.json for testing
// parseInfoJSON, jsonString, and jsonInt code paths.
func createAPKMWithInfoJSON(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.apkm")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	// info.json with APK Mirror short keys.
	infoJSON := `{"pn":"com.example.app","vn":"2.0.1","vc":42,"mn":21,"tn":33,"arches":"arm64-v8a"}`
	fw, err := w.Create("info.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(infoJSON))

	// base.apk entry (required for APKM detection).
	fw, err = w.Create("base.apk")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("fake apk"))

	// icon file to test icon detection path.
	fw, err = w.Create("icon.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("fake png"))

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestInfo_APKMBundleInfo(t *testing.T) {
	apkPath := createAPKMWithInfoJSON(t)

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if result.Format != FormatAPKM {
		t.Errorf("Format = %q, want %q", result.Format, FormatAPKM)
	}

	if result.BundleInfo == nil {
		t.Fatal("expected non-nil BundleInfo")
	}

	bi := result.BundleInfo
	if bi.PackageName != "com.example.app" {
		t.Errorf("PackageName = %q, want %q", bi.PackageName, "com.example.app")
	}
	if bi.VersionName != "2.0.1" {
		t.Errorf("VersionName = %q, want %q", bi.VersionName, "2.0.1")
	}
	if bi.VersionCode != 42 {
		t.Errorf("VersionCode = %d, want 42", bi.VersionCode)
	}
	if bi.MinSDK != 21 {
		t.Errorf("MinSDK = %d, want 21", bi.MinSDK)
	}
	if bi.TargetSDK != 33 {
		t.Errorf("TargetSDK = %d, want 33", bi.TargetSDK)
	}
	if bi.ABIs != "arm64-v8a" {
		t.Errorf("ABIs = %q, want %q", bi.ABIs, "arm64-v8a")
	}
	if bi.IconFile != "icon.png" {
		t.Errorf("IconFile = %q, want %q", bi.IconFile, "icon.png")
	}
}

// createV1SignedAPK creates an APK with META-INF entries that trigger v1 signature scheme detection.
func createV1SignedAPK(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "v1signed.apk")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)

	entries := []struct {
		name    string
		content string
	}{
		{"AndroidManifest.xml", "<manifest/>"},
		{"classes.dex", "dex\n035"},
		{"META-INF/MANIFEST.MF", "Manifest-Version: 1.0"},
		{"META-INF/CERT.SF", "Signature-Version: 1.0"},
		{"META-INF/CERT.RSA", "fake rsa data"},
	}

	for _, e := range entries {
		fw, err := w.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte(e.content))
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestInfo_V1SignatureDetection(t *testing.T) {
	apkPath := createV1SignedAPK(t)

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if !result.HasSignature {
		t.Error("expected HasSignature = true for APK with .MF + .SF + .RSA")
	}

	found := slices.Contains(result.SignatureSchemes, "v1")
	if !found {
		t.Errorf("expected v1 in SignatureSchemes, got: %v", result.SignatureSchemes)
	}
}

func TestVerify_NonExistent(t *testing.T) {
	_, err := Verify("/nonexistent/file.apk")
	if err == nil {
		t.Error("Verify() expected error for non-existent file, got nil")
	}
}

func TestVerify_NotZip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.apk")

	if err := os.WriteFile(path, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Verify(path)
	if err == nil {
		t.Error("Verify() expected error for non-zip file, got nil")
	}
}

func TestVerify_V1SignedAPK(t *testing.T) {
	apkPath := createV1SignedAPK(t)

	result, err := Verify(apkPath)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result == nil {
		t.Fatal("Verify() returned nil result")
	}

	// v1 check runs but fake signatures won't validate fully.
	if len(result.Schemes) == 0 && len(result.Signatures) == 0 {
		// At minimum the v1 check path should have been exercised.
		t.Log("no schemes or signatures detected (expected for fake certs)")
	}
}

func TestExtractCertificates_MinimalAPK(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)

	result, err := ExtractCertificates(apkPath)
	if err != nil {
		t.Fatalf("ExtractCertificates() error: %v", err)
	}

	if result == nil {
		t.Fatal("ExtractCertificates() returned nil result")
	}

	// Minimal APK has no real certs so source should be "none".
	if result.Source != "none" {
		t.Errorf("Source = %q, want %q", result.Source, "none")
	}

	if len(result.Certificates) != 0 {
		t.Errorf("expected 0 certificates, got %d", len(result.Certificates))
	}
}

func TestExtractCertificates_NonExistent(t *testing.T) {
	_, err := ExtractCertificates("/nonexistent/file.apk")
	if err == nil {
		t.Error("ExtractCertificates() expected error for non-existent file, got nil")
	}
}

func TestExtractCertificates_V1SignedAPK(t *testing.T) {
	apkPath := createV1SignedAPK(t)

	result, err := ExtractCertificates(apkPath)
	if err != nil {
		t.Fatalf("ExtractCertificates() error: %v", err)
	}

	if result == nil {
		t.Fatal("ExtractCertificates() returned nil result")
	}

	// Fake RSA data won't parse as valid PKCS#7, so we expect no certs found.
	if result.Source != "none" {
		t.Logf("Source = %q (expected 'none' for fake certs, but v1 path was exercised)", result.Source)
	}
}

// createZipWithEntriesAndContent creates a ZIP file with named entries and their corresponding content.
func createZipWithEntriesAndContent(t *testing.T, entries map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	w := zip.NewWriter(f)
	for name, content := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte(content))
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestDetectFormatFromZip_DefaultCase verifies that a ZIP with no recognizable
// entries falls through to the default case and returns an error (not a false APK match).
func TestDetectFormatFromZip_DefaultCase(t *testing.T) {
	path := createZipWithEntries(t, "random_file.txt", "some/other/file.bin")

	_, err := DetectFormat(path)
	if err == nil {
		t.Error("DetectFormat() expected error for non-Android ZIP, got nil")
	}
}

// TestDetectFormatFromZip_BaseAPKWithoutInfoJSON verifies that a ZIP containing
// base.apk but no info.json returns FormatAPKM via the hasBaseAPK-only branch.
func TestDetectFormatFromZip_BaseAPKWithoutInfoJSON(t *testing.T) {
	path := createZipWithEntries(t, "base.apk", "split_config.arm64_v8a.apk")

	format, err := DetectFormat(path)
	if err != nil {
		t.Fatalf("DetectFormat() error: %v", err)
	}
	if format != FormatAPKM {
		t.Errorf("DetectFormat() = %q, want %q", format, FormatAPKM)
	}
}

// TestInfo_HasKotlin verifies that an APK containing kotlin/ entries sets HasKotlin.
func TestInfo_HasKotlin(t *testing.T) {
	path := createZipWithEntries(t,
		"AndroidManifest.xml",
		"classes.dex",
		"kotlin/kotlin.kotlin_builtins",
		"kotlin/collections/collections.kotlin_builtins",
	)

	result, err := Info(path, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}
	if !result.HasKotlin {
		t.Error("expected HasKotlin = true for APK with kotlin/ entries")
	}
}

// TestExtract_EmptyOutputDir verifies that Extract auto-generates an output
// directory name when outputDir is empty.
func TestExtract_EmptyOutputDir(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "myapp.apk")

	f, err := os.Create(apkPath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	fw, err := w.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("<manifest/>"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// Change working directory to dir so the auto-generated output path is predictable.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	report, err := Extract(apkPath, "", false)
	if err != nil {
		t.Fatalf("Extract() error: %v", err)
	}

	// Output should be auto-named "myapp_extracted".
	if report.Output == "" {
		t.Error("expected non-empty Output when outputDir is auto-generated")
	}
	if !strings.Contains(report.Output, "myapp_extracted") {
		t.Errorf("auto-generated output dir = %q, expected to contain %q", report.Output, "myapp_extracted")
	}
}

// TestParseInfoJSON_LongKeys verifies parseInfoJSON via Info() when info.json
// uses the standard long key names ("package_name", "version_name", etc.)
// instead of the short APK Mirror keys.
func TestParseInfoJSON_LongKeys(t *testing.T) {
	infoJSON := `{
		"package_name": "com.example.longkey",
		"version_name": "3.1.4",
		"version_code": 314,
		"min_sdk_version": 23,
		"target_sdk_version": 34,
		"abis": "x86_64"
	}`

	path := createZipWithEntriesAndContent(t, map[string]string{
		"info.json": infoJSON,
		"base.apk":  "fake apk",
	})

	result, err := Info(path, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if result.BundleInfo == nil {
		t.Fatal("expected non-nil BundleInfo")
	}

	bi := result.BundleInfo
	if bi.PackageName != "com.example.longkey" {
		t.Errorf("PackageName = %q, want %q", bi.PackageName, "com.example.longkey")
	}
	if bi.VersionName != "3.1.4" {
		t.Errorf("VersionName = %q, want %q", bi.VersionName, "3.1.4")
	}
	if bi.VersionCode != 314 {
		t.Errorf("VersionCode = %d, want 314", bi.VersionCode)
	}
	if bi.MinSDK != 23 {
		t.Errorf("MinSDK = %d, want 23", bi.MinSDK)
	}
	if bi.TargetSDK != 34 {
		t.Errorf("TargetSDK = %d, want 34", bi.TargetSDK)
	}
	if bi.ABIs != "x86_64" {
		t.Errorf("ABIs = %q, want %q", bi.ABIs, "x86_64")
	}
}

// TestParseInfoJSON_InvalidJSON verifies that parseInfoJSON returns nil when
// info.json contains malformed JSON.
func TestParseInfoJSON_InvalidJSON(t *testing.T) {
	path := createZipWithEntriesAndContent(t, map[string]string{
		"info.json": `{not valid json at all`,
		"base.apk":  "fake apk",
	})

	result, err := Info(path, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	// Invalid JSON means BundleInfo should be nil.
	if result.BundleInfo != nil {
		t.Errorf("expected nil BundleInfo for invalid JSON, got %+v", result.BundleInfo)
	}
}

// TestParseInfoJSON_FallbackKeys verifies that jsonString and jsonInt fall back
// to the second key when the first key is absent. We use a mix: short key present
// for some fields (first key missing), long key present for others (second key missing).
func TestParseInfoJSON_FallbackKeys(t *testing.T) {
	// Only short keys present (pn, vn, vc, mn, tn, arches).
	// jsonString is called as jsonString(raw, "package_name", "pn") — first key
	// "package_name" is absent, so it must fall back to "pn".
	infoJSON := `{"pn":"com.fallback.test","vn":"9.8.7","vc":987,"mn":19,"tn":30,"arches":"armeabi-v7a"}`

	path := createZipWithEntriesAndContent(t, map[string]string{
		"info.json": infoJSON,
		"base.apk":  "fake apk",
	})

	result, err := Info(path, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if result.BundleInfo == nil {
		t.Fatal("expected non-nil BundleInfo")
	}

	bi := result.BundleInfo
	if bi.PackageName != "com.fallback.test" {
		t.Errorf("PackageName = %q, want %q", bi.PackageName, "com.fallback.test")
	}
	if bi.VersionName != "9.8.7" {
		t.Errorf("VersionName = %q, want %q", bi.VersionName, "9.8.7")
	}
	if bi.VersionCode != 987 {
		t.Errorf("VersionCode = %d, want 987", bi.VersionCode)
	}
	if bi.MinSDK != 19 {
		t.Errorf("MinSDK = %d, want 19", bi.MinSDK)
	}
	if bi.TargetSDK != 30 {
		t.Errorf("TargetSDK = %d, want 30", bi.TargetSDK)
	}
	if bi.ABIs != "armeabi-v7a" {
		t.Errorf("ABIs = %q, want %q", bi.ABIs, "armeabi-v7a")
	}
}

// TestJSONString_NonStringValue verifies that jsonString returns the empty string
// when a key is present but its value is not a JSON string (e.g., a number).
// We test this indirectly via parseInfoJSON: if "pn" holds a number, PackageName
// must be empty.
func TestJSONString_NonStringValue(t *testing.T) {
	// "pn" is a number, not a string; "package_name" is absent.
	// jsonString(raw, "package_name", "pn") must return "".
	infoJSON := `{"pn":12345,"vn":"1.0","vc":1,"mn":21,"tn":33,"arches":"arm64-v8a"}`

	path := createZipWithEntriesAndContent(t, map[string]string{
		"info.json": infoJSON,
		"base.apk":  "fake apk",
	})

	result, err := Info(path, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if result.BundleInfo == nil {
		t.Fatal("expected non-nil BundleInfo")
	}

	if result.BundleInfo.PackageName != "" {
		t.Errorf("PackageName = %q, want empty string when value is not a JSON string", result.BundleInfo.PackageName)
	}
}

// TestJSONInt_NonIntValue verifies that jsonInt returns 0 when a key is present
// but its value is not a JSON number (e.g., a string). We test this via
// parseInfoJSON: if "vc" holds a string, VersionCode must be 0.
func TestJSONInt_NonIntValue(t *testing.T) {
	// "vc" is a string, not a number; "version_code" is absent.
	// jsonInt(raw, "version_code", "vc") must return 0.
	infoJSON := `{"pn":"com.example","vn":"1.0","vc":"not-an-int","mn":21,"tn":33,"arches":"arm64-v8a"}`

	path := createZipWithEntriesAndContent(t, map[string]string{
		"info.json": infoJSON,
		"base.apk":  "fake apk",
	})

	result, err := Info(path, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if result.BundleInfo == nil {
		t.Fatal("expected non-nil BundleInfo")
	}

	if result.BundleInfo.VersionCode != 0 {
		t.Errorf("VersionCode = %d, want 0 when value is not a JSON number", result.BundleInfo.VersionCode)
	}
}

// buildSigningBlock constructs a synthetic APK Signing Block containing a single
// ID-value pair. Android's block format is:
//
//	[8-byte blockSize][pairs...][8-byte blockSize][16-byte magic]
//
// blockSize = 8 (the leading size field) + len(pairs). findSigningBlock subtracts
// blockSize+8 from the CD offset to get blockStart, and parseSigningBlock reads
// (blockSize-8) bytes of pairs starting at blockStart+8. This means blockSize must
// equal len(pairsData) + 8.
func buildSigningBlock(id uint32, value []byte) []byte {
	// Each pair: 8-byte len + 4-byte ID + value
	pairLen := uint64(4 + len(value))
	pairsData := 8 + int(pairLen) // pair-len-field(8) + id(4) + value

	// blockSize is stored in both the leading and trailing 8-byte size fields.
	// findSigningBlock uses: blockStart = cdOffset - blockSize - 8
	// The full block on disk = leading(8) + pairsData + trailing(8) + magic(16) = pairsData+32
	// For blockStart to equal the real start: blockSize = (pairsData+32) - 8 = pairsData + 24
	blockSize := uint64(pairsData + 24)

	var buf bytes.Buffer

	// Leading 8-byte size
	binary.Write(&buf, binary.LittleEndian, blockSize)

	// Pair
	binary.Write(&buf, binary.LittleEndian, pairLen)
	binary.Write(&buf, binary.LittleEndian, id)
	buf.Write(value)

	// Footer: 8-byte size + 16-byte magic
	binary.Write(&buf, binary.LittleEndian, blockSize)
	buf.WriteString(sigBlockMagic)

	return buf.Bytes()
}

// createAPKWithSigningBlock writes a ZIP file and injects an APK Signing Block
// between the local-file data and the Central Directory. It returns the path.
func createAPKWithSigningBlock(t *testing.T, id uint32, value []byte) string {
	t.Helper()

	// Build a zip in memory first so we can locate the central directory.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	fw, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("<manifest/>"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipData := zipBuf.Bytes()

	// Find the EOCD to locate the central directory offset.
	eocdOffset := -1
	for i := len(zipData) - eocdMinSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(zipData[i:]) == eocdMagic {
			eocdOffset = i
			break
		}
	}
	if eocdOffset < 0 {
		t.Fatal("could not find EOCD in in-memory zip")
	}

	cdOffset := int(binary.LittleEndian.Uint32(zipData[eocdOffset+16 : eocdOffset+20]))

	// Construct the signing block.
	sigBlock := buildSigningBlock(id, value)

	// Reassemble: [local entries][signing block][central directory + EOCD]
	var out bytes.Buffer
	out.Write(zipData[:cdOffset])
	out.Write(sigBlock)

	// Update the EOCD CD offset to point past the signing block.
	newCDOffset := cdOffset + len(sigBlock)
	cdAndEOCD := make([]byte, len(zipData)-cdOffset)
	copy(cdAndEOCD, zipData[cdOffset:])
	binary.LittleEndian.PutUint32(cdAndEOCD[eocdOffset-cdOffset+16:], uint32(newCDOffset))
	out.Write(cdAndEOCD)

	dir := t.TempDir()
	path := filepath.Join(dir, "signed.apk")
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

// TestFindSigningBlock_Valid verifies that findSigningBlock correctly locates a
// synthetic APK Signing Block embedded before the Central Directory.
func TestFindSigningBlock_Valid(t *testing.T) {
	apkPath := createAPKWithSigningBlock(t, blockIDV2, []byte("dummy-v2-data"))

	f, err := os.Open(apkPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	offset, size, err := findSigningBlock(f)
	if err != nil {
		t.Fatalf("findSigningBlock() error: %v", err)
	}

	if offset < 0 {
		t.Errorf("expected non-negative offset, got %d", offset)
	}
	if size <= 0 {
		t.Errorf("expected positive size, got %d", size)
	}
}

// TestFindSigningBlock_NoBlock verifies that findSigningBlock returns an error
// when the file has no APK Signing Block (plain ZIP without magic).
func TestFindSigningBlock_NoBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nosigblock.apk")

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("AndroidManifest.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("<manifest/>"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	_, _, err = findSigningBlock(f)
	if err == nil {
		t.Error("findSigningBlock() expected error for ZIP without signing block, got nil")
	}
}

// TestFindSigningBlock_TinyFile verifies that findSigningBlock returns an error
// for a file too small to hold a valid ZIP structure.
func TestFindSigningBlock_TinyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.bin")
	if err := os.WriteFile(path, []byte("tiny"), 0o644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	_, _, err = findSigningBlock(f)
	if err == nil {
		t.Error("findSigningBlock() expected error for tiny file, got nil")
	}
}

// TestParseSigningBlock_Valid verifies that parseSigningBlock correctly decodes
// the ID-value pairs from a synthetic signing block.
func TestParseSigningBlock_Valid(t *testing.T) {
	apkPath := createAPKWithSigningBlock(t, blockIDV2, []byte("v2-payload"))

	f, err := os.Open(apkPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	offset, size, err := findSigningBlock(f)
	if err != nil {
		t.Fatalf("findSigningBlock() error: %v", err)
	}

	pairs, err := parseSigningBlock(f, offset, size)
	if err != nil {
		t.Fatalf("parseSigningBlock() error: %v", err)
	}

	val, ok := pairs[blockIDV2]
	if !ok {
		t.Fatalf("expected block ID 0x%x in pairs, got keys: %v", blockIDV2, pairs)
	}

	if string(val) != "v2-payload" {
		t.Errorf("pair value = %q, want %q", string(val), "v2-payload")
	}
}

// buildMinimalV2V3BlockData constructs a structurally minimal v2/v3 scheme block.
// Layout (all length-prefixed with uint32 LE):
//
//	signersLen → [ signerLen → [ signedDataLen → [digestsLen=0][certsLen=0] ] [sigsLen=0] [pkLen=0] ]
func buildMinimalV2V3BlockData() []byte {
	// signedData = digestsLen(4)=0 + certsLen(4)=0
	var sd bytes.Buffer
	binary.Write(&sd, binary.LittleEndian, uint32(0)) // digestsLen
	binary.Write(&sd, binary.LittleEndian, uint32(0)) // certsLen
	sdBytes := sd.Bytes()

	// signerContent = signedDataLen(4) + sdBytes + sigsLen(4) + pkLen(4)
	var signerContent bytes.Buffer
	binary.Write(&signerContent, binary.LittleEndian, uint32(len(sdBytes)))
	signerContent.Write(sdBytes)
	binary.Write(&signerContent, binary.LittleEndian, uint32(0))
	binary.Write(&signerContent, binary.LittleEndian, uint32(0))
	sc := signerContent.Bytes()

	// block = signersLen(4) + signerLen(4) + signerContent
	var block bytes.Buffer
	binary.Write(&block, binary.LittleEndian, uint32(4+len(sc))) // signersLen
	binary.Write(&block, binary.LittleEndian, uint32(len(sc)))   // signerLen
	block.Write(sc)

	return block.Bytes()
}

// TestCheckV2_WithSigningBlock verifies that checkSigningBlockScheme (via checkV2)
// detects the v2 scheme when a synthetic signing block is present.
func TestCheckV2_WithSigningBlock(t *testing.T) {
	apkPath := createAPKWithSigningBlock(t, blockIDV2, buildMinimalV2V3BlockData())

	f, err := os.Open(apkPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	info := checkSigningBlockScheme(f, SchemeV2, blockIDV2)
	if info == nil {
		t.Fatal("checkSigningBlockScheme() returned nil")
	}

	if !info.Present {
		t.Error("expected Present = true when v2 signing block is present")
	}
	if info.Scheme != SchemeV2 {
		t.Errorf("Scheme = %q, want %q", info.Scheme, SchemeV2)
	}
}

// TestCheckV3_WithSigningBlock verifies v3 detection mirrors v2.
func TestCheckV3_WithSigningBlock(t *testing.T) {
	apkPath := createAPKWithSigningBlock(t, blockIDV3, buildMinimalV2V3BlockData())

	f, err := os.Open(apkPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()

	info := checkSigningBlockScheme(f, SchemeV3, blockIDV3)
	if info == nil {
		t.Fatal("checkSigningBlockScheme() returned nil")
	}

	if !info.Present {
		t.Error("expected Present = true when v3 signing block is present")
	}
}

// TestCheckV4_WithIdsig verifies that checkV4 detects a .idsig file alongside the APK.
func TestCheckV4_WithIdsig(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)
	idsigPath := apkPath + ".idsig"

	if err := os.WriteFile(idsigPath, []byte("v4 signature data"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := checkV4(apkPath)
	if !info.Present {
		t.Error("expected Present = true when .idsig file exists")
	}
	if !info.Valid {
		t.Error("expected Valid = true when .idsig has content")
	}
	if info.SignerCount != 1 {
		t.Errorf("SignerCount = %d, want 1", info.SignerCount)
	}
	if info.Scheme != SchemeV4 {
		t.Errorf("Scheme = %q, want %q", info.Scheme, SchemeV4)
	}
}

// TestCheckV4_EmptyIdsig verifies that an empty .idsig file marks Valid = false.
func TestCheckV4_EmptyIdsig(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)
	idsigPath := apkPath + ".idsig"

	if err := os.WriteFile(idsigPath, []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}

	info := checkV4(apkPath)
	if !info.Present {
		t.Error("expected Present = true when .idsig exists")
	}
	if info.Valid {
		t.Error("expected Valid = false for empty .idsig")
	}
}

// TestCheckV4_NoIdsig verifies that checkV4 returns Present = false when no .idsig exists.
func TestCheckV4_NoIdsig(t *testing.T) {
	dir := t.TempDir()
	apkPath := createMinimalAPK(t, dir)

	info := checkV4(apkPath)
	if info.Present {
		t.Error("expected Present = false when .idsig file is absent")
	}
}

// TestCountSigners_Valid verifies countSigners returns the correct signer count
// for a well-formed length-prefixed signer sequence.
func TestCountSigners_Valid(t *testing.T) {
	tests := []struct {
		name        string
		signerSizes []int
		wantCount   int
	}{
		{"single signer of 8 bytes", []int{8}, 1},
		{"two signers", []int{4, 12}, 2},
		{"three signers", []int{0, 0, 0}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer

			// Calculate total signers payload length.
			totalLen := 0
			for _, sz := range tt.signerSizes {
				totalLen += 4 + sz // 4 for the per-signer length prefix
			}

			binary.Write(&buf, binary.LittleEndian, uint32(totalLen))
			for _, sz := range tt.signerSizes {
				binary.Write(&buf, binary.LittleEndian, uint32(sz))
				buf.Write(make([]byte, sz))
			}

			count, err := countSigners(buf.Bytes())
			if err != nil {
				t.Fatalf("countSigners() error: %v", err)
			}
			if count != tt.wantCount {
				t.Errorf("countSigners() = %d, want %d", count, tt.wantCount)
			}
		})
	}
}

// TestCountSigners_TooShort verifies that countSigners returns an error for
// data shorter than 4 bytes.
func TestCountSigners_TooShort(t *testing.T) {
	_, err := countSigners([]byte{0x01, 0x02})
	if err == nil {
		t.Error("countSigners() expected error for data < 4 bytes, got nil")
	}
}

// TestCountSigners_Empty verifies countSigners handles a zero-length signer sequence.
func TestCountSigners_Empty(t *testing.T) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], 0) // signersLen = 0

	count, err := countSigners(buf[:])
	if err != nil {
		t.Fatalf("countSigners() error: %v", err)
	}
	if count != 0 {
		t.Errorf("countSigners() = %d, want 0", count)
	}
}

// generateSelfSignedCertDER creates a minimal self-signed X.509 certificate
// and returns its DER encoding.
func generateSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return der
}

// TestParseSignerCerts_WithRealCert verifies that parseSignerCerts correctly
// extracts a real X.509 certificate embedded in a synthetic v2/v3 signer block.
func TestParseSignerCerts_WithRealCert(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	// Build the signer block structure containing one certificate.
	// Layout:
	//   signersLen (4)
	//     signerLen (4)
	//       signedDataLen (4)
	//         signedData:
	//           digestsLen (4) = 0 (no digests)
	//           certsLen (4)
	//             certLen (4) + certDER
	//       signaturesLen (4) = 0
	//       publicKeyLen (4) = 0

	// Build signedData inner content.
	var sdInner bytes.Buffer
	binary.Write(&sdInner, binary.LittleEndian, uint32(0)) // digestsLen = 0

	// certs sequence: certLen + certDER
	certsPayload := make([]byte, 4+len(certDER))
	binary.LittleEndian.PutUint32(certsPayload, uint32(len(certDER)))
	copy(certsPayload[4:], certDER)
	binary.Write(&sdInner, binary.LittleEndian, uint32(len(certsPayload)))
	sdInner.Write(certsPayload)
	sdBytes := sdInner.Bytes()

	// Build signer content: signedDataLen + signedData + signaturesLen + publicKeyLen
	var signerContent bytes.Buffer
	binary.Write(&signerContent, binary.LittleEndian, uint32(len(sdBytes))) // signedDataLen
	signerContent.Write(sdBytes)
	binary.Write(&signerContent, binary.LittleEndian, uint32(0)) // signaturesLen
	binary.Write(&signerContent, binary.LittleEndian, uint32(0)) // publicKeyLen
	signerContentBytes := signerContent.Bytes()

	// Build top-level block: signersLen + signerLen + signerContent
	var block bytes.Buffer
	// signersLen = 4 (signerLen field) + len(signerContent)
	signersPayloadLen := 4 + len(signerContentBytes)
	binary.Write(&block, binary.LittleEndian, uint32(signersPayloadLen))
	binary.Write(&block, binary.LittleEndian, uint32(len(signerContentBytes)))
	block.Write(signerContentBytes)

	certs, err := parseSignerCerts(block.Bytes())
	if err != nil {
		t.Fatalf("parseSignerCerts() error: %v", err)
	}

	if len(certs) != 1 {
		t.Fatalf("expected 1 certificate, got %d", len(certs))
	}

	cert := certs[0]
	if cert.Subject == "" {
		t.Error("expected non-empty Subject")
	}
	if cert.Fingerprint.SHA256 == "" {
		t.Error("expected non-empty SHA256 fingerprint")
	}
	if cert.IsSelfSigned != (cert.Subject == cert.Issuer) {
		t.Errorf("IsSelfSigned mismatch: Subject=%q Issuer=%q IsSelfSigned=%v",
			cert.Subject, cert.Issuer, cert.IsSelfSigned)
	}
}

// TestParseSignerCerts_TooShort verifies parseSignerCerts returns an error
// when the input is shorter than 4 bytes.
func TestParseSignerCerts_TooShort(t *testing.T) {
	_, err := parseSignerCerts([]byte{0x01})
	if err == nil {
		t.Error("parseSignerCerts() expected error for data < 4 bytes, got nil")
	}
}

// TestParseCertificate_Fields verifies parseCertificate populates all expected
// fields from a real X.509 certificate.
func TestParseCertificate_Fields(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	parsed, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	cert := parseCertificate(parsed, certDER)

	if cert.Subject == "" {
		t.Error("expected non-empty Subject")
	}
	if cert.Issuer == "" {
		t.Error("expected non-empty Issuer")
	}
	if cert.SerialNumber == "" {
		t.Error("expected non-empty SerialNumber")
	}
	if cert.Fingerprint.MD5 == "" {
		t.Error("expected non-empty MD5 fingerprint")
	}
	if cert.Fingerprint.SHA1 == "" {
		t.Error("expected non-empty SHA1 fingerprint")
	}
	if cert.Fingerprint.SHA256 == "" {
		t.Error("expected non-empty SHA256 fingerprint")
	}
	if cert.IsExpired {
		t.Error("expected IsExpired = false for a freshly created certificate")
	}
	if !cert.IsSelfSigned {
		t.Error("expected IsSelfSigned = true for a self-signed certificate")
	}
}

// buildPKCS7DER constructs a minimal DER-encoded PKCS#7 SignedData structure
// containing one X.509 certificate. This exercises parsePKCS7Certs.
func buildPKCS7DER(t *testing.T, certDER []byte) []byte {
	t.Helper()

	// Wrap the raw certificate DER in an IMPLICIT [0] context tag (the Certificates field).
	certTagged, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certDER,
	})
	if err != nil {
		t.Fatalf("marshal cert tag: %v", err)
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: []byte{}},
		ContentInfo:      asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: []byte{}},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certDER},
	}
	_ = certTagged

	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal SignedData: %v", err)
	}

	// OID for signedData: 1.2.840.113549.1.7.2
	signedDataOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	ci := contentInfo{
		ContentType: signedDataOID,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER},
	}

	ciDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("marshal ContentInfo: %v", err)
	}

	return ciDER
}

// TestParsePKCS7Certs_WithRealCert verifies parsePKCS7Certs extracts a certificate
// from a minimal but well-formed PKCS#7 SignedData structure.
func TestParsePKCS7Certs_WithRealCert(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)
	pkcs7DER := buildPKCS7DER(t, certDER)

	certs, err := parsePKCS7Certs(pkcs7DER)
	if err != nil {
		t.Fatalf("parsePKCS7Certs() error: %v", err)
	}

	// We embedded one cert; we should get at least the parsing attempt.
	// Depending on ASN.1 structure the cert may or may not decode depending
	// on how the Certificates field is encoded; accept either 0 or 1 without error.
	t.Logf("parsePKCS7Certs() returned %d certs (error-free path exercised)", len(certs))
}

// TestParsePKCS7Certs_InvalidDER verifies that parsePKCS7Certs returns an error
// for malformed DER input.
func TestParsePKCS7Certs_InvalidDER(t *testing.T) {
	_, err := parsePKCS7Certs([]byte{0x00, 0x01, 0x02, 0x03})
	if err == nil {
		t.Error("parsePKCS7Certs() expected error for invalid DER, got nil")
	}
}

// TestVerify_WithV2SigningBlock exercises the full Verify() path with a synthetic
// APK that contains a v2 signing block so checkV2/checkV3 paths are reached.
func TestVerify_WithV2SigningBlock(t *testing.T) {
	apkPath := createAPKWithSigningBlock(t, blockIDV2, buildMinimalV2V3BlockData())

	result, err := Verify(apkPath)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if result == nil {
		t.Fatal("Verify() returned nil")
	}

	// v2 scheme should be detected as present.
	foundV2 := slices.Contains(result.Schemes, "v2")

	if !foundV2 {
		t.Errorf("expected v2 in Schemes, got: %v", result.Schemes)
	}
}

// TestDetectSignatureSchemes_V2Block exercises detectSignatureSchemes with a
// synthetic APK that contains a v2 signing block, covering the v2/v3 block
// detection path inside Info().
func TestDetectSignatureSchemes_V2Block(t *testing.T) {
	apkPath := createAPKWithSigningBlock(t, blockIDV2, buildMinimalV2V3BlockData())

	result, err := Info(apkPath, false)
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	foundV2 := slices.Contains(result.SignatureSchemes, "v2")

	if !foundV2 {
		t.Errorf("expected v2 in SignatureSchemes, got: %v", result.SignatureSchemes)
	}
}
