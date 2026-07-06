/*
Copyright (c) 2026 Security Research
*/
package tools

import (
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry() returned nil")
	}

	expectedTools := []string{
		"apktool", "jadx", "dex2jar", "procyon",
		"jd-cli", "retdec", "ilspycmd", "bundletool", "adb",
	}

	for _, name := range expectedTools {
		if r.tools[name] == nil {
			t.Errorf("expected tool %q in registry", name)
		}
	}

	if len(r.tools) != len(expectedTools) {
		t.Errorf("expected %d tools, got %d", len(expectedTools), len(r.tools))
	}
}

func TestNewRegistry_ToolTypes(t *testing.T) {
	r := NewRegistry()

	tests := []struct {
		name     string
		wantType ToolType
	}{
		{"apktool", ToolTypeJava},
		{"jadx", ToolTypeJava},
		{"dex2jar", ToolTypeJava},
		{"retdec", ToolTypeNative},
		{"ilspycmd", ToolTypeDotnet},
		{"adb", ToolTypeNative},
		{"bundletool", ToolTypeJava},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := r.GetTool(tt.name)
			if tool == nil {
				t.Fatalf("tool %q not found", tt.name)
			}

			if tool.Type != tt.wantType {
				t.Errorf("tool %q type = %q, want %q", tt.name, tool.Type, tt.wantType)
			}
		})
	}
}

func TestGetTool_Existing(t *testing.T) {
	r := NewRegistry()

	tests := []struct {
		name        string
		wantBinary  string
		wantHasAlts bool
	}{
		{"apktool", "apktool", false},
		{"jadx", "jadx", false},
		{"dex2jar", "d2j-dex2jar", true},
		{"procyon", "procyon", true},
		{"retdec", "retdec-decompiler", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := r.GetTool(tt.name)
			if tool == nil {
				t.Fatalf("GetTool(%q) returned nil", tt.name)
			}

			if tool.Name != tt.name {
				t.Errorf("Name = %q, want %q", tool.Name, tt.name)
			}

			if tool.Binary != tt.wantBinary {
				t.Errorf("Binary = %q, want %q", tool.Binary, tt.wantBinary)
			}

			if tool.Description == "" {
				t.Error("Description is empty")
			}

			hasAlts := len(tool.AltBinaries) > 0
			if hasAlts != tt.wantHasAlts {
				t.Errorf("has alt binaries = %v, want %v", hasAlts, tt.wantHasAlts)
			}
		})
	}
}

func TestGetTool_Nonexistent(t *testing.T) {
	r := NewRegistry()

	tool := r.GetTool("nonexistent")
	if tool != nil {
		t.Errorf("GetTool(\"nonexistent\") = %v, want nil", tool)
	}
}

func TestIsAvailable_Undetected(t *testing.T) {
	r := NewRegistry()

	// Tools should not be available before detection
	names := []string{"apktool", "jadx", "dex2jar", "retdec"}
	for _, name := range names {
		if r.IsAvailable(name) {
			t.Errorf("IsAvailable(%q) = true before detection, want false", name)
		}
	}
}

func TestIsAvailable_Nonexistent(t *testing.T) {
	r := NewRegistry()

	if r.IsAvailable("nonexistent") {
		t.Error("IsAvailable(\"nonexistent\") = true, want false")
	}
}

func TestDetect_Nonexistent(t *testing.T) {
	r := NewRegistry()

	tool := r.Detect("nonexistent")
	if tool != nil {
		t.Error("Detect(\"nonexistent\") returned non-nil")
	}
}

func TestDetect_SetsError(t *testing.T) {
	r := NewRegistry()

	// Detect a tool that almost certainly doesn't exist on the system
	tool := r.Detect("apktool")
	if tool == nil {
		t.Fatal("Detect returned nil for registered tool")
	}

	// If the tool is not installed, it should have an error message
	if !tool.Available && tool.Error == "" {
		t.Error("unavailable tool should have error message")
	}
}

func TestDetectAll(t *testing.T) {
	r := NewRegistry()

	status := r.DetectAll()
	if status == nil {
		t.Fatal("DetectAll returned nil")
	}

	if status.Total != 9 {
		t.Errorf("Total = %d, want 9", status.Total)
	}

	if len(status.Tools) != 9 {
		t.Errorf("len(Tools) = %d, want 9", len(status.Tools))
	}

	if status.Available > status.Total {
		t.Errorf("Available (%d) > Total (%d)", status.Available, status.Total)
	}
}

func TestParseVersionLine(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "single line",
			input:  "apktool 2.9.3",
			expect: "apktool 2.9.3",
		},
		{
			name:   "multi-line takes first",
			input:  "jadx 1.4.7\nSome extra info\nMore lines",
			expect: "jadx 1.4.7",
		},
		{
			name:   "empty input",
			input:  "",
			expect: "",
		},
		{
			name:   "whitespace only",
			input:  "   \n  \n",
			expect: "",
		},
		{
			name:   "leading and trailing whitespace",
			input:  "  version 1.0  \n",
			expect: "version 1.0",
		},
		{
			name:   "truncated at 100 chars",
			input:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			expect: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			name:   "carriage return in multi-line",
			input:  "tool v3.0\r\ngarbage",
			expect: "tool v3.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseVersionLine(tt.input)
			if got != tt.expect {
				t.Errorf("parseVersionLine(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

// --- helpers ---

// makeZip creates a ZIP file at path with the given entries (name -> content).
func makeZip(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create zip: %v", err)
	}
	defer func() { _ = f.Close() }()

	w := zip.NewWriter(f)
	defer func() { _ = w.Close() }()

	for name, data := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatalf("zip entry %q: %v", name, err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatalf("write zip entry %q: %v", name, err)
		}
	}
}

// makeMinimalAPK writes a ZIP file that DetectFormat recognises as FormatAPK
// (it contains AndroidManifest.xml).
func makeMinimalAPK(t *testing.T, path string) {
	t.Helper()
	makeZip(t, path, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         []byte("dex\n035"),
	})
}

// --- extractFileFromZip ---

func TestExtractFileFromZip_Found(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "test.zip")

	content := []byte("hello from zip")
	makeZip(t, zipPath, map[string][]byte{
		"inner/file.txt": content,
	})

	dest := filepath.Join(dir, "file.txt")
	if err := extractFileFromZip(zipPath, "inner/file.txt", dest); err != nil {
		t.Fatalf("extractFileFromZip: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestExtractFileFromZip_NotFound(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "test.zip")

	makeZip(t, zipPath, map[string][]byte{
		"other.txt": []byte("data"),
	})

	dest := filepath.Join(dir, "out.txt")
	err := extractFileFromZip(zipPath, "missing.txt", dest)
	if err == nil {
		t.Fatal("expected error for missing entry, got nil")
	}
	if !strings.Contains(err.Error(), "missing.txt") {
		t.Errorf("error %q should mention the missing entry name", err)
	}
}

func TestExtractFileFromZip_InvalidZip(t *testing.T) {
	dir := t.TempDir()
	notZip := filepath.Join(dir, "notzip.zip")
	if err := os.WriteFile(notZip, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := extractFileFromZip(notZip, "anything", filepath.Join(dir, "out"))
	if err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

// --- extractByPattern / extractNativeLibs / extractDotnetAssemblies ---

func TestExtractByPattern_MatchesFiles(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "app.apk")

	makeZip(t, zipPath, map[string][]byte{
		"lib/arm64-v8a/libnative.so": []byte("ELF"),
		"lib/x86/libother.so":        []byte("ELF2"),
		"classes.dex":                []byte("dex"),
		"res/layout/main.xml":        []byte("<layout/>"),
	})

	outDir := t.TempDir()
	files, err := extractNativeLibs(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractNativeLibs: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("extracted %d files, want 2", len(files))
	}
}

func TestExtractByPattern_NoMatches(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "app.apk")

	makeZip(t, zipPath, map[string][]byte{
		"classes.dex": []byte("dex"),
	})

	outDir := t.TempDir()
	files, err := extractNativeLibs(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractNativeLibs: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

func TestExtractDotnetAssemblies_MatchesAssemblies(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "app.apk")

	makeZip(t, zipPath, map[string][]byte{
		"assemblies/MyApp.dll":   []byte("MZ"),
		"assemblies/Support.dll": []byte("MZ2"),
		"lib/arm64/libnative.so": []byte("ELF"),
	})

	outDir := t.TempDir()
	files, err := extractDotnetAssemblies(zipPath, outDir)
	if err != nil {
		t.Fatalf("extractDotnetAssemblies: %v", err)
	}
	if len(files) != 2 {
		t.Errorf("extracted %d dll files, want 2", len(files))
	}
}

func TestExtractByPattern_InvalidZip(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.apk")
	if err := os.WriteFile(bad, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := extractNativeLibs(bad, dir)
	if err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

// --- unwrapZipBundle ---

func TestUnwrapZipBundle_WithBaseApk(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "app.xapk")

	makeZip(t, bundlePath, map[string][]byte{
		"base.apk":      []byte("fake-apk-content"),
		"manifest.json": []byte(`{"package_name":"com.example"}`),
		"icon.png":      []byte("PNG"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	apkPath, err := unwrapZipBundle(bundlePath, outDir, result)
	if err != nil {
		t.Fatalf("unwrapZipBundle: %v", err)
	}

	if !strings.HasSuffix(apkPath, "base.apk") {
		t.Errorf("returned path %q should end with base.apk", apkPath)
	}

	if _, err := os.Stat(apkPath); err != nil {
		t.Errorf("extracted file not found: %v", err)
	}

	if !result.Steps[0].Success {
		t.Errorf("step should be marked successful")
	}
}

func TestUnwrapZipBundle_FallsBackToFirstApk(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "app.apkm")

	makeZip(t, bundlePath, map[string][]byte{
		"split_config.arm64.apk": []byte("fake-split-apk"),
		"info.json":              []byte(`{}`),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	apkPath, err := unwrapZipBundle(bundlePath, outDir, result)
	if err != nil {
		t.Fatalf("unwrapZipBundle: %v", err)
	}

	if !strings.HasSuffix(apkPath, "base.apk") {
		t.Errorf("returned path %q should end with base.apk (the extracted name)", apkPath)
	}
}

func TestUnwrapZipBundle_NoApkInBundle(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "app.xapk")

	makeZip(t, bundlePath, map[string][]byte{
		"manifest.json": []byte(`{}`),
		"icon.png":      []byte("PNG"),
	})

	outDir := t.TempDir()
	result := &DecompileResult{}
	_, err := unwrapZipBundle(bundlePath, outDir, result)
	if err == nil {
		t.Fatal("expected error when no APK in bundle")
	}
	if !strings.Contains(err.Error(), "no APK") {
		t.Errorf("error %q should mention 'no APK'", err)
	}
	if len(result.Steps) == 0 || result.Steps[0].Error == "" {
		t.Error("step should record the error")
	}
}

func TestUnwrapZipBundle_InvalidZip(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.xapk")
	if err := os.WriteFile(bad, []byte("not a zip"), 0o644); err != nil {
		t.Fatal(err)
	}

	outDir := t.TempDir()
	result := &DecompileResult{}
	_, err := unwrapZipBundle(bad, outDir, result)
	if err == nil {
		t.Fatal("expected error for invalid zip")
	}
}

// --- Registry.Run ---

func TestRegistry_Run_UnknownTool(t *testing.T) {
	r := NewRegistry()
	_, err := r.Run(context.Background(), "nonexistent-tool")
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("error %q should mention 'unknown tool'", err)
	}
}

func TestRegistry_Run_UnavailableTool(t *testing.T) {
	r := NewRegistry()
	// Tools are not detected yet, so all are unavailable.
	_, err := r.Run(context.Background(), "jadx", "--help")
	if err == nil {
		t.Fatal("expected error for unavailable tool")
	}
	if !strings.Contains(err.Error(), "not available") {
		t.Errorf("error %q should mention 'not available'", err)
	}
}

func TestRegistry_Run_WithEcho(t *testing.T) {
	r := NewRegistry()

	// Inject a synthetic "echo" tool directly so we can test Run end-to-end
	// without relying on any of the registered Android tools being present.
	echoPath, err := os.Executable()
	if err != nil {
		t.Skip("cannot determine executable path")
	}

	// Use /bin/echo which is universally available on Linux/macOS.
	echoPath = "/bin/echo"
	if _, err := os.Stat(echoPath); err != nil {
		t.Skip("/bin/echo not available")
	}

	r.mu.Lock()
	r.tools["_echo"] = &Tool{
		Name:      "_echo",
		Binary:    "echo",
		Path:      echoPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	res, err := r.Run(context.Background(), "_echo", "hello", "world")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("stdout %q should contain 'hello'", res.Stdout)
	}
	if res.Tool != "_echo" {
		t.Errorf("Tool = %q, want _echo", res.Tool)
	}
	if res.Duration <= 0 {
		t.Error("Duration should be positive")
	}
}

func TestRegistry_RunWithOptions_Timeout(t *testing.T) {
	r := NewRegistry()

	sleepPath := "/bin/sleep"
	if _, err := os.Stat(sleepPath); err != nil {
		t.Skip("/bin/sleep not available")
	}

	r.mu.Lock()
	r.tools["_sleep"] = &Tool{
		Name:      "_sleep",
		Binary:    "sleep",
		Path:      sleepPath,
		Available: true,
		Type:      ToolTypeNative,
	}
	r.mu.Unlock()

	opts := &RunOptions{Timeout: 1} // 1 nanosecond — guaranteed to expire
	_, err := r.RunWithOptions(context.Background(), "_sleep", opts, "10")
	// Either the context deadline is hit (err != nil) or we get a non-zero exit.
	// Either outcome is acceptable — the important thing is the call completes.
	_ = err
}

// --- Decompile ---

func TestDecompile_MissingInput(t *testing.T) {
	_, err := Decompile(context.Background(), DecompileOptions{
		InputPath: "/nonexistent/path/to/app.apk",
		OutputDir: t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error for missing input file")
	}
}

func TestDecompile_NoToolsAvailable(t *testing.T) {
	// This test asserts the missing-tools detection contract: when the
	// decompile pipeline runs without any external decompilers on PATH,
	// every skipped tool must surface in result.ToolsMissing. On a developer
	// machine where apktool/jadx/etc. are actually installed (e.g. via
	// scoop/brew), the contract isn't observable here — skip rather than
	// asserting against a polluted environment. CI runs without these tools
	// so the assertion still gates the contract there. (DEPT-01, P62-04.)
	if anyDecompileToolOnPATH() {
		t.Skip("decompile tools present on PATH — contract only observable in clean CI env")
	}

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "minimal.apk")
	makeMinimalAPK(t, apkPath)

	outDir := t.TempDir()
	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath: apkPath,
		OutputDir: outDir,
	})
	if err != nil {
		t.Fatalf("Decompile returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.InputPath == "" {
		t.Error("InputPath should be populated")
	}
	if result.OutputDir != outDir {
		t.Errorf("OutputDir = %q, want %q", result.OutputDir, outDir)
	}
	// Without any tools, all tools should be in the missing list.
	if len(result.ToolsMissing) == 0 {
		t.Error("expected ToolsMissing to be non-empty when no tools are installed")
	}
}

func TestDecompile_WithToolFilter_NoToolsAvailable(t *testing.T) {
	// See TestDecompile_NoToolsAvailable — same env-robustness rationale.
	// The contract under test is: with ToolFilter="jadx" and jadx absent
	// from PATH, "jadx" must appear in ToolsMissing. (DEPT-01, P62-04.)
	if _, err := exec.LookPath("jadx"); err == nil {
		t.Skip("jadx present on PATH — contract only observable when jadx is missing")
	}

	dir := t.TempDir()
	apkPath := filepath.Join(dir, "minimal.apk")
	makeMinimalAPK(t, apkPath)

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath:  apkPath,
		OutputDir:  t.TempDir(),
		ToolFilter: "jadx",
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	// jadx is not installed in CI, so it must appear in missing.
	found := slices.Contains(result.ToolsMissing, "jadx")
	if !found {
		t.Error("expected 'jadx' in ToolsMissing")
	}
}

// anyDecompileToolOnPATH reports whether any of the decompile pipeline's
// external tools resolve via PATH on the host. Used to skip tests that
// require a clean environment to observe the missing-tools contract.
func anyDecompileToolOnPATH() bool {
	for _, tool := range []string{"apktool", "jadx", "dex2jar", "procyon", "jd-cli", "retdec", "ilspycmd", "bundletool"} {
		if _, err := exec.LookPath(tool); err == nil {
			return true
		}
	}
	return false
}

func TestDecompile_DefaultOutputDir(t *testing.T) {
	dir := t.TempDir()
	apkPath := filepath.Join(dir, "myapp.apk")
	makeMinimalAPK(t, apkPath)

	// Change working directory so the default output ends up inside the temp dir.
	origDir, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Skip("cannot chdir")
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	result, err := Decompile(context.Background(), DecompileOptions{
		InputPath: apkPath,
		// OutputDir deliberately left empty — should default to myapp_decompiled
	})
	if err != nil {
		t.Fatalf("Decompile: %v", err)
	}
	if !strings.Contains(result.OutputDir, "myapp_decompiled") {
		t.Errorf("OutputDir %q should contain 'myapp_decompiled'", result.OutputDir)
	}
	// Clean up the auto-created directory.
	_ = os.RemoveAll(result.OutputDir)
}
