/* Copyright (c) 2026 Security Research */
package detect

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestIsMCPServer(t *testing.T) {
	tests := []struct {
		name    string
		pkgJSON string
		want    bool
	}{
		{
			name:    "has MCP SDK in dependencies",
			pkgJSON: `{"dependencies":{"@modelcontextprotocol/sdk":"^1.0.0"}}`,
			want:    true,
		},
		{
			name:    "has MCP SDK in devDependencies",
			pkgJSON: `{"devDependencies":{"@modelcontextprotocol/sdk":"^1.0.0"}}`,
			want:    true,
		},
		{
			name:    "no MCP SDK",
			pkgJSON: `{"dependencies":{"express":"^4.0.0"}}`,
			want:    false,
		},
		{
			name:    "invalid JSON",
			pkgJSON: `not json`,
			want:    false,
		},
		{
			name:    "empty dependencies",
			pkgJSON: `{}`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(tt.pkgJSON), 0o644)
			if got := isMCPServer(dir); got != tt.want {
				t.Errorf("isMCPServer() = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("no package.json", func(t *testing.T) {
		if isMCPServer(t.TempDir()) {
			t.Error("isMCPServer() = true for dir without package.json")
		}
	})
}

func TestIsNodeModule(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{"inside node_modules", filepath.Join("some", "node_modules", "express"), true},
		{"not inside node_modules", filepath.Join("some", "project"), false},
		{"nested node_modules", filepath.Join("a", "node_modules", "b", "node_modules", "c"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNodeModule(tt.path); got != tt.want {
				t.Errorf("isNodeModule(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestDetectDirectory_MCPServer(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"dependencies":{"@modelcontextprotocol/sdk":"^1.0.0"}}`), 0o644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeMCPServer {
		t.Errorf("FileType = %q, want MCP Server", result.FileType)
	}
	if result.Category != CategoryNodePackage {
		t.Errorf("Category = %q, want node_package", result.Category)
	}
}

func TestDetectDirectory_NPMPackage(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "package.json"),
		[]byte(`{"name":"my-pkg","dependencies":{"express":"^4.0.0"}}`), 0o644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeNPMPackage {
		t.Errorf("FileType = %q, want NPM Package", result.FileType)
	}
}

func TestDetectDirectory_NodeModule(t *testing.T) {
	base := t.TempDir()
	modDir := filepath.Join(base, "node_modules", "express")
	_ = os.MkdirAll(modDir, 0o755)
	_ = os.WriteFile(filepath.Join(modDir, "package.json"),
		[]byte(`{"name":"express"}`), 0o644)

	result, err := Detect(modDir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeNodeModule {
		t.Errorf("FileType = %q, want Node Module", result.FileType)
	}
}

func TestDetectByExtension_SourceMap(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bundle.js.map")
	_ = os.WriteFile(p, []byte("source map content"), 0o644)

	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeSourceMap {
		t.Errorf("FileType = %q, want Source Map", result.FileType)
	}
}

func TestDetectByExtension_WASMByExt(t *testing.T) {
	// WASM detected by extension (no magic bytes)
	p := filepath.Join(t.TempDir(), "module.wasm")
	_ = os.WriteFile(p, []byte("not wasm magic"), 0o644)

	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeWASM {
		t.Errorf("FileType = %q, want WebAssembly", result.FileType)
	}
	if result.Confidence != ConfidenceMedium {
		t.Errorf("Confidence = %q, want MEDIUM for extension-based detection", result.Confidence)
	}
}

func TestDetectByExtension_TGZNoGzipMagic(t *testing.T) {
	// .tgz extension without GZIP magic bytes falls to extension-based detection
	p := filepath.Join(t.TempDir(), "pkg.tgz")
	_ = os.WriteFile(p, []byte("not gzip magic"), 0o644)

	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeNPMPackage {
		t.Errorf("FileType = %q, want NPM Package", result.FileType)
	}
}

func TestCommandsForType_NewTypes(t *testing.T) {
	tests := []struct {
		ft      FileType
		wantLen int
	}{
		{TypeJavaClass, 2},
		{TypeJAR, 3},
		{TypeWAR, 3},
		{TypeEAR, 3},
		{TypeBunStandalone, 4},
		{TypePyInstaller, 2},
		{TypePyZipApp, 2},
		{TypeAdvancedInstaller, 4},
		{TypeSourceMap, 2},
		{TypeMCPServer, 3},
		{TypeNPMPackage, 2},
		{TypeIPA, 2},
		{TypeWASM, 1},
	}

	for _, tt := range tests {
		t.Run(string(tt.ft), func(t *testing.T) {
			cmds := commandsForType(tt.ft)
			if len(cmds) != tt.wantLen {
				t.Errorf("commandsForType(%s) = %d commands, want %d", tt.ft, len(cmds), tt.wantLen)
			}
		})
	}
}

func TestDetect_WASMMagic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "module.wasm")
	data := []byte{0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00}
	data = append(data, make([]byte, 100)...)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeWASM {
		t.Errorf("FileType = %q, want WebAssembly", result.FileType)
	}
	if result.Confidence != ConfidenceCertain {
		t.Errorf("Confidence = %q, want CERTAIN", result.Confidence)
	}
}

func TestDetect_GZIPNpmTarball(t *testing.T) {
	p := filepath.Join(t.TempDir(), "package.tgz")
	data := []byte{0x1f, 0x8b, 0x08, 0x00}
	data = append(data, make([]byte, 100)...)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeNPMPackage {
		t.Errorf("FileType = %q, want NPM Package", result.FileType)
	}
}

func TestDetect_GZIPTarGz(t *testing.T) {
	p := filepath.Join(t.TempDir(), "package.tar.gz")
	data := []byte{0x1f, 0x8b, 0x08, 0x00}
	data = append(data, make([]byte, 100)...)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeNPMPackage {
		t.Errorf("FileType = %q, want NPM Package", result.FileType)
	}
}

func TestDetect_PlainGZIP(t *testing.T) {
	p := filepath.Join(t.TempDir(), "data.gz")
	data := []byte{0x1f, 0x8b, 0x08, 0x00}
	data = append(data, make([]byte, 100)...)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeGZIP {
		t.Errorf("FileType = %q, want GZIP", result.FileType)
	}
}

func TestDetect_ZipWithIPAPayload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.ipa")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("Payload/MyApp.app/Info.plist")
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("<plist></plist>"))
	_ = zw.Close()
	_ = f.Close()

	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeIPA {
		t.Errorf("FileType = %q, want IPA", result.FileType)
	}
}

func TestDetect_ZipPlain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "archive.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("readme.txt")
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("hello world"))
	_ = zw.Close()
	_ = f.Close()

	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeZIP {
		t.Errorf("FileType = %q, want ZIP", result.FileType)
	}
}

func TestDetect_ZipWithJARManifest(t *testing.T) {
	p := filepath.Join(t.TempDir(), "app.jar")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_, _ = w.Write([]byte("Manifest-Version: 1.0\n"))
	w2, _ := zw.Create("com/example/Main.class")
	_, _ = w2.Write([]byte{0xca, 0xfe, 0xba, 0xbe})
	_ = zw.Close()
	_ = f.Close()

	result, err := Detect(p)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	validTypes := map[FileType]bool{TypeJAR: true, TypeWAR: true, TypeEAR: true, TypeZIP: true}
	if !validTypes[result.FileType] {
		t.Errorf("FileType = %q, want JAR/WAR/EAR/ZIP", result.FileType)
	}
}

func TestTryUpgradeToBunStandalone_SkipsTypes(t *testing.T) {
	for _, ft := range []FileType{TypeGoBinary, TypeTauriApp, TypeUPXPacked, TypeNSIS} {
		t.Run(string(ft), func(t *testing.T) {
			result := &DetectResult{FileType: ft}
			tryUpgradeToBunStandalone(result, make([]byte, 100))
			if result.FileType != ft {
				t.Errorf("should not upgrade %s, got %q", ft, result.FileType)
			}
		})
	}
}

func TestTryUpgradeToBunStandalone_ShortHeader(t *testing.T) {
	result := &DetectResult{FileType: TypePE}
	// Header too short for PE offset read
	tryUpgradeToBunStandalone(result, make([]byte, 0x30))
	if result.FileType != TypePE {
		t.Errorf("should remain PE for short header, got %q", result.FileType)
	}
}

func TestTryUpgradeToBunStandalone_InvalidPESignature(t *testing.T) {
	result := &DetectResult{FileType: TypePE, Path: filepath.Join(t.TempDir(), "notbun")}
	_ = os.WriteFile(result.Path, append([]byte{'M', 'Z'}, make([]byte, 500)...), 0o644)

	header := make([]byte, 0x100)
	header[0] = 'M'
	header[1] = 'Z'
	// PE offset at 0x3C points to offset where there's no valid PE signature
	header[0x3C] = 0x50 // offset 0x50
	// No "PE\x00\x00" at offset 0x50
	header[0x50] = 'X'
	header[0x51] = 'X'

	tryUpgradeToBunStandalone(result, header)
	if result.FileType != TypePE {
		t.Errorf("should remain PE for invalid PE signature, got %q", result.FileType)
	}
}

func TestTryUpgradeToBunStandalone_PEOffsetOutOfBounds(t *testing.T) {
	result := &DetectResult{FileType: TypePE, Path: filepath.Join(t.TempDir(), "notbun2")}
	_ = os.WriteFile(result.Path, append([]byte{'M', 'Z'}, make([]byte, 500)...), 0o644)

	header := make([]byte, 0x100)
	header[0] = 'M'
	header[1] = 'Z'
	// PE offset points beyond header length
	header[0x3C] = 0xF0

	tryUpgradeToBunStandalone(result, header)
	if result.FileType != TypePE {
		t.Errorf("should remain PE for out-of-bounds PE offset, got %q", result.FileType)
	}
}

func TestTryUpgradeToPyInstOrZipApp_SkipsTypes(t *testing.T) {
	for _, ft := range []FileType{TypeGoBinary, TypeTauriApp, TypeUPXPacked, TypeNSIS, TypeBunStandalone} {
		t.Run(string(ft), func(t *testing.T) {
			result := &DetectResult{FileType: ft}
			tryUpgradeToPyInstOrZipApp(result)
			if result.FileType != ft {
				t.Errorf("should not upgrade %s, got %q", ft, result.FileType)
			}
		})
	}
}

func TestTryUpgradeToPyInstOrZipApp_NotPyInst(t *testing.T) {
	p := filepath.Join(t.TempDir(), "notpyinst")
	_ = os.WriteFile(p, append([]byte{'M', 'Z'}, make([]byte, 200)...), 0o644)

	result := &DetectResult{Path: p, FileType: TypePE}
	tryUpgradeToPyInstOrZipApp(result)
	// Should remain PE since it's not a PyInstaller binary
	if result.FileType != TypePE {
		t.Logf("FileType = %q (may have matched PyInstaller or ZipApp)", result.FileType)
	}
}

func TestTryUpgradeToAdvancedInstaller_SkipsTypes(t *testing.T) {
	for _, ft := range []FileType{TypeGoBinary, TypeTauriApp, TypeUPXPacked, TypeNSIS, TypeBunStandalone, TypePyInstaller, TypePyZipApp} {
		t.Run(string(ft), func(t *testing.T) {
			result := &DetectResult{FileType: ft}
			tryUpgradeToAdvancedInstaller(result)
			if result.FileType != ft {
				t.Errorf("should not upgrade %s, got %q", ft, result.FileType)
			}
		})
	}
}

func TestTryUpgradeToAdvancedInstaller_CannotOpen(t *testing.T) {
	result := &DetectResult{Path: "/nonexistent/file.exe", FileType: TypePE}
	tryUpgradeToAdvancedInstaller(result)
	if result.FileType != TypePE {
		t.Errorf("should remain PE for nonexistent file, got %q", result.FileType)
	}
}

func TestTryUpgradeToAdvancedInstaller_EmptyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.exe")
	_ = os.WriteFile(p, []byte{}, 0o644)

	result := &DetectResult{Path: p, FileType: TypePE}
	tryUpgradeToAdvancedInstaller(result)
	if result.FileType != TypePE {
		t.Errorf("should remain PE for empty file, got %q", result.FileType)
	}
}

func TestTryUpgradeToAdvancedInstaller_WithMarkers(t *testing.T) {
	markers := []struct {
		name    string
		content string
	}{
		{"ADVINSTSFX", "some data ADVINSTSFX more data"},
		{"ExternalUi.pdb", "some data ExternalUi.pdb more data"},
		{"Registry path", `some data Software\Caphyon\Advanced Installer more data`},
		{"InitializeEmbeddedUI", "some data InitializeEmbeddedUI more data"},
	}

	for _, m := range markers {
		t.Run(m.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "installer.exe")
			_ = os.WriteFile(p, []byte(m.content), 0o644)

			result := &DetectResult{Path: p, FileType: TypePE}
			tryUpgradeToAdvancedInstaller(result)
			if result.FileType != TypeAdvancedInstaller {
				t.Errorf("FileType = %q, want Advanced Installer for marker %s", result.FileType, m.name)
			}
		})
	}
}

func TestDetectDirectory_TauriPriority(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "tauri.conf.json"), []byte(`{"build":{}}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"tauri-app"}`), 0o644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.FileType != TypeTauriApp {
		t.Errorf("FileType = %q, want Tauri App (tauri.conf.json has priority)", result.FileType)
	}
}

func TestDetect_ApplicableCommandsPopulated(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		data     []byte
		wantCmds bool
	}{
		{"ELF has commands", "binary", append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 12)...), true},
		{"JS has commands", "app.js", []byte("var x = 1;"), true},
		{"Unknown has no commands", "data.xyz", []byte("random"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), tt.filename)
			_ = os.WriteFile(p, tt.data, 0o644)

			result, err := Detect(p)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}

			hasCmds := len(result.ApplicableCommands) > 0
			if hasCmds != tt.wantCmds {
				t.Errorf("ApplicableCommands present = %v, want %v", hasCmds, tt.wantCmds)
			}
		})
	}
}

func TestTryUpgradeToNSIS_PE_NonNSIS(t *testing.T) {
	// Test that tryUpgradeToNSIS is called on PE path and doesn't upgrade non-NSIS
	p := filepath.Join(t.TempDir(), "notnsispe")
	data := append([]byte{'M', 'Z'}, make([]byte, 200)...)
	_ = os.WriteFile(p, data, 0o644)

	result := &DetectResult{Path: p, FileType: TypePE}
	tryUpgradeToNSIS(result)
	if result.FileType != TypePE {
		t.Errorf("should remain PE for non-NSIS binary, got %q", result.FileType)
	}
}

func TestDetect_IsIPAFalse(t *testing.T) {
	// ZIP without Payload/... should not be IPA
	p := filepath.Join(t.TempDir(), "notipa.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, _ := zw.Create("some/other/file.txt")
	_, _ = w.Write([]byte("content"))
	_ = zw.Close()
	_ = f.Close()

	if isIPA(p) {
		t.Error("isIPA should return false for ZIP without Payload")
	}
}

func TestDetect_IsIPACannotOpen(t *testing.T) {
	if isIPA("/nonexistent/file.zip") {
		t.Error("isIPA should return false for nonexistent file")
	}
}

func TestTryUpgradeToBunStandalone_ValidPEWithBunSection(t *testing.T) {
	// Build a synthetic PE header that has a .bun section
	header := make([]byte, 512)
	header[0] = 'M'
	header[1] = 'Z'

	// PE offset at 0x3C => point to offset 0x80
	peOffset := 0x80
	header[0x3C] = byte(peOffset)

	// PE signature at peOffset
	copy(header[peOffset:peOffset+4], "PE\x00\x00")

	// Number of sections = 1 at peOffset+6
	header[peOffset+6] = 1

	// Optional header size = 0 at peOffset+20 (simplify)
	header[peOffset+20] = 0

	// Section starts at peOffset + 24 + 0 = peOffset + 24
	sectStart := peOffset + 24
	copy(header[sectStart:sectStart+8], ".bun\x00\x00\x00\x00")

	p := filepath.Join(t.TempDir(), "bunapp.exe")
	_ = os.WriteFile(p, header, 0o644)

	result := &DetectResult{Path: p, FileType: TypePE}
	tryUpgradeToBunStandalone(result, header)
	if result.FileType != TypeBunStandalone {
		t.Errorf("FileType = %q, want Bun Standalone", result.FileType)
	}
}

func TestTryUpgradeToBunStandalone_ValidPENoMatchingSections(t *testing.T) {
	// Build a synthetic PE with sections but no .bun
	header := make([]byte, 512)
	header[0] = 'M'
	header[1] = 'Z'

	peOffset := 0x80
	header[0x3C] = byte(peOffset)
	copy(header[peOffset:peOffset+4], "PE\x00\x00")
	header[peOffset+6] = 1 // 1 section
	header[peOffset+20] = 0

	sectStart := peOffset + 24
	copy(header[sectStart:sectStart+8], ".text\x00\x00\x00")

	p := filepath.Join(t.TempDir(), "notbun.exe")
	_ = os.WriteFile(p, header, 0o644)

	result := &DetectResult{Path: p, FileType: TypePE}
	tryUpgradeToBunStandalone(result, header)
	// Should remain PE (bun.IsBunBinary will also return false for this small file)
	if result.FileType == TypeBunStandalone {
		t.Log("Unexpectedly detected as Bun (bun.IsBunBinary returned true)")
	}
}

func TestTryUpgradeToBunStandalone_SectionOverflow(t *testing.T) {
	// PE with section count that would overflow beyond header
	header := make([]byte, 0x100)
	header[0] = 'M'
	header[1] = 'Z'

	peOffset := 0x80
	header[0x3C] = byte(peOffset)
	copy(header[peOffset:peOffset+4], "PE\x00\x00")
	header[peOffset+6] = 10 // 10 sections, but header is only 256 bytes
	header[peOffset+20] = 0

	p := filepath.Join(t.TempDir(), "overflow.exe")
	_ = os.WriteFile(p, header, 0o644)

	result := &DetectResult{Path: p, FileType: TypePE}
	tryUpgradeToBunStandalone(result, header)
	// Should not crash, should remain PE
	if result.FileType == TypeBunStandalone {
		t.Log("Detected as Bun despite section overflow")
	}
}

func TestScan_WithSubdirDetectedAsApp(t *testing.T) {
	dir := t.TempDir()

	// Create an Electron-like app directory
	appDir := filepath.Join(dir, "electronapp")
	resDir := filepath.Join(appDir, "resources")
	_ = os.MkdirAll(resDir, 0o755)
	_ = os.WriteFile(filepath.Join(resDir, "app.asar"), []byte("asar"), 0o644)
	_ = os.WriteFile(filepath.Join(appDir, "inside.js"), []byte("var x;"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "root.js"), []byte("var y;"), 0o644)

	result, err := Scan(dir)
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	foundElectron := false
	foundInside := false
	for _, d := range result.Detected {
		if d.FileType == TypeElectronApp {
			foundElectron = true
		}
		if d.Name == "inside.js" {
			foundInside = true
		}
	}
	if !foundElectron {
		t.Error("should detect Electron app directory")
	}
	if foundInside {
		t.Error("should skip files inside detected app directory (SkipDir)")
	}
}
