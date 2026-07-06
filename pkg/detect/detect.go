/*
Copyright (c) 2026 Security Research
*/
package detect

import (
	"archive/zip"
	"debug/buildinfo"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/bun"
	"github.com/inovacc/unravel-oss/pkg/cache"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	javaarchive "github.com/inovacc/unravel-oss/pkg/java/archive"
	"github.com/inovacc/unravel-oss/pkg/msi"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/msm"
	"github.com/inovacc/unravel-oss/pkg/nsis"
	"github.com/inovacc/unravel-oss/pkg/pyinst"
	"github.com/inovacc/unravel-oss/pkg/upx"
	webview2detect "github.com/inovacc/unravel-oss/pkg/webview2/detect"
	"github.com/inovacc/unravel-oss/pkg/zipapp"
)

// FileCategory groups detected file types into broad categories.
type FileCategory string

const (
	CategoryBinary       FileCategory = "binary"
	CategoryArchive      FileCategory = "archive"
	CategoryPackage      FileCategory = "package"
	CategoryData         FileCategory = "data"
	CategorySource       FileCategory = "source"
	CategoryMedia        FileCategory = "media"
	CategoryAppDirectory FileCategory = "app_directory"
	CategoryNodePackage  FileCategory = "node_package"
	CategoryUnknown      FileCategory = "unknown"
)

// FileType identifies the specific file format.
type FileType string

const (
	TypePE                FileType = "PE"
	TypeELF               FileType = "ELF"
	TypeMachO             FileType = "Mach-O"
	TypeMachOFat          FileType = "Mach-O Fat"
	TypeGoBinary          FileType = "Go Binary"
	TypeDEX               FileType = "DEX"
	TypeJavaClass         FileType = "Java Class"
	TypeAPK               FileType = "APK"
	TypeAAB               FileType = "AAB"
	TypeXAPK              FileType = "XAPK"
	TypeAPKS              FileType = "APKS"
	TypeAPKM              FileType = "APKM"
	TypeASAR              FileType = "ASAR"
	TypeDEB               FileType = "DEB"
	TypeRPM               FileType = "RPM"
	TypeZIP               FileType = "ZIP"
	TypeGZIP              FileType = "GZIP"
	TypeTAR               FileType = "TAR"
	TypeElectronApp       FileType = "Electron App"
	TypeTauriApp          FileType = "Tauri App"
	TypeWebView2App       FileType = "WebView2 App"
	TypeLevelDB           FileType = "LevelDB"
	TypeChromiumCache     FileType = "Chromium Cache"
	TypeSQLite            FileType = "SQLite"
	TypeJavaScript        FileType = "JavaScript"
	TypeJSON              FileType = "JSON"
	TypeYAML              FileType = "YAML"
	TypeXML               FileType = "XML"
	TypePNG               FileType = "PNG"
	TypeJPEG              FileType = "JPEG"
	TypeGIF               FileType = "GIF"
	TypeWebP              FileType = "WebP"
	TypePDF               FileType = "PDF"
	TypeWOFF              FileType = "WOFF"
	TypeWOFF2             FileType = "WOFF2"
	TypeBrowserExtPkg     FileType = "Browser Extension Package"
	TypeUPXPacked         FileType = "UPX Packed Binary"
	TypeNSIS              FileType = "NSIS Installer"
	TypeMSI               FileType = "MSI"
	TypeMSM               FileType = "MSM"
	TypeMSIX              FileType = "MSIX"
	TypeWinUIApp          FileType = "WinUI App"
	TypeUWPApp            FileType = "UWP App"
	TypeDotNetApp         FileType = ".NET App"
	TypeDotNetService     FileType = ".NET Windows Service"
	TypeJAR               FileType = "JAR"
	TypeWAR               FileType = "WAR"
	TypeEAR               FileType = "EAR"
	TypeBunStandalone     FileType = "Bun Standalone"
	TypePyInstaller       FileType = "PyInstaller"
	TypePyZipApp          FileType = "Python ZipApp"
	TypeAdvancedInstaller FileType = "Advanced Installer"
	TypeNPMPackage        FileType = "NPM Package"
	TypeNodeModule        FileType = "Node Module"
	TypeMCPServer         FileType = "MCP Server"
	TypeIPA               FileType = "IPA"
	TypeSourceMap         FileType = "Source Map"
	TypeWASM              FileType = "WebAssembly"
	TypeNodeAddon         FileType = "Node Addon"
	TypeUnknown           FileType = "Unknown"
)

// Confidence indicates how certain the detection is.
type Confidence string

const (
	ConfidenceCertain Confidence = "CERTAIN"
	ConfidenceHigh    Confidence = "HIGH"
	ConfidenceMedium  Confidence = "MEDIUM"
	ConfidenceLow     Confidence = "LOW"
)

// ApplicableCommand describes a unravel command that can process the detected file.
type ApplicableCommand struct {
	Command     string `json:"command"`
	Description string `json:"description"`
}

// DetectResult holds the detection result for a single path.
type DetectResult struct {
	Path               string              `json:"path"`
	Name               string              `json:"name"`
	Size               int64               `json:"size"`
	IsDir              bool                `json:"is_dir"`
	FileType           FileType            `json:"file_type"`
	Category           FileCategory        `json:"category"`
	Confidence         Confidence          `json:"confidence"`
	MagicBytes         string              `json:"magic_bytes,omitempty"`
	Details            string              `json:"details,omitempty"`
	ApplicableCommands []ApplicableCommand `json:"applicable_commands"`
}

// ScanResult holds results from scanning a directory.
type ScanResult struct {
	Path       string         `json:"path"`
	TotalFiles int            `json:"total_files"`
	Detected   []DetectResult `json:"detected"`
	Summary    map[string]int `json:"summary"`
	Errors     []string       `json:"errors,omitempty"`
}

// skipDirs contains directory names to skip during recursive scanning.
var skipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"__pycache__":  true,
	".idea":        true,
	".vscode":      true,
}

// DetectDir performs directory-level detection by walking top-level entries to
// identify framework markers (Electron app, Tauri app, etc.).
func DetectDir(path string) (*DetectResult, error) {
	return Detect(path)
}

// IsTauriBinary checks if a native binary contains Tauri framework signatures.
func IsTauriBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	// Read up to 1MB looking for Tauri signatures
	buf := make([]byte, 1024*1024)
	n, _ := f.Read(buf)
	if n == 0 {
		return false
	}

	content := string(buf[:n])
	markers := []string{"__tauri", "tauri://", "tauri::"}

	for _, m := range markers {
		if strings.Contains(content, m) {
			return true
		}
	}

	return false
}

// Detect identifies a single file or directory and returns its type with applicable commands.
func Detect(path string) (*DetectResult, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	result := &DetectResult{
		Path:  absPath,
		Name:  info.Name(),
		Size:  info.Size(),
		IsDir: info.IsDir(),
	}

	if info.IsDir() {
		detectDirectory(result)
	} else {
		detectFile(result)
	}

	result.ApplicableCommands = commandsForType(result.FileType)

	return result, nil
}

// Scan recursively scans a directory and classifies all files found.
func Scan(dirPath string) (*ScanResult, error) {
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", absPath)
	}

	scan := &ScanResult{
		Path:    absPath,
		Summary: make(map[string]int),
	}

	_ = filepath.WalkDir(absPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			scan.Errors = append(scan.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil
		}

		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			// Check if this directory is a recognizable app/data directory
			result, detectErr := Detect(path)
			if detectErr == nil && result.FileType != TypeUnknown {
				scan.Detected = append(scan.Detected, *result)
				scan.Summary[string(result.FileType)]++
				// Skip recursing into detected app directories
				if result.IsDir {
					return filepath.SkipDir
				}
			}

			return nil
		}

		scan.TotalFiles++

		result, detectErr := Detect(path)
		if detectErr != nil {
			scan.Errors = append(scan.Errors, fmt.Sprintf("%s: %v", path, detectErr))
			return nil
		}

		if result.FileType != TypeUnknown {
			scan.Detected = append(scan.Detected, *result)
			scan.Summary[string(result.FileType)]++
		}

		return nil
	})

	return scan, nil
}

// detectDirectory checks if a directory is a recognizable application or data store.
func detectDirectory(result *DetectResult) {
	path := result.Path

	// Phase 4 (FRM-05): UWP / WinUI 3 framework detection runs before
	// Electron/Tauri so an installed WindowsApps/<pkg> directory is
	// classified as the framework type rather than a generic Chromium app.
	if detectUWPDir(result, path) {
		return
	}

	if detectWinUIDir(result, path) {
		return
	}

	// Phase 16 (carryover): .NET self-contained app + Windows-service
	// disambiguation. Runs after WinUI 3 so a hybrid WinUI-on-DotNet
	// app (which also ships a .deps.json + .runtimeconfig.json) keeps
	// the higher-fidelity WinUI classification.
	if detectDotNetDir(result, path) {
		return
	}

	if detectElectronDir(result, path) {
		return
	}

	if detectTauriDir(result, path) {
		return
	}

	// MCP Server: package.json with @modelcontextprotocol/sdk dependency
	if _, err := os.Stat(filepath.Join(path, "package.json")); err == nil {
		if isMCPServer(path) {
			result.FileType = TypeMCPServer
			result.Category = CategoryNodePackage
			result.Confidence = ConfidenceHigh
			result.Details = "MCP Server (Node.js with @modelcontextprotocol/sdk)"
			return
		}
		// Check for node_modules indicator (installed module, not standalone package)
		if isNodeModule(path) {
			result.FileType = TypeNodeModule
			result.Category = CategoryNodePackage
			result.Confidence = ConfidenceHigh
			result.Details = "Node.js module (installed dependency)"
			return
		}
		// Regular npm package
		result.FileType = TypeNPMPackage
		result.Category = CategoryNodePackage
		result.Confidence = ConfidenceHigh
		result.Details = "Node.js package (package.json)"
		return
	}

	// LevelDB: has CURRENT file plus .log or .ldb files
	if _, err := os.Stat(filepath.Join(path, "CURRENT")); err == nil {
		hasLog := hasGlobMatch(filepath.Join(path, "*.log"))
		hasLdb := hasGlobMatch(filepath.Join(path, "*.ldb"))

		hasSst := hasGlobMatch(filepath.Join(path, "*.sst"))
		if hasLog || hasLdb || hasSst {
			result.FileType = TypeLevelDB
			result.Category = CategoryData
			result.Confidence = ConfidenceHigh
			result.Details = "LevelDB directory (CURRENT file + data files)"

			return
		}
	}

	// Chromium cache
	format := cache.DetectFormat(path)
	if format != "unknown" {
		result.FileType = TypeChromiumCache
		result.Category = CategoryData
		result.Confidence = ConfidenceHigh
		result.Details = fmt.Sprintf("Chromium %s cache", format)

		return
	}

	result.FileType = TypeUnknown
	result.Category = CategoryUnknown
	result.Confidence = ConfidenceLow
}

// detectElectronDir checks if a directory is an Electron app using multiple heuristics:
// 1. Direct resources/app.asar or resources/app/ (unpacked)
// 2. Subdirectory containing resources/app.asar (snap layouts like app/, lib/slack/)
// 3. Electron ELF/PE binary with Chromium helper files (.pak, locales/)
func detectElectronDir(result *DetectResult, path string) bool {
	// Direct: resources/app.asar
	if _, err := os.Stat(filepath.Join(path, "resources", "app.asar")); err == nil {
		result.FileType = TypeElectronApp
		result.Category = CategoryAppDirectory
		result.Confidence = ConfidenceHigh
		result.Details = "Contains resources/app.asar"

		return true
	}

	// Unpacked: resources/app/ with package.json
	if _, err := os.Stat(filepath.Join(path, "resources", "app", "package.json")); err == nil {
		result.FileType = TypeElectronApp
		result.Category = CategoryAppDirectory
		result.Confidence = ConfidenceHigh
		result.Details = "Contains resources/app/ (unpacked)"

		return true
	}

	// Check one level of subdirectories for standard Electron layout
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}

		sub := filepath.Join(path, e.Name())

		if _, err := os.Stat(filepath.Join(sub, "resources", "app.asar")); err == nil {
			result.FileType = TypeElectronApp
			result.Category = CategoryAppDirectory
			result.Confidence = ConfidenceHigh
			result.Details = fmt.Sprintf("Contains %s/resources/app.asar", e.Name())

			return true
		}

		if _, err := os.Stat(filepath.Join(sub, "resources", "app", "package.json")); err == nil {
			result.FileType = TypeElectronApp
			result.Category = CategoryAppDirectory
			result.Confidence = ConfidenceHigh
			result.Details = fmt.Sprintf("Contains %s/resources/app/ (unpacked)", e.Name())

			return true
		}
	}

	// Chromium marker files (.pak + locales/) with an executable binary
	hasPak := hasGlobMatch(filepath.Join(path, "*.pak"))
	if !hasPak {
		return false
	}

	if info, err := os.Stat(filepath.Join(path, "locales")); err != nil || !info.IsDir() {
		return false
	}

	// Confirm there's a native binary (not just Chromium data)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != "" {
			continue
		}

		info, err := e.Info()
		if err != nil || info.Size() < 1024*1024 || info.Mode()&0111 == 0 {
			continue
		}

		binPath := filepath.Join(path, e.Name())

		f, err := os.Open(binPath)
		if err != nil {
			continue
		}

		magic := make([]byte, 4)
		_, err = f.Read(magic)
		_ = f.Close()

		if err != nil {
			continue
		}

		isELF := magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
		isPE := magic[0] == 'M' && magic[1] == 'Z'

		if isELF || isPE {
			result.FileType = TypeElectronApp
			result.Category = CategoryAppDirectory
			result.Confidence = ConfidenceMedium
			result.Details = fmt.Sprintf("Chromium-based app (binary: %s)", e.Name())

			return true
		}
	}

	return false
}

// detectTauriDir checks if a directory is a Tauri app.
func detectTauriDir(result *DetectResult, path string) bool {
	if _, err := os.Stat(filepath.Join(path, "tauri.conf.json")); err == nil {
		result.FileType = TypeTauriApp
		result.Category = CategoryAppDirectory
		result.Confidence = ConfidenceHigh
		result.Details = "Contains tauri.conf.json"

		return true
	}

	return false
}

// detectFile identifies a file by reading its magic bytes and applying heuristics.
func detectFile(result *DetectResult) {
	f, err := os.Open(result.Path)
	if err != nil {
		result.FileType = TypeUnknown
		result.Category = CategoryUnknown
		result.Confidence = ConfidenceLow

		return
	}

	defer func() { _ = f.Close() }()

	// Read first 512 bytes for magic detection
	buf := make([]byte, 512)

	n, _ := f.Read(buf)
	if n == 0 {
		result.FileType = TypeUnknown
		result.Category = CategoryUnknown
		result.Confidence = ConfidenceLow

		return
	}

	buf = buf[:n]

	result.MagicBytes = formatMagicHex(buf, 16)

	// Try magic byte detection
	if detectByMagic(result, buf) {
		// Upgrade PE/ELF/Mach-O to Node Addon if extension is .node
		tryUpgradeToNodeAddon(result)
		return
	}

	// Try ASAR by extension + header validation
	if detectASAR(result, buf) {
		return
	}

	// Extension-based fallback
	detectByExtension(result)
}

// detectByMagic checks the file header against known magic byte signatures.
// Returns true if a match was found.
func detectByMagic(result *DetectResult, buf []byte) bool {
	n := len(buf)

	// ELF: \x7fELF
	if n >= 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
		result.FileType = TypeELF
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		tryUpgradeToGoBinary(result)
		tryUpgradeToTauriBinary(result)
		tryUpgradeToUPXBinary(result)

		return true
	}

	// PE: MZ
	if n >= 2 && buf[0] == 'M' && buf[1] == 'Z' {
		result.FileType = TypePE
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		tryUpgradeToGoBinary(result)
		tryUpgradeToTauriBinary(result)
		tryUpgradeToUPXBinary(result)
		tryUpgradeToNSIS(result)
		tryUpgradeToBunStandalone(result, buf)
		tryUpgradeToPyInstOrZipApp(result)
		tryUpgradeToAdvancedInstaller(result)
		tryUpgradeToWebView2App(result)

		return true
	}

	// Mach-O (32-bit LE)
	if n >= 4 && buf[0] == 0xfe && buf[1] == 0xed && buf[2] == 0xfa && buf[3] == 0xce {
		result.FileType = TypeMachO
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		tryUpgradeToGoBinary(result)
		tryUpgradeToTauriBinary(result)
		tryUpgradeToUPXBinary(result)

		return true
	}

	// Mach-O (32-bit BE)
	if n >= 4 && buf[0] == 0xce && buf[1] == 0xfa && buf[2] == 0xed && buf[3] == 0xfe {
		result.FileType = TypeMachO
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		tryUpgradeToGoBinary(result)
		tryUpgradeToTauriBinary(result)
		tryUpgradeToUPXBinary(result)

		return true
	}

	// Mach-O (64-bit LE)
	if n >= 4 && buf[0] == 0xcf && buf[1] == 0xfa && buf[2] == 0xed && buf[3] == 0xfe {
		result.FileType = TypeMachO
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		tryUpgradeToGoBinary(result)
		tryUpgradeToTauriBinary(result)
		tryUpgradeToUPXBinary(result)

		return true
	}

	// Mach-O (64-bit BE)
	if n >= 4 && buf[0] == 0xfe && buf[1] == 0xed && buf[2] == 0xfa && buf[3] == 0xcf {
		result.FileType = TypeMachO
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		tryUpgradeToGoBinary(result)
		tryUpgradeToTauriBinary(result)
		tryUpgradeToUPXBinary(result)

		return true
	}

	// \xca\xfe\xba\xbe: Mach-O Fat or Java Class
	if n >= 8 && buf[0] == 0xca && buf[1] == 0xfe && buf[2] == 0xba && buf[3] == 0xbe {
		v := binary.BigEndian.Uint32(buf[4:8])
		if v < 30 {
			result.FileType = TypeMachOFat
			result.Category = CategoryBinary
			result.Confidence = ConfidenceCertain
			tryUpgradeToGoBinary(result)
			tryUpgradeToTauriBinary(result)
		} else {
			result.FileType = TypeJavaClass
			result.Category = CategoryBinary
			result.Confidence = ConfidenceCertain
			result.Details = fmt.Sprintf("Java class version %d", v)
		}

		return true
	}

	// WASM: \x00asm
	if n >= 4 && buf[0] == 0x00 && buf[1] == 0x61 && buf[2] == 0x73 && buf[3] == 0x6D {
		result.FileType = TypeWASM
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain
		result.Details = "WebAssembly binary module"

		return true
	}

	// DEX: dex\n
	if n >= 4 && buf[0] == 'd' && buf[1] == 'e' && buf[2] == 'x' && buf[3] == '\n' {
		result.FileType = TypeDEX
		result.Category = CategoryBinary
		result.Confidence = ConfidenceCertain

		return true
	}

	// RPM: \xed\xab\xee\xdb
	if n >= 4 && buf[0] == 0xed && buf[1] == 0xab && buf[2] == 0xee && buf[3] == 0xdb {
		result.FileType = TypeRPM
		result.Category = CategoryPackage
		result.Confidence = ConfidenceCertain

		return true
	}

	// DEB (ar archive): !<arch>\n
	if n >= 8 && string(buf[:8]) == "!<arch>\n" {
		result.FileType = TypeDEB
		result.Category = CategoryPackage
		result.Confidence = ConfidenceCertain

		return true
	}

	// ZIP/APK/AAB: PK\x03\x04
	if n >= 4 && buf[0] == 'P' && buf[1] == 'K' && buf[2] == 0x03 && buf[3] == 0x04 {
		return detectZipVariant(result)
	}

	// GZIP: \x1f\x8b
	if n >= 2 && buf[0] == 0x1f && buf[1] == 0x8b {
		// Check if this is an npm package tarball by extension
		lower := strings.ToLower(result.Name)
		if strings.HasSuffix(lower, ".tgz") || strings.HasSuffix(lower, ".tar.gz") {
			result.FileType = TypeNPMPackage
			result.Category = CategoryNodePackage
			result.Confidence = ConfidenceMedium
			result.Details = "npm package tarball (.tgz)"

			return true
		}

		result.FileType = TypeGZIP
		result.Category = CategoryArchive
		result.Confidence = ConfidenceCertain

		return true
	}

	// TAR: "ustar" at offset 257
	if n >= 263 && string(buf[257:262]) == "ustar" {
		result.FileType = TypeTAR
		result.Category = CategoryArchive
		result.Confidence = ConfidenceCertain

		return true
	}

	// SQLite: "SQLite format 3\0"
	if n >= 16 && string(buf[:16]) == "SQLite format 3\x00" {
		result.FileType = TypeSQLite
		result.Category = CategoryData
		result.Confidence = ConfidenceCertain

		return true
	}

	// PNG: \x89PNG
	if n >= 4 && buf[0] == 0x89 && buf[1] == 'P' && buf[2] == 'N' && buf[3] == 'G' {
		result.FileType = TypePNG
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// JPEG: \xff\xd8\xff
	if n >= 3 && buf[0] == 0xff && buf[1] == 0xd8 && buf[2] == 0xff {
		result.FileType = TypeJPEG
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// GIF: GIF8
	if n >= 4 && buf[0] == 'G' && buf[1] == 'I' && buf[2] == 'F' && buf[3] == '8' {
		result.FileType = TypeGIF
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// WebP: RIFF + WEBP at offset 8
	if n >= 12 && string(buf[:4]) == "RIFF" && string(buf[8:12]) == "WEBP" {
		result.FileType = TypeWebP
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// PDF: %PDF
	if n >= 4 && string(buf[:4]) == "%PDF" {
		result.FileType = TypePDF
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// WOFF: wOFF
	if n >= 4 && string(buf[:4]) == "wOFF" {
		result.FileType = TypeWOFF
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// WOFF2: wOF2
	if n >= 4 && string(buf[:4]) == "wOF2" {
		result.FileType = TypeWOFF2
		result.Category = CategoryMedia
		result.Confidence = ConfidenceCertain

		return true
	}

	// CFBF/OLE2: d0 cf 11 e0 a1 b1 1a e1 — check if MSI
	if n >= 8 && buf[0] == 0xd0 && buf[1] == 0xcf && buf[2] == 0x11 && buf[3] == 0xe0 &&
		buf[4] == 0xa1 && buf[5] == 0xb1 && buf[6] == 0x1a && buf[7] == 0xe1 {
		return tryDetectMSI(result)
	}

	return false
}

// detectZipVariant determines if a ZIP file is an Android package or plain ZIP.
func detectZipVariant(result *DetectResult) bool {
	format, err := apk.DetectFormat(result.Path)
	if err == nil {
		switch format {
		case apk.FormatAPK:
			result.FileType = TypeAPK
			result.Category = CategoryPackage
			result.Confidence = ConfidenceCertain

			return true
		case apk.FormatAAB:
			result.FileType = TypeAAB
			result.Category = CategoryPackage
			result.Confidence = ConfidenceCertain

			return true
		case apk.FormatXAPK:
			result.FileType = TypeXAPK
			result.Category = CategoryPackage
			result.Confidence = ConfidenceCertain

			return true
		case apk.FormatAPKS:
			result.FileType = TypeAPKS
			result.Category = CategoryPackage
			result.Confidence = ConfidenceCertain

			return true
		case apk.FormatAPKM:
			result.FileType = TypeAPKM
			result.Category = CategoryPackage
			result.Confidence = ConfidenceCertain

			return true
		case apk.FormatSplit:
			result.FileType = TypeAPK
			result.Category = CategoryPackage
			result.Confidence = ConfidenceHigh
			result.Details = "Split APK"

			return true
		}
	}

	// Check for MSIX/APPX (ZIP with AppxManifest.xml)
	if msix.IsMSIX(result.Path) {
		result.FileType = TypeMSIX
		result.Category = CategoryPackage
		result.Confidence = ConfidenceCertain
		result.Details = "MSIX/APPX package"

		return true
	}

	// Check for iOS IPA (ZIP with Payload/*.app/)
	if isIPA(result.Path) {
		result.FileType = TypeIPA
		result.Category = CategoryPackage
		result.Confidence = ConfidenceCertain
		result.Details = "iOS Application Archive (IPA)"

		return true
	}

	// Check for Java archives (JAR/WAR/EAR)
	if jt := javaarchive.DetectType(result.Path); jt != javaarchive.ArchiveUnknown {
		switch jt {
		case javaarchive.ArchiveJAR:
			result.FileType = TypeJAR
			result.Details = "Java Archive (JAR)"
		case javaarchive.ArchiveWAR:
			result.FileType = TypeWAR
			result.Details = "Java Web Archive (WAR)"
		case javaarchive.ArchiveEAR:
			result.FileType = TypeEAR
			result.Details = "Java Enterprise Archive (EAR)"
		}
		result.Category = CategoryPackage
		result.Confidence = ConfidenceCertain

		return true
	}

	// Plain ZIP
	result.FileType = TypeZIP
	result.Category = CategoryArchive
	result.Confidence = ConfidenceCertain

	return true
}

func isIPA(path string) bool {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return false
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if strings.HasPrefix(f.Name, "Payload/") && strings.Contains(f.Name, ".app/") {
			return true
		}
	}

	return false
}

// tryUpgradeToTauriBinary checks if a native binary is a Tauri application.
// Only runs if the binary wasn't already identified as a Go binary.
func tryUpgradeToTauriBinary(result *DetectResult) {
	if result.FileType == TypeGoBinary {
		return
	}

	if IsTauriBinary(result.Path) {
		result.FileType = TypeTauriApp
		result.Category = CategoryAppDirectory
		result.Details = "Tauri application binary"
	}
}

// tryUpgradeToGoBinary checks if a native binary is a Go binary.
func tryUpgradeToGoBinary(result *DetectResult) {
	bi, err := buildinfo.ReadFile(result.Path)
	if err != nil {
		return
	}

	baseType := result.FileType
	result.FileType = TypeGoBinary

	result.Details = fmt.Sprintf("%s binary, Go %s", baseType, bi.GoVersion)
	if bi.Path != "" {
		result.Details += fmt.Sprintf(", module: %s", bi.Path)
	}
}

// tryUpgradeToUPXBinary checks if a native binary is UPX-packed.
// Only upgrades PE/ELF/Mach-O types (skips Go/Tauri).
func tryUpgradeToUPXBinary(result *DetectResult) {
	switch result.FileType {
	case TypeGoBinary, TypeTauriApp:
		return
	}

	if upx.HasUPXMarker(result.Path) {
		result.FileType = TypeUPXPacked
		result.Details = "UPX-packed binary"
	}
}

// tryUpgradeToNSIS checks if a PE binary is an NSIS installer.
// Only upgrades plain PE types (skips Go/Tauri/UPX).
func tryUpgradeToNSIS(result *DetectResult) {
	switch result.FileType {
	case TypeGoBinary, TypeTauriApp, TypeUPXPacked:
		return
	}

	if nsis.IsNSIS(result.Path) {
		result.FileType = TypeNSIS
		result.Category = CategoryPackage
		result.Details = "NSIS installer"
	}
}

// tryUpgradeToBunStandalone checks if a PE binary has a .bun section.
func tryUpgradeToBunStandalone(result *DetectResult, header []byte) {
	switch result.FileType {
	case TypeGoBinary, TypeTauriApp, TypeUPXPacked, TypeNSIS:
		return
	}

	if len(header) < 0x40 {
		return
	}

	peOffset := binary.LittleEndian.Uint32(header[0x3C:0x40])
	if int(peOffset)+24 > len(header) {
		return
	}
	if string(header[peOffset:peOffset+4]) != "PE\x00\x00" {
		return
	}

	sectionCount := int(binary.LittleEndian.Uint16(header[peOffset+6 : peOffset+8]))
	optHeaderSize := int(binary.LittleEndian.Uint16(header[peOffset+20 : peOffset+22]))
	sectionsStart := int(peOffset) + 24 + optHeaderSize

	for i := range sectionCount {
		off := sectionsStart + i*40
		if off+8 > len(header) {
			break
		}
		name := strings.TrimRight(string(header[off:off+8]), "\x00")
		if name == ".bun" {
			result.FileType = TypeBunStandalone
			result.Category = CategoryBinary
			result.Details = "Bun standalone executable (.bun section)"
			return
		}
	}

	// Fall back: check for trailer near end of file
	ok, _ := bun.IsBunBinary(result.Path)
	if ok {
		result.FileType = TypeBunStandalone
		result.Category = CategoryBinary
		result.Details = "Bun standalone executable"
	}
}

// tryUpgradeToPyInstOrZipApp checks if a binary is a PyInstaller or Python zipapp.
func tryUpgradeToPyInstOrZipApp(result *DetectResult) {
	switch result.FileType {
	case TypeGoBinary, TypeTauriApp, TypeUPXPacked, TypeNSIS, TypeBunStandalone:
		return
	}

	ok, _ := pyinst.IsPyInstaller(result.Path)
	if ok {
		result.FileType = TypePyInstaller
		result.Category = CategoryBinary
		result.Details = "PyInstaller executable"
		return
	}

	ok, _ = zipapp.IsZipAppBinary(result.Path)
	if ok {
		result.FileType = TypePyZipApp
		result.Category = CategoryBinary
		result.Details = "Python zipapp (PE stub + ZIP)"
	}
}

// tryUpgradeToAdvancedInstaller checks if a PE binary is an Advanced Installer bootstrapper.
// Only upgrades plain PE types (skips Go/Tauri/UPX/NSIS/Bun/PyInstaller).
func tryUpgradeToAdvancedInstaller(result *DetectResult) {
	switch result.FileType {
	case TypeGoBinary, TypeTauriApp, TypeUPXPacked, TypeNSIS, TypeBunStandalone, TypePyInstaller, TypePyZipApp:
		return
	}

	f, err := os.Open(result.Path)
	if err != nil {
		return
	}

	defer func() { _ = f.Close() }()

	// Read up to 2MB looking for Advanced Installer signatures
	buf := make([]byte, 2*1024*1024)
	n, _ := f.Read(buf)
	if n == 0 {
		return
	}

	content := string(buf[:n])

	markers := []struct {
		pattern     string
		description string
	}{
		{"ADVINSTSFX", "SFX marker (ADVINSTSFX)"},
		{"ExternalUi.pdb", "PDB path (ExternalUi.pdb)"},
		{`Software\Caphyon\Advanced Installer`, "registry path (Software\\Caphyon\\Advanced Installer)"},
		{"InitializeEmbeddedUI", "embedded UI function (InitializeEmbeddedUI)"},
	}

	for _, m := range markers {
		if strings.Contains(content, m.pattern) {
			result.FileType = TypeAdvancedInstaller
			result.Category = CategoryPackage
			result.Details = fmt.Sprintf("Advanced Installer bootstrapper — %s", m.description)

			return
		}
	}
}

// tryUpgradeToNodeAddon upgrades a PE/ELF/Mach-O detection to Node Addon
// when the file has a .node extension.
func tryUpgradeToNodeAddon(result *DetectResult) {
	if strings.EqualFold(filepath.Ext(result.Path), ".node") {
		switch result.FileType {
		case TypePE, TypeELF, TypeMachO, TypeMachOFat:
			result.FileType = TypeNodeAddon
			result.Confidence = ConfidenceHigh
			result.Details = "Node.js native addon (N-API)"
		}
	}
}

// tryDetectMSI opens a CFBF file and checks for MSI-specific streams.
//
// A merge module (.msm) shares the MSI container + database format, so it is
// checked first: an .msm carries a ModuleSignature table that a plain .msi does
// not. The strong signal is CFBF magic (already matched by the caller) + MSI
// streams + the ModuleSignature table; the .msm extension is a corroborating
// hint but not required.
func tryDetectMSI(result *DetectResult) bool {
	f, err := os.Open(result.Path)
	if err != nil {
		return false
	}

	defer func() { _ = f.Close() }()

	if !msi.IsMSI(f, result.Size) {
		return false
	}

	if msm.IsMergeModule(result.Path) {
		result.FileType = TypeMSM
		result.Category = CategoryPackage
		result.Confidence = ConfidenceCertain
		result.Details = "Windows Installer Merge Module (MSM)"

		return true
	}

	result.FileType = TypeMSI
	result.Category = CategoryPackage
	result.Confidence = ConfidenceCertain
	result.Details = "Windows Installer (MSI) package"

	return true
}

// detectASAR checks if a file is an ASAR archive by extension and header validation.
func detectASAR(result *DetectResult, buf []byte) bool {
	if !strings.EqualFold(filepath.Ext(result.Path), ".asar") {
		return false
	}

	// ASAR header: first 4 bytes = pickle size (uint32 LE), next 4 = header string size
	// Both should be reasonable positive values
	if len(buf) >= 16 {
		pickleSize := binary.LittleEndian.Uint32(buf[0:4])
		if pickleSize > 0 && pickleSize < 1<<28 {
			result.FileType = TypeASAR
			result.Category = CategoryArchive
			result.Confidence = ConfidenceHigh
			result.Details = fmt.Sprintf("ASAR archive (header size: %d)", pickleSize)

			return true
		}
	}

	// Extension-only fallback
	result.FileType = TypeASAR
	result.Category = CategoryArchive
	result.Confidence = ConfidenceMedium

	return true
}

// detectByExtension falls back to extension-based detection.
func detectByExtension(result *DetectResult) {
	ext := strings.ToLower(filepath.Ext(result.Path))
	switch ext {
	case ".js", ".mjs", ".cjs":
		result.FileType = TypeJavaScript
		result.Category = CategorySource
		result.Confidence = ConfidenceMedium
	case ".json":
		result.FileType = TypeJSON
		result.Category = CategoryData
		result.Confidence = ConfidenceMedium
	case ".yaml", ".yml":
		result.FileType = TypeYAML
		result.Category = CategoryData
		result.Confidence = ConfidenceMedium
	case ".xml":
		result.FileType = TypeXML
		result.Category = CategoryData
		result.Confidence = ConfidenceMedium
	case ".crx", ".xpi":
		result.FileType = TypeBrowserExtPkg
		result.Category = CategoryPackage
		result.Confidence = ConfidenceMedium
		result.Details = "Browser extension package"
	case ".tgz":
		result.FileType = TypeNPMPackage
		result.Category = CategoryPackage
		result.Confidence = ConfidenceMedium
		result.Details = "npm package tarball (.tgz)"
	case ".map":
		result.FileType = TypeSourceMap
		result.Category = CategorySource
		result.Confidence = ConfidenceMedium
		result.Details = "JavaScript source map"
	case ".wasm":
		result.FileType = TypeWASM
		result.Category = CategoryBinary
		result.Confidence = ConfidenceMedium
		result.Details = "WebAssembly binary module"
	case ".node":
		result.FileType = TypeNodeAddon
		result.Category = CategoryBinary
		result.Confidence = ConfidenceMedium
		result.Details = "Node.js native addon (N-API)"
	default:
		result.FileType = TypeUnknown
		result.Category = CategoryUnknown
		result.Confidence = ConfidenceLow
	}
}

// commandsForType maps a file type to the applicable unravel commands.
func commandsForType(ft FileType) []ApplicableCommand {
	switch ft {
	case TypePE, TypeELF, TypeMachO, TypeMachOFat:
		return []ApplicableCommand{
			{Command: "cert info", Description: "Extract certificate information"},
			{Command: "cert verify", Description: "Verify certificate validity"},
			{Command: "dissect --disassemble", Description: "Disassemble binary code"},
		}
	case TypeGoBinary:
		return []ApplicableCommand{
			{Command: "garble detect", Description: "Detect garble obfuscation"},
			{Command: "garble info", Description: "Extract Go binary metadata"},
			{Command: "garble strings", Description: "Extract strings with entropy analysis"},
			{Command: "garble symbols", Description: "Analyze symbol table"},
			{Command: "cert info", Description: "Extract certificate information"},
			{Command: "cert verify", Description: "Verify certificate validity"},
		}
	case TypeASAR:
		return []ApplicableCommand{
			{Command: "asar extract", Description: "Extract ASAR archive contents"},
			{Command: "asar dump", Description: "Dump ASAR header as JSON"},
			{Command: "asar search", Description: "Search inside ASAR archive"},
		}
	case TypeAPK, TypeAAB, TypeXAPK, TypeAPKS, TypeAPKM:
		return []ApplicableCommand{
			{Command: "android info", Description: "Show Android package information"},
			{Command: "android extract", Description: "Extract package contents"},
			{Command: "android verify", Description: "Verify package signatures"},
			{Command: "android cert", Description: "Extract signing certificates"},
			{Command: "android decompile", Description: "Decompile with external tools"},
		}
	case TypeJavaClass:
		return []ApplicableCommand{
			{Command: "java decompile", Description: "Decompile Java class to source"},
			{Command: "java info", Description: "Show class file metadata"},
		}
	case TypeJAR, TypeWAR, TypeEAR:
		return []ApplicableCommand{
			{Command: "java info", Description: "Show Java archive metadata"},
			{Command: "java decompile", Description: "Decompile all classes to source"},
			{Command: "java extract", Description: "Extract archive contents"},
		}
	case TypeDEX:
		return []ApplicableCommand{
			{Command: "android info", Description: "Show DEX file information"},
		}
	case TypeDEB:
		return []ApplicableCommand{
			{Command: "deb info", Description: "Show Debian package information"},
			{Command: "deb extract", Description: "Extract package contents"},
			{Command: "deb verify", Description: "Verify package signatures"},
		}
	case TypeRPM:
		return []ApplicableCommand{
			{Command: "rpm info", Description: "Show RPM package information"},
			{Command: "rpm extract", Description: "Extract package contents"},
			{Command: "rpm verify", Description: "Verify package signatures"},
		}
	case TypeElectronApp:
		return []ApplicableCommand{
			{Command: "analyze -t electron", Description: "Full Electron security analysis"},
		}
	case TypeTauriApp:
		return []ApplicableCommand{
			{Command: "analyze -t tauri", Description: "Full Tauri security analysis"},
		}
	case TypeLevelDB:
		return []ApplicableCommand{
			{Command: "leveldb parse", Description: "Parse LevelDB database"},
		}
	case TypeChromiumCache:
		return []ApplicableCommand{
			{Command: "cache parse", Description: "Parse Chromium HTTP cache"},
		}
	case TypeJavaScript:
		return []ApplicableCommand{
			{Command: "jsdeob analyze", Description: "Analyze JavaScript for security patterns"},
			{Command: "jsdeob deobfuscate", Description: "Deobfuscate JavaScript"},
		}
	case TypeBrowserExtPkg:
		return []ApplicableCommand{
			{Command: "extension analyze", Description: "Analyze extension package (.crx/.xpi)"},
			{Command: "extension extract", Description: "Extract extension files and forensic metadata"},
		}
	case TypeMSI:
		return []ApplicableCommand{
			{Command: "msi info", Description: "Show MSI package information"},
			{Command: "msi extract", Description: "Extract MSI streams"},
			{Command: "msi verify", Description: "Verify MSI signatures"},
		}
	case TypeMSM:
		return []ApplicableCommand{
			{Command: "msm info", Description: "Show Merge Module metadata, components, and driver files"},
		}
	case TypeMSIX:
		return []ApplicableCommand{
			{Command: "msix info", Description: "Show MSIX package information"},
			{Command: "msix extract", Description: "Extract MSIX contents"},
			{Command: "msix verify", Description: "Verify MSIX signatures"},
		}
	case TypeNSIS:
		return []ApplicableCommand{
			{Command: "nsis info", Description: "Show NSIS installer information"},
			{Command: "nsis extract", Description: "Extract NSIS installer contents"},
			{Command: "cert info", Description: "Extract certificate information"},
			{Command: "cert verify", Description: "Verify certificate validity"},
		}
	case TypeUPXPacked:
		return []ApplicableCommand{
			{Command: "upx -l", Description: "List UPX packing info"},
			{Command: "upx -d", Description: "Unpack binary"},
			{Command: "cert info", Description: "Extract certificate information"},
			{Command: "cert verify", Description: "Verify certificate validity"},
			{Command: "dissect --disassemble", Description: "Disassemble binary code"},
		}
	case TypeBunStandalone:
		return []ApplicableCommand{
			{Command: "bun info", Description: "Show Bun binary metadata and bundled files"},
			{Command: "bun extract", Description: "Decompile: extract all bundled JS/TS sources"},
			{Command: "cert info", Description: "Extract certificate information"},
			{Command: "cert verify", Description: "Verify certificate validity"},
		}
	case TypePyInstaller:
		return []ApplicableCommand{
			{Command: "pyinst info", Description: "Show PyInstaller binary metadata"},
			{Command: "pyinst extract", Description: "Extract all bundled Python files"},
		}
	case TypePyZipApp:
		return []ApplicableCommand{
			{Command: "pyinst info", Description: "Show Python zipapp metadata"},
			{Command: "pyinst extract", Description: "Extract zipapp contents"},
		}
	case TypeAdvancedInstaller:
		return []ApplicableCommand{
			{Command: "advinstaller info", Description: "Analyze Advanced Installer bootstrapper"},
			{Command: "advinstaller extract", Description: "Extract embedded MSI package"},
			{Command: "cert info", Description: "Extract certificate information"},
			{Command: "cert verify", Description: "Verify certificate validity"},
		}
	case TypeSourceMap:
		return []ApplicableCommand{
			{Command: "sourcemap info", Description: "Parse source map metadata"},
			{Command: "sourcemap extract", Description: "Extract original sources"},
		}
	case TypeMCPServer:
		return []ApplicableCommand{
			{Command: "npm analyze", Description: "Security analysis of MCP server"},
			{Command: "npm mcp", Description: "Extract MCP tool inventory"},
			{Command: "probe", Description: "Launch and enumerate MCP tools dynamically"},
		}
	case TypeNPMPackage:
		return []ApplicableCommand{
			{Command: "npm analyze", Description: "Security analysis of Node.js package"},
			{Command: "npm deps", Description: "Show package dependencies"},
		}
	case TypeIPA:
		return []ApplicableCommand{
			{Command: "ios info", Description: "Show iOS app metadata"},
			{Command: "ios extract", Description: "Extract IPA contents"},
		}
	case TypeWASM:
		return []ApplicableCommand{
			{Command: "wasm info", Description: "Display WebAssembly module metadata"},
		}
	case TypeNodeAddon:
		return []ApplicableCommand{
			{Command: "nodeaddon info", Description: "Analyze Node.js native addon metadata"},
			{Command: "nodeaddon symbols", Description: "Extract exported symbols with N-API annotation"},
			{Command: "nodeaddon strings", Description: "Extract strings with entropy analysis"},
			{Command: "nodeaddon imports", Description: "Analyze imported libraries with risk scoring"},
			{Command: "dissect", Description: "Run full analysis pipeline"},
		}
	case TypeSQLite:
		return []ApplicableCommand{
			{Command: "(informational)", Description: "SQLite database detected"},
		}
	default:
		return nil
	}
}

// isMCPServer checks if a directory with package.json contains the MCP SDK dependency.
func isMCPServer(dir string) bool {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return false
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if json.Unmarshal(data, &pkg) != nil {
		return false
	}

	_, inDeps := pkg.Dependencies["@modelcontextprotocol/sdk"]
	_, inDev := pkg.DevDependencies["@modelcontextprotocol/sdk"]

	return inDeps || inDev
}

// isNodeModule returns true if the directory is an installed node_modules dependency
// (lives inside a node_modules/ parent) rather than a standalone npm package.
func isNodeModule(dir string) bool {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	return strings.Contains(filepath.ToSlash(abs), "/node_modules/")
}

// hasGlobMatch returns true if the glob pattern matches at least one file.
func hasGlobMatch(pattern string) bool {
	matches, _ := filepath.Glob(pattern)
	return len(matches) > 0
}

// formatMagicHex formats the first maxBytes of a buffer as hex.
func formatMagicHex(buf []byte, maxBytes int) string {
	if len(buf) > maxBytes {
		buf = buf[:maxBytes]
	}

	parts := make([]string, len(buf))
	for i, b := range buf {
		parts[i] = fmt.Sprintf("%02x", b)
	}

	return strings.Join(parts, " ")
}

// tryUpgradeToWebView2App inspects the PE import table for WebView2Loader.dll
// and, when present, upgrades the result to TypeWebView2App (FRM-01, D-01).
//
// Precedence: Electron/Tauri framework wins — if the binary was already
// classified as TypeElectronApp, TypeTauriApp, TypeGoBinary, or TypeBunStandalone,
// no upgrade happens. This mirrors RESEARCH.md pitfall 9 (Electron apps may ship
// WebView2 as a secondary runtime; primary framework classification should win).
func tryUpgradeToWebView2App(result *DetectResult) {
	switch result.FileType {
	case TypeElectronApp, TypeTauriApp, TypeGoBinary, TypeBunStandalone,
		TypeUPXPacked, TypeNSIS, TypePyInstaller, TypePyZipApp, TypeAdvancedInstaller:
		return
	}
	if result.Path == "" {
		return
	}
	imports := readPEImportsQuiet(result.Path)
	if len(imports) == 0 {
		return
	}
	if sig := webview2detect.DetectFromImports(imports); sig != nil {
		result.FileType = TypeWebView2App
		result.Category = CategoryBinary
		result.Details = "WebView2 host binary (imports " + sig.Detail + ")"
	}
}

// detectUWPDir flags a directory as TypeUWPApp when an AppxManifest.xml
// is present at the root (FRM-05, FRM-08). Confidence is "confirmed".
func detectUWPDir(result *DetectResult, path string) bool {
	if _, err := os.Stat(filepath.Join(path, "AppxManifest.xml")); err != nil {
		return false
	}
	result.FileType = TypeUWPApp
	result.Category = CategoryAppDirectory
	result.Confidence = ConfidenceHigh
	result.Details = "Contains AppxManifest.xml (UWP/MSIX app)"
	return true
}

// detectWinUIDir flags a directory as TypeWinUIApp when WinUI 3 or
// WindowsAppSDK markers are present (FRM-05). Checked AFTER UWP because
// a packaged WinUI 3 app will satisfy both predicates and the AppxManifest
// signal is the higher-fidelity classification.
func detectWinUIDir(result *DetectResult, path string) bool {
	if _, err := os.Stat(filepath.Join(path, "Microsoft.UI.Xaml.dll")); err == nil {
		result.FileType = TypeWinUIApp
		result.Category = CategoryAppDirectory
		result.Confidence = ConfidenceHigh
		result.Details = "Contains Microsoft.UI.Xaml.dll (WinUI 3)"
		return true
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".deps.json") {
			continue
		}
		if strings.Contains(name, "Microsoft.WinUI") ||
			strings.Contains(name, "Microsoft.WindowsAppSDK") {
			result.FileType = TypeWinUIApp
			result.Category = CategoryAppDirectory
			result.Confidence = ConfidenceHigh
			result.Details = "Contains " + name + " (WinUI 3 / WindowsAppSDK)"
			return true
		}
	}
	return false
}

// detectDotNetDir flags a directory as TypeDotNetService when the .NET
// self-contained app markers are present (sibling *.deps.json AND
// *.runtimeconfig.json) AND `pkg/dotnet.IsWindowsService` reports any
// of: ASP.NET Core framework reference in runtimeconfig, Generic Host
// (Microsoft.Extensions.Hosting) in deps.json, or a `Service`/`Worker`
// suffixed .exe sibling. Otherwise classifies as TypeDotNetApp.
//
// Phase 16 carryover — the dotnet package shipped service-detection
// logic months ago; this is the missing detect.go wiring.
func detectDotNetDir(result *DetectResult, path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}
	hasDeps, hasRC := false, false
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		lower := strings.ToLower(e.Name())
		if strings.HasSuffix(lower, ".deps.json") {
			hasDeps = true
		}
		if strings.HasSuffix(lower, ".runtimeconfig.json") {
			hasRC = true
		}
	}
	if !(hasDeps && hasRC) {
		return false
	}
	result.Category = CategoryAppDirectory
	result.Confidence = ConfidenceHigh
	if dotnet.IsWindowsService(path) {
		result.FileType = TypeDotNetService
		result.Details = "Contains .deps.json + .runtimeconfig.json (Windows service / worker — ASP.NET Core, Generic Host, or *Service.exe)"
	} else {
		result.FileType = TypeDotNetApp
		result.Details = "Contains .deps.json + .runtimeconfig.json (.NET self-contained app)"
	}
	return true
}

// readPEImportsQuiet returns the imported DLL names of a PE file, or nil on
// any error. It never panics (defer/recover guards against malformed PEs —
// T-03-02 DoS mitigation).
func readPEImportsQuiet(path string) (imports []string) {
	defer func() {
		if r := recover(); r != nil {
			imports = nil
		}
	}()
	f, err := pe.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil
	}
	return libs
}
