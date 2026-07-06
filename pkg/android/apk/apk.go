/*
Copyright (c) 2026 Security Research
*/
package apk

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/internal/boundedzip"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
)

// FormatType identifies the Android package format.
type FormatType string

const (
	FormatAPK   FormatType = "APK"
	FormatAAB   FormatType = "AAB"
	FormatSplit FormatType = "Split"
	FormatXAPK  FormatType = "XAPK"
	FormatAPKS  FormatType = "APKS"
	FormatAPKM  FormatType = "APKM"
)

// Entry represents a single file inside an APK archive.
type Entry struct {
	Name           string `json:"name"`
	Size           int64  `json:"size"`
	CompressedSize int64  `json:"compressed_size"`
	Method         string `json:"method"`
	CRC32          uint32 `json:"crc32"`
	IsDir          bool   `json:"is_dir"`
	Category       string `json:"category"`
}

// InfoResult contains metadata about an APK file.
type InfoResult struct {
	Path             string         `json:"path"`
	FileName         string         `json:"file_name"`
	Size             int64          `json:"size"`
	Format           FormatType     `json:"format"`
	TotalFiles       int            `json:"total_files"`
	TotalDirs        int            `json:"total_dirs"`
	UncompressedSize int64          `json:"uncompressed_size"`
	HasManifest      bool           `json:"has_manifest"`
	DEXFiles         []string       `json:"dex_files"`
	DEXCount         int            `json:"dex_count"`
	NativeLibs       map[string]int `json:"native_libs"`
	HasResources     bool           `json:"has_resources"`
	HasAssets        bool           `json:"has_assets"`
	HasKotlin        bool           `json:"has_kotlin"`
	HasSignature     bool           `json:"has_signature"`
	SignatureSchemes []string       `json:"signature_schemes,omitempty"`
	SplitAPKs        []string       `json:"split_apks,omitempty"`
	BundleInfo       *BundleInfo    `json:"bundle_info,omitempty"`
	Entries          []Entry        `json:"entries,omitempty"`

	// Permissions and Components are empty from the thin Info() parse — Info
	// only inspects the ZIP central directory, it does not decode the binary
	// manifest. The dissect pipeline reconciles these from the full manifest
	// analyzer result (androidmanifest.ParseAPK) after both have run, so
	// consumers reading the typed APKInfo fields see complete data instead of
	// an empty list. See reconcileAPKInfo in pkg/dissect/analyze_apk.go.
	Permissions []androidmanifest.Permission `json:"permissions,omitempty"`
	Components  []androidmanifest.Component  `json:"components,omitempty"`
}

// BundleInfo holds metadata from APKM/XAPK info.json or similar bundle metadata.
type BundleInfo struct {
	PackageName string `json:"package_name,omitempty"`
	VersionName string `json:"version_name,omitempty"`
	VersionCode int64  `json:"version_code,omitempty"`
	MinSDK      int    `json:"min_sdk,omitempty"`
	TargetSDK   int    `json:"target_sdk,omitempty"`
	ABIs        string `json:"abis,omitempty"`
	IconFile    string `json:"icon_file,omitempty"`
}

// ExtractReport summarizes an extraction operation.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Format      string   `json:"format"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors,omitempty"`
}

// Info opens an APK file and returns metadata about its contents.
func Info(apkPath string, includeEntries bool) (*InfoResult, error) {
	absPath, err := filepath.Abs(apkPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	zr, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	format, _ := detectFormatFromZip(zr.Reader)

	result := &InfoResult{
		Path:       absPath,
		FileName:   filepath.Base(absPath),
		Size:       stat.Size(),
		Format:     format,
		NativeLibs: make(map[string]int),
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			result.TotalDirs++
			if includeEntries {
				result.Entries = append(result.Entries, Entry{
					Name:  f.Name,
					IsDir: true,
				})
			}

			continue
		}

		result.TotalFiles++
		result.UncompressedSize += int64(f.UncompressedSize64)

		cat := categorizeEntry(f.Name)

		if includeEntries {
			method := "Deflate"
			if f.Method == zip.Store {
				method = "Store"
			}

			result.Entries = append(result.Entries, Entry{
				Name:           f.Name,
				Size:           int64(f.UncompressedSize64),
				CompressedSize: int64(f.CompressedSize64),
				Method:         method,
				CRC32:          f.CRC32,
				Category:       cat,
			})
		}

		switch cat {
		case "manifest":
			result.HasManifest = true
		case "dex":
			result.DEXFiles = append(result.DEXFiles, f.Name)
		case "native":
			abi := extractABI(f.Name)
			if abi != "" {
				result.NativeLibs[abi]++
			}
		case "resource":
			result.HasResources = true
		case "asset":
			result.HasAssets = true
		case "kotlin":
			result.HasKotlin = true
		case "meta":
			// Check for signature files
			name := filepath.Base(f.Name)
			if strings.HasSuffix(name, ".RSA") || strings.HasSuffix(name, ".DSA") ||
				strings.HasSuffix(name, ".EC") || strings.HasSuffix(name, ".SF") {
				result.HasSignature = true
			}
		}
	}

	result.DEXCount = len(result.DEXFiles)

	// For bundle formats (APKM, XAPK), collect split APKs and parse metadata
	if format == FormatAPKM || format == FormatXAPK {
		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, ".apk") {
				result.SplitAPKs = append(result.SplitAPKs, f.Name)
			}
		}

		result.BundleInfo = parseInfoJSON(zr.Reader)
	}

	// Check for v2/v3 signing block
	schemes := detectSignatureSchemes(absPath, zr.Reader)

	result.SignatureSchemes = schemes
	if len(schemes) > 0 {
		result.HasSignature = true
	} else if result.HasSignature {
		result.SignatureSchemes = []string{"v1"}
	}

	return result, nil
}

// Extract extracts all files from an APK to the given output directory.
func Extract(apkPath, outputDir string, verbose bool) (*ExtractReport, error) {
	absPath, err := filepath.Abs(apkPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	zr, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	format, _ := detectFormatFromZip(zr.Reader)

	if outputDir == "" {
		base := filepath.Base(absPath)
		outputDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	}

	report := &ExtractReport{
		Source: absPath,
		Output: outputDir,
		Format: string(format),
	}

	for _, f := range zr.File {
		// Skip symlink entries to prevent TOCTOU symlink-escape attacks.
		if f.Mode()&os.ModeSymlink != 0 {
			report.Errors = append(report.Errors, fmt.Sprintf("skipped (symlink): %s", f.Name))
			continue
		}

		target := filepath.Join(outputDir, f.Name)

		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(outputDir)+string(os.PathSeparator)) {
			report.Errors = append(report.Errors, fmt.Sprintf("skipped (zip slip): %s", f.Name))
			continue
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("mkdir %s: %v", f.Name, err))
			}

			report.Directories++

			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("mkdir parent %s: %v", f.Name, err))
			continue
		}

		if err := extractFile(f, target); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("extract %s: %v", f.Name, err))
			continue
		}

		report.Files++
		report.TotalSize += int64(f.UncompressedSize64)
	}

	return report, nil
}

// DetectFormat checks the format of an APK-like file.
func DetectFormat(path string) (FormatType, error) {
	zr, err := boundedzip.OpenReader(path, boundedzip.DefaultOptions())
	if err != nil {
		return "", fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = zr.Close() }()

	return detectFormatFromZip(zr.Reader)
}

func detectFormatFromZip(zr *zip.Reader) (FormatType, error) {
	hasManifest := false
	hasBundleConfig := false
	hasBase := false
	hasManifestJSON := false
	hasTocPB := false
	hasInfoJSON := false
	hasBaseAPK := false
	hasSplitAPK := false

	for _, f := range zr.File {
		name := f.Name
		switch {
		case name == "AndroidManifest.xml":
			hasManifest = true
		case name == "BundleConfig.pb":
			hasBundleConfig = true
		case strings.HasPrefix(name, "base/"):
			hasBase = true
		case name == "manifest.json":
			hasManifestJSON = true
		case name == "toc.pb":
			hasTocPB = true
		case name == "info.json":
			hasInfoJSON = true
		case name == "base.apk":
			hasBaseAPK = true
		case strings.HasSuffix(name, ".apk") && strings.HasPrefix(name, "split_"):
			hasSplitAPK = true
		}
	}

	switch {
	case hasTocPB:
		return FormatAPKS, nil
	case hasInfoJSON && hasBaseAPK:
		// APKM from APK Mirror: contains info.json + base.apk + split_*.apk
		return FormatAPKM, nil
	case hasManifestJSON:
		return FormatXAPK, nil
	case hasBundleConfig && hasBase:
		return FormatAAB, nil
	case hasManifest:
		if hasSplitAPK {
			return FormatSplit, nil
		}

		return FormatAPK, nil
	case hasBaseAPK:
		// APKM variant without info.json
		return FormatAPKM, nil
	default:
		return "", fmt.Errorf("not an Android package")
	}
}

func categorizeEntry(name string) string {
	switch {
	case name == "AndroidManifest.xml":
		return "manifest"
	case strings.HasPrefix(name, "classes") && strings.HasSuffix(name, ".dex"):
		return "dex"
	case strings.HasPrefix(name, "lib/") && strings.HasSuffix(name, ".so"):
		return "native"
	case strings.HasPrefix(name, "res/") || name == "resources.arsc":
		return "resource"
	case strings.HasPrefix(name, "assets/"):
		return "asset"
	case strings.HasPrefix(name, "META-INF/"):
		return "meta"
	case strings.HasPrefix(name, "kotlin/"):
		return "kotlin"
	default:
		return "other"
	}
}

func extractABI(name string) string {
	// lib/<abi>/libfoo.so
	parts := strings.Split(name, "/")
	if len(parts) >= 3 && parts[0] == "lib" {
		return parts[1]
	}

	return ""
}

func detectSignatureSchemes(apkPath string, zr *zip.Reader) []string {
	var schemes []string

	// Check v1 (JAR signing)
	hasManifestMF := false
	hasSF := false
	hasRSA := false

	for _, f := range zr.File {
		base := filepath.Base(f.Name)

		dir := filepath.Dir(f.Name)
		if dir != "META-INF" {
			continue
		}

		switch {
		case base == "MANIFEST.MF":
			hasManifestMF = true
		case strings.HasSuffix(base, ".SF"):
			hasSF = true
		case strings.HasSuffix(base, ".RSA") || strings.HasSuffix(base, ".DSA") || strings.HasSuffix(base, ".EC"):
			hasRSA = true
		}
	}

	if hasManifestMF && hasSF && hasRSA {
		schemes = append(schemes, "v1")
	}

	// Check v2/v3 from signing block
	f, err := os.Open(apkPath)
	if err != nil {
		return schemes
	}

	defer func() { _ = f.Close() }()

	offset, size, err := findSigningBlock(f)
	if err != nil {
		return schemes
	}

	pairs, err := parseSigningBlock(f, offset, size)
	if err != nil {
		return schemes
	}

	if _, ok := pairs[0x7109871a]; ok {
		schemes = append(schemes, "v2")
	}

	if _, ok := pairs[0xf05368c0]; ok {
		schemes = append(schemes, "v3")
	}

	// Check v4
	if _, err := os.Stat(apkPath + ".idsig"); err == nil {
		schemes = append(schemes, "v4")
	}

	return schemes
}

func extractFile(f *zip.File, target string) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}

	defer func() { _ = out.Close() }()

	const maxExtractedFileBytes = 512 << 20 // 512 MiB per-file cap
	_, err = io.Copy(out, io.LimitReader(rc, maxExtractedFileBytes))

	return err
}

// parseInfoJSON reads and parses info.json from an APKM/XAPK bundle.
// APK Mirror's info.json typically contains:
//
//	{"pn":"com.example.app","vc":123,"vn":"1.2.3","mn":21,"tn":34,...}
func parseInfoJSON(zr *zip.Reader) *BundleInfo {
	for _, f := range zr.File {
		if f.Name != "info.json" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return nil
		}

		data, err := io.ReadAll(rc)
		_ = rc.Close()

		if err != nil {
			return nil
		}

		// Parse flexible JSON - APK Mirror uses short keys
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil
		}

		info := &BundleInfo{}

		// Try standard keys first, then APK Mirror short keys
		info.PackageName = jsonString(raw, "package_name", "pn")
		info.VersionName = jsonString(raw, "version_name", "vn")
		info.VersionCode = jsonInt(raw, "version_code", "vc")
		info.MinSDK = int(jsonInt(raw, "min_sdk_version", "mn"))
		info.TargetSDK = int(jsonInt(raw, "target_sdk_version", "tn"))
		info.ABIs = jsonString(raw, "abis", "arches")

		// Check for icon
		for _, zf := range zr.File {
			if strings.HasSuffix(zf.Name, ".png") && strings.Contains(zf.Name, "icon") {
				info.IconFile = zf.Name
				break
			}
		}

		return info
	}

	return nil
}

func jsonString(raw map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			var s string
			if json.Unmarshal(v, &s) == nil {
				return s
			}
		}
	}

	return ""
}

func jsonInt(raw map[string]json.RawMessage, keys ...string) int64 {
	for _, k := range keys {
		if v, ok := raw[k]; ok {
			var n int64
			if json.Unmarshal(v, &n) == nil {
				return n
			}
		}
	}

	return 0
}

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(size int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(gb))
	case size >= mb:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
	case size >= kb:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}
