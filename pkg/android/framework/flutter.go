/*
Copyright (c) 2026 Security Research
*/

package framework

import (
	"archive/zip"
	"encoding/binary"
	"io"
	"regexp"
	"strings"
)

var flutterNativeLibs = []string{"libflutter.so", "libapp.so"}

var flutterSnapshotNames = []string{
	"kernel_blob.bin",
	"vm_snapshot_data",
	"vm_snapshot_instr",
	"isolate_snapshot_data",
	"isolate_snapshot_instr",
}

// maxFlutterRead is the max bytes to read from libflutter.so for version scanning.
const maxFlutterRead = 4 * 1024 * 1024

// maxSnapshotRead is the max bytes to read from vm_snapshot_data header.
const maxSnapshotRead = 256

var semverRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func detectFlutter(entries []zipEntry, classes []string, zr *zip.ReadCloser) *FlutterInfo {
	var nativeLibs []string
	var abis []string
	var snapshotFiles []string
	hasAssetManifest := false
	hasFlutterAssets := false

	for _, e := range entries {
		base := libBaseName(e.Name)

		// Check native libs
		for _, lib := range flutterNativeLibs {
			if base == lib {
				nativeLibs = append(nativeLibs, e.Name)
				if abi := extractABI(e.Name); abi != "" {
					abis = append(abis, abi)
				}
			}
		}

		// Check flutter_assets directory
		if strings.HasPrefix(e.Name, "assets/flutter_assets/") {
			hasFlutterAssets = true
			if base == "AssetManifest.json" || base == "AssetManifest.bin" {
				hasAssetManifest = true
			}
		}

		// Check snapshot files
		for _, snap := range flutterSnapshotNames {
			if base == snap {
				snapshotFiles = append(snapshotFiles, e.Name)
			}
		}
	}

	// Check DEX classes for Flutter
	hasDEXMarker := false
	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.HasPrefix(cn, "io/flutter/") {
			hasDEXMarker = true
			break
		}
	}

	if len(nativeLibs) == 0 && !hasFlutterAssets && !hasDEXMarker {
		return nil
	}

	info := &FlutterInfo{
		NativeLibs:       nativeLibs,
		ABIs:             uniqueStrings(abis),
		SnapshotFiles:    snapshotFiles,
		HasAssetManifest: hasAssetManifest,
	}

	// Detect obfuscation: if libapp.so exists but no snapshot data, Dart code is compiled into it
	hasLibApp := false
	hasSnapshot := false
	for _, lib := range nativeLibs {
		if libBaseName(lib) == "libapp.so" {
			hasLibApp = true
		}
	}
	for _, snap := range snapshotFiles {
		base := libBaseName(snap)
		if base == "isolate_snapshot_data" || base == "vm_snapshot_data" {
			hasSnapshot = true
		}
	}
	info.IsObfuscated = hasLibApp && !hasSnapshot

	// Extract plugins from AssetManifest
	info.Plugins = detectFlutterPlugins(classes)

	// Extract version information from binary data
	if zr != nil {
		info.EngineVersion = extractFlutterEngineVersion(zr, nativeLibs)
		info.DartVersion = extractDartVersion(zr, snapshotFiles)
	}

	return info
}

// extractFlutterEngineVersion reads libflutter.so and scans for a semver string.
func extractFlutterEngineVersion(zr *zip.ReadCloser, nativeLibs []string) string {
	for _, lib := range nativeLibs {
		if libBaseName(lib) != "libflutter.so" {
			continue
		}
		data := readZipEntry(zr, lib, maxFlutterRead)
		if data == nil {
			continue
		}
		return findVersionNearFlutter(data)
	}
	return ""
}

// findVersionNearFlutter scans binary data for a semver pattern near "Flutter" text.
func findVersionNearFlutter(data []byte) string {
	// Find all semver matches and pick the one closest to a "Flutter" occurrence.
	matches := semverRe.FindAllIndex(data, -1)
	if len(matches) == 0 {
		return ""
	}

	// Find "Flutter" occurrences
	flutterPositions := findAllOccurrences(data, []byte("Flutter"))

	if len(flutterPositions) == 0 {
		// No "Flutter" text found; return first semver as fallback
		return string(data[matches[0][0]:matches[0][1]])
	}

	// Find the semver closest to any "Flutter" string (within 256 bytes)
	bestMatch := ""
	bestDist := int(^uint(0) >> 1)

	for _, m := range matches {
		for _, fp := range flutterPositions {
			dist := m[0] - fp
			if dist < 0 {
				dist = -dist
			}
			if dist < bestDist {
				bestDist = dist
				bestMatch = string(data[m[0]:m[1]])
			}
		}
	}

	if bestDist <= 256 {
		return bestMatch
	}

	return ""
}

// findAllOccurrences returns start indices of needle in haystack.
func findAllOccurrences(haystack, needle []byte) []int {
	var positions []int
	s := string(haystack)
	n := string(needle)
	start := 0
	for {
		idx := strings.Index(s[start:], n)
		if idx < 0 {
			break
		}
		positions = append(positions, start+idx)
		start += idx + len(n)
	}
	return positions
}

// extractDartVersion reads vm_snapshot_data and extracts the Dart version from its header.
// Dart VM snapshot format: 4-byte magic, then version string data.
func extractDartVersion(zr *zip.ReadCloser, snapshotFiles []string) string {
	for _, snap := range snapshotFiles {
		if libBaseName(snap) != "vm_snapshot_data" {
			continue
		}
		data := readZipEntry(zr, snap, maxSnapshotRead)
		if data == nil || len(data) < 8 {
			continue
		}

		// Check for Dart snapshot magic (0xf5f5dcdc LE for 64-bit, 0xf5f5dcd5 for 32-bit)
		magic := binary.LittleEndian.Uint32(data[:4])
		if magic != 0xf5f5dcdc && magic != 0xf5f5dcd5 {
			// Fallback: scan raw bytes for semver
			if m := semverRe.Find(data); m != nil {
				return string(m)
			}
			continue
		}

		// After magic, scan for version string in the header region
		if m := semverRe.Find(data[4:]); m != nil {
			return string(m)
		}
	}
	return ""
}

// readZipEntry reads up to maxBytes from a ZIP entry by name.
func readZipEntry(zr *zip.ReadCloser, name string, maxBytes int) []byte {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		defer func() { _ = rc.Close() }()

		data := make([]byte, maxBytes)
		n, err := io.ReadFull(rc, data)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil
		}
		return data[:n]
	}
	return nil
}

// detectFlutterPlugins infers Flutter plugins from DEX class names.
func detectFlutterPlugins(classes []string) []string {
	pluginSet := make(map[string]bool)
	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		cn = strings.TrimSuffix(cn, ";")
		if strings.HasPrefix(cn, "io/flutter/plugins/") {
			// io/flutter/plugins/camera/CameraPlugin -> camera
			parts := strings.Split(cn, "/")
			if len(parts) >= 4 {
				pluginSet[parts[3]] = true
			}
		}
	}

	if len(pluginSet) == 0 {
		return nil
	}

	plugins := make([]string, 0, len(pluginSet))
	for p := range pluginSet {
		plugins = append(plugins, p)
	}
	return plugins
}
