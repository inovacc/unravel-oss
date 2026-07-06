/*
Copyright (c) 2026 Security Research
*/

package framework

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

var reactNativeLibs = []string{
	"libreactnativejni.so",
	"libreact_nativejni.so",
	"libhermes.so",
	"libhermes-executor.so",
	"libjsc.so",
	"libjscexecutor.so",
	"libv8executor.so",
}

// Hermes bytecode magic: 0xc61fbc03
var hermesMagic = []byte{0xc6, 0x1f, 0xbc, 0x03}

func detectReactNative(entries []zipEntry, classes []string, zr *zip.ReadCloser) *ReactNativeInfo {
	var nativeLibs []string
	var abis []string
	hasJSBundle := false
	var jsBundleSize int64
	var jsBundleName string
	var mapFiles []string
	hasHermesLib := false
	hasJSCLib := false
	hasV8Lib := false

	for _, e := range entries {
		base := libBaseName(e.Name)

		for _, lib := range reactNativeLibs {
			if base == lib {
				nativeLibs = append(nativeLibs, e.Name)
				if abi := extractABI(e.Name); abi != "" {
					abis = append(abis, abi)
				}
				switch base {
				case "libhermes.so", "libhermes-executor.so":
					hasHermesLib = true
				case "libjsc.so", "libjscexecutor.so":
					hasJSCLib = true
				case "libv8executor.so":
					hasV8Lib = true
				}
			}
		}

		// Check for JS bundle
		if base == "index.android.bundle" || base == "index.android.bundle.hbc" {
			hasJSBundle = true
			jsBundleSize = e.Size
			jsBundleName = e.Name
		}

		// Source maps
		if strings.HasSuffix(e.Name, ".map") && strings.Contains(e.Name, "assets/") {
			mapFiles = append(mapFiles, e.Name)
		}
	}

	// Check DEX classes
	hasDEXMarker := false
	var nativeModules []string
	for _, c := range classes {
		cn := strings.TrimPrefix(c, "L")
		if strings.HasPrefix(cn, "com/facebook/react/") || strings.HasPrefix(cn, "com/facebook/hermes/") {
			hasDEXMarker = true
		}
		// Detect native modules
		if strings.HasPrefix(cn, "com/facebook/react/bridge/") {
			continue // skip bridge internals
		}
		if strings.Contains(cn, "Module") && !strings.HasPrefix(cn, "com/facebook/") {
			cn = strings.TrimSuffix(cn, ";")
			parts := strings.Split(cn, "/")
			if len(parts) > 0 {
				name := parts[len(parts)-1]
				if strings.HasSuffix(name, "Module") && len(nativeModules) < 50 {
					nativeModules = append(nativeModules, name)
				}
			}
		}
	}

	if len(nativeLibs) == 0 && !hasJSBundle && !hasDEXMarker {
		return nil
	}

	info := &ReactNativeInfo{
		JSEngine:      detectJSEngine(hasHermesLib, hasJSCLib, hasV8Lib),
		HasJSBundle:   hasJSBundle,
		JSBundleSize:  jsBundleSize,
		HasSourceMap:  len(mapFiles) > 0,
		NativeModules: nativeModules,
		NativeLibs:    nativeLibs,
		ABIs:          uniqueStrings(abis),
	}

	// Try to detect Hermes bytecode from bundle content
	if hasJSBundle && zr != nil {
		if ver, ok := readHermesHeader(zr, jsBundleName); ok {
			if info.JSEngine == "unknown" {
				info.JSEngine = "Hermes"
			}
			info.HermesVersion = ver
		}
	}

	// Extract source map metadata
	if len(mapFiles) > 0 && zr != nil {
		info.SourceMap = extractSourceMapInfo(zr, mapFiles)
	}

	return info
}

func detectJSEngine(hasHermes, hasJSC, hasV8 bool) string {
	if hasHermes {
		return "Hermes"
	}
	if hasJSC {
		return "JSC"
	}
	if hasV8 {
		return "V8"
	}
	return "unknown"
}

// readHermesHeader reads the HBC header and returns (bytecode version string, true) if Hermes.
// HBC format: bytes 0-3 magic (0xc61fbc03), bytes 4-7 bytecode version (uint32 LE).
func readHermesHeader(zr *zip.ReadCloser, name string) (string, bool) {
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", false
		}
		defer func() { _ = rc.Close() }()

		header := make([]byte, 8)
		n, err := io.ReadFull(rc, header)
		if err != nil || n < 8 {
			// Try with just 4 bytes for magic detection
			if n >= 4 && header[0] == hermesMagic[0] && header[1] == hermesMagic[1] &&
				header[2] == hermesMagic[2] && header[3] == hermesMagic[3] {
				return "", true
			}
			return "", false
		}

		if header[0] != hermesMagic[0] || header[1] != hermesMagic[1] ||
			header[2] != hermesMagic[2] || header[3] != hermesMagic[3] {
			return "", false
		}

		ver := binary.LittleEndian.Uint32(header[4:8])
		return fmt.Sprintf("%d", ver), true
	}
	return "", false
}

// sourceMapHeader is a lightweight struct for parsing source map JSON without
// decoding the large "mappings" field.
type sourceMapHeader struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []any    `json:"sourcesContent"`
}

const sourceMapMaxBytes = 2 * 1024 * 1024 // 2MB

// extractSourceMapInfo reads the first source map file and extracts metadata.
func extractSourceMapInfo(zr *zip.ReadCloser, mapFiles []string) *SourceMapInfo {
	info := &SourceMapInfo{
		Files: mapFiles,
	}

	data := readZipEntry(zr, mapFiles[0], sourceMapMaxBytes)
	if data == nil {
		return info
	}

	var header sourceMapHeader
	if err := json.Unmarshal(data, &header); err != nil {
		return info
	}

	info.Version = header.Version
	info.SourceCount = len(header.Sources)

	// Check if sourcesContent has non-null entries
	for _, sc := range header.SourcesContent {
		if sc != nil {
			info.HasSources = true
			break
		}
	}

	// Collect top 20 source paths
	limit := min(len(header.Sources), 20)
	if limit > 0 {
		info.TopSources = make([]string, limit)
		copy(info.TopSources, header.Sources[:limit])
	}

	return info
}
