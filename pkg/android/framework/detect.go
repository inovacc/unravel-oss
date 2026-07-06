/*
Copyright (c) 2026 Security Research
*/

package framework

import (
	"archive/zip"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

// ScanAPK detects the framework used to build an APK by inspecting its ZIP entries and DEX classes.
func ScanAPK(apkPath string, dexResult *dex.ParseResult) (*ScanResult, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	entries := make([]zipEntry, 0, len(zr.File))
	for _, f := range zr.File {
		entries = append(entries, zipEntry{
			Name: f.Name,
			Size: int64(f.UncompressedSize64),
		})
	}

	var classes []string
	if dexResult != nil {
		for _, df := range dexResult.DexFiles {
			for _, c := range df.Classes {
				classes = append(classes, c.ClassName)
			}
		}
	}

	result := &ScanResult{}

	if info := detectFlutter(entries, classes, zr); info != nil {
		result.Framework = "Flutter"
		result.Flutter = info
		return result, nil
	}

	if info := detectReactNative(entries, classes, zr); info != nil {
		result.Framework = "React Native"
		result.ReactNative = info
		return result, nil
	}

	if info := detectXamarin(entries, classes); info != nil {
		result.Framework = "Xamarin"
		result.Xamarin = info
		return result, nil
	}

	return result, nil
}

type zipEntry struct {
	Name string
	Size int64
}

// extractABI returns the ABI from a lib/ path, e.g. "lib/arm64-v8a/libfoo.so" -> "arm64-v8a".
func extractABI(name string) string {
	if !strings.HasPrefix(name, "lib/") {
		return ""
	}
	parts := strings.SplitN(name, "/", 3)
	if len(parts) >= 3 {
		return parts[1]
	}
	return ""
}

// libBaseName returns the file name from a path.
func libBaseName(name string) string {
	return filepath.Base(name)
}

// uniqueStrings deduplicates a string slice preserving order.
func uniqueStrings(ss []string) []string {
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
