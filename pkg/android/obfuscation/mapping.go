/*
Copyright (c) 2026 Security Research
*/
package obfuscation

import (
	"archive/zip"
)

// knownMappingPaths lists the common locations for ProGuard/R8 mapping files
// inside an APK archive.
var knownMappingPaths = []string{
	"proguard/mapping.txt",
	"mapping.txt",
	"META-INF/proguard/mapping.txt",
}

// DetectMapping opens the APK at the given path and returns true if it
// contains a ProGuard or R8 mapping file.
func DetectMapping(apkPath string) bool {
	r, err := zip.OpenReader(apkPath)
	if err != nil {
		return false
	}
	defer func() { _ = r.Close() }()

	entries := make(map[string]struct{}, len(r.File))
	for _, f := range r.File {
		entries[f.Name] = struct{}{}
	}

	for _, path := range knownMappingPaths {
		if _, ok := entries[path]; ok {
			return true
		}
	}

	return false
}
