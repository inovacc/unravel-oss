/*
Copyright (c) 2026 Security Research
*/

// Package analyze orchestrates WebView2 data extraction by delegating to the
// existing Chromium parsers (pkg/cache, pkg/leveldb, pkg/chromium). It adds
// no new binary-format parsing — it is pure orchestration (D-06/D-07/D-08,
// FRM-02, anti-pattern).
package analyze

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// RuntimeInfo describes the WebView2 runtime targeted by a host. Local to
// the analyze package to avoid an import cycle with the parent webview2
// package; webview2.Analyze converts this to the public RuntimeInfo.
type RuntimeInfo struct {
	// Mode is one of: "evergreen" | "fixed" | "unknown".
	Mode       string `json:"mode"`
	Version    string `json:"version,omitempty"`
	InstallDir string `json:"install_dir,omitempty"`
}

// maxRuntimeWalkDepth bounds DetectRuntime filesystem walk to defeat symlink
// bombs and adversarial trees (T-03-09, V12 ASVS).
const maxRuntimeWalkDepth = 4

// DetectRuntime determines whether the host uses a fixed (bundled)
// msedgewebview2.exe or the Evergreen runtime (pitfall 1, D-05).
//
// Resolution order:
//  1. Walk appDir (depth <= 4, skip symlinks) for msedgewebview2.exe → "fixed"
//  2. Fall back to the platform Evergreen registry probe → "evergreen"
//  3. Otherwise Mode="unknown"
//
// Never returns an error for the not-found case — absence is information,
// not a failure.
func DetectRuntime(appDir string) (RuntimeInfo, error) {
	if appDir != "" {
		if installDir, ok := findFixedRuntime(appDir); ok {
			return RuntimeInfo{
				Mode:       "fixed",
				InstallDir: installDir,
			}, nil
		}
	}
	if info, ok := detectEvergreen(); ok {
		return info, nil
	}
	return RuntimeInfo{Mode: "unknown"}, nil
}

// findFixedRuntime walks appDir (bounded depth, skipping symlinks) for
// msedgewebview2.exe. Returns the containing directory and true on first hit.
func findFixedRuntime(appDir string) (string, bool) {
	root := filepath.Clean(appDir)
	var found string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if rel, relErr := filepath.Rel(root, path); relErr == nil && rel != "." {
			depth := 1 + strings.Count(rel, string(filepath.Separator))
			if depth > maxRuntimeWalkDepth {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(d.Name(), "msedgewebview2.exe") {
			found = filepath.Dir(path)
			return fs.SkipAll
		}
		return nil
	})
	if found == "" {
		return "", false
	}
	return found, true
}
