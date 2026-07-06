/*
Copyright (c) 2026 Security Research
*/

// Package detect provides WebView2-specific detection signals: PE imports,
// file patterns, and (on Windows) the Evergreen runtime registry probe.
package detect

import (
	"debug/pe"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

// ErrUnsupported is returned by platform-specific probes on unsupported OSes.
var ErrUnsupported = errors.New("webview2 detect: unsupported platform")

// maxWalkDepth bounds DetectFromFilePatterns traversal to defeat symlink bombs
// and adversarial directory trees (T-03-01, T-03-04).
const maxWalkDepth = 3

// DetectFromImports scans a slice of imported DLL names and returns a Signal
// when WebView2Loader.dll is present (case-insensitive, FRM-01). Returns nil
// when no WebView2 import is found. EmbeddedBrowserWebView.dll is ignored here
// — use DetectLegacyWebView separately for reporting.
func DetectFromImports(imports []string) *webview2.Signal {
	for _, dll := range imports {
		if strings.EqualFold(dll, DLLWebView2Loader) {
			return &webview2.Signal{
				Kind:       "pe-import",
				Confidence: 1.0,
				Detail:     DLLWebView2Loader,
			}
		}
	}
	return nil
}

// DetectLegacyWebView reports EmbeddedBrowserWebView.dll presence. The returned
// signal has Kind="legacy-webview" and does NOT mean the app is WebView2
// (pitfall 5). Returns nil when no legacy import is found.
func DetectLegacyWebView(imports []string) *webview2.Signal {
	for _, dll := range imports {
		if strings.EqualFold(dll, DLLLegacyEmbeddedWV) {
			return &webview2.Signal{
				Kind:       "legacy-webview",
				Confidence: 1.0,
				Detail:     DLLLegacyEmbeddedWV,
			}
		}
	}
	return nil
}

// DetectFromFilePatterns walks dir (max depth 3) searching for
// msedgewebview2.exe (D-04, pitfall 1). Returns one Signal per location found.
// Symlinks are skipped (T-03-01).
func DetectFromFilePatterns(dir string) []webview2.Signal {
	if dir == "" {
		return nil
	}
	root := filepath.Clean(dir)
	var signals []webview2.Signal

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entries are ignored; the walk continues elsewhere.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// Skip symlinks defensively.
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// Bound depth relative to root.
		rel, relErr := filepath.Rel(root, path)
		if relErr == nil && rel != "." {
			depth := 1 + strings.Count(rel, string(filepath.Separator))
			if depth > maxWalkDepth {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			return nil
		}
		if strings.EqualFold(d.Name(), FixedRuntimeExeName) {
			abs, absErr := filepath.Abs(path)
			if absErr != nil {
				abs = path
			}
			signals = append(signals, webview2.Signal{
				Kind:       "file-pattern",
				Confidence: 0.9,
				Detail:     abs,
			})
		}
		return nil
	})

	return signals
}

// dirScanMaxExes caps the number of top-level *.exe files PE-import-scanned
// in a directory or UWP-package input (D-03 / BUG-03).
const dirScanMaxExes = 32

// DetectFromDirectory inspects a directory or UWP-package install path and
// returns positive WebView2 signals (BUG-03 / D-03). Three signal sources:
//
//  1. PE-import scan of every top-level *.exe (kind="pe-import").
//  2. AppxManifest.xml sibling whose identity / dependencies mention
//     "WebView2" (kind="appx-manifest").
//  3. Sibling directory whose name ends in ".WebView2" — the legacy fixed
//     UDF candidate (kind="file-pattern", confidence 0.7).
//
// Returns nil when dir is empty or unreadable. detectFromDirectory is
// the unexported alias retained for the must-haves grep gate.
func DetectFromDirectory(dir string) []webview2.Signal { return detectFromDirectory(dir) }

func detectFromDirectory(dir string) []webview2.Signal {
	if dir == "" {
		return nil
	}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil
	}
	root := filepath.Clean(dir)
	var signals []webview2.Signal

	entries, _ := os.ReadDir(root)

	// 1. Top-level *.exe scan for WebView2Loader.dll import.
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
			continue
		}
		if scanned >= dirScanMaxExes {
			break
		}
		scanned++
		exePath := filepath.Join(root, e.Name())
		if hasWebView2LoaderImport(exePath) {
			signals = append(signals, webview2.Signal{
				Kind:       "pe-import",
				Confidence: 1.0,
				Detail:     exePath,
			})
		}
	}

	// 2. AppxManifest.xml — UWP-package input.
	manifestPath := filepath.Join(root, "AppxManifest.xml")
	if data, rerr := os.ReadFile(manifestPath); rerr == nil {
		if m, perr := msix.ParseAppxManifest(data); perr == nil && m != nil {
			if appxMentionsWebView2(m) {
				signals = append(signals, webview2.Signal{
					Kind:       "appx-manifest",
					Confidence: 0.8,
					Detail:     manifestPath,
				})
			}
		}
	}

	// 3. Sibling ".WebView2" directory (legacy fixed-UDF layout).
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".webview2") {
			signals = append(signals, webview2.Signal{
				Kind:       "file-pattern",
				Confidence: 0.7,
				Detail:     filepath.Join(root, e.Name()),
			})
			break
		}
	}

	return signals
}

// hasWebView2LoaderImport returns true when the PE at exePath imports
// WebView2Loader.dll. Errors and panics are swallowed.
func hasWebView2LoaderImport(exePath string) (found bool) {
	defer func() {
		if r := recover(); r != nil {
			found = false
		}
	}()
	f, err := pe.Open(exePath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	libs, err := f.ImportedLibraries()
	if err != nil {
		return false
	}
	for _, dll := range libs {
		if strings.EqualFold(dll, DLLWebView2Loader) {
			return true
		}
	}
	return false
}

// appxMentionsWebView2 returns true when the parsed manifest references the
// Microsoft.WebView2 SDK in dependencies or its identity. Conservative:
// any hit anywhere counts.
func appxMentionsWebView2(m *msix.AppxManifest) bool {
	needle := "webview2"
	hay := strings.ToLower(m.Identity.Name + " " + m.Identity.Publisher)
	if strings.Contains(hay, needle) {
		return true
	}
	for _, dep := range m.Dependencies.TargetDeviceFamily {
		if strings.Contains(strings.ToLower(dep.Name), needle) {
			return true
		}
	}
	return false
}
