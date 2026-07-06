/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"
	"github.com/inovacc/unravel-oss/pkg/webview2/udf"
)

// dllWebView2Loader is duplicated locally to avoid importing
// pkg/webview2/detect (which already imports this package — cycle).
const dllWebView2Loader = "WebView2Loader.dll"

// dirScanMaxExesAnalyze caps top-level *.exe imports scanned in directory mode.
const dirScanMaxExesAnalyze = 32

// Analyze composes detection, UDF discovery, profile enumeration, data
// extraction, and runtime detection into a single Result. It is the
// top-level public entrypoint for WebView2 analysis (FRM-02).
//
// The caller always receives a Result — even when IsWebView2=false — so
// downstream tools can inspect Signals, UDF candidates, and runtime info
// independently of the positive-detection verdict.
func Analyze(exePath string, opts analyze.Options) (*Result, error) {
	res := &Result{}

	// Detection (BUG-03 / D-03): set IsWebView2 + Signals based on whether
	// the input is a single PE, a directory, or a UWP-package install dir.
	if exePath != "" {
		signals := detectSignals(exePath)
		for _, s := range signals {
			res.Signals = append(res.Signals, s)
			if s.Kind == "pe-import" || s.Kind == "appx-manifest" || s.Kind == "file-pattern" {
				// Any positive signal flips the verdict; legacy-webview is
				// emitted with its own kind elsewhere (not here) so does
				// not contribute.
				res.IsWebView2 = true
			}
		}
	}

	// UDF discovery (always attempted). Threads the caller's udf_override
	// through so the resolver can prepend it as Source="override" (D-02).
	udfs, err := udf.DiscoverUDFsWithOptions(exePath, udf.DiscoverOptions{
		Override: opts.UDFOverride,
	})
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("udf discover: %v", err))
	}
	for _, u := range udfs {
		res.UDFs = append(res.UDFs, UDFInfo{Path: u.Path, Source: u.Source, Exists: u.Exists})
		// A resolved EBWebView dir under %LOCALAPPDATA%\Packages\<PFN>\
		// LocalCache is itself definitive WebView2 evidence (BUG-03):
		// the package would not write that subtree otherwise. This rescues
		// the verdict when WindowsApps PE/AppxManifest scans are blocked
		// by ACLs.
		if u.Exists && u.Source == "uwp-localcache" {
			res.Signals = append(res.Signals, Signal{
				Kind:       "uwp-localcache",
				Confidence: 0.95,
				Detail:     u.Path,
			})
			res.IsWebView2 = true
		}
	}

	// Per-UDF extraction.
	for _, u := range udfs {
		if !u.Exists {
			continue
		}
		sub, aerr := analyze.Analyze(u.Path, opts)
		if aerr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("analyze %s: %v", u.Path, aerr))
			continue
		}
		for _, p := range sub.Profiles {
			res.Profiles = append(res.Profiles, ProfileInfo{Name: p.Name, Path: p.Path})
		}
		for _, pb := range sub.ProfileData {
			res.ProfileData = append(res.ProfileData, pb)
		}
		for _, rj := range sub.RecoveredJS {
			res.RecoveredJS = append(res.RecoveredJS, rj)
		}
		for _, rc := range sub.RecoveredCSS {
			res.RecoveredCSS = append(res.RecoveredCSS, rc)
		}
	}

	// Runtime detection relative to the exe (or directory input).
	if exePath != "" {
		rtRoot := exePath
		if st, serr := os.Stat(exePath); serr == nil && !st.IsDir() {
			rtRoot = filepath.Dir(exePath)
		}
		rt, rterr := analyze.DetectRuntime(rtRoot)
		if rterr != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("runtime detect: %v", rterr))
		}
		res.Runtime = RuntimeInfo{Mode: rt.Mode, Version: rt.Version, InstallDir: rt.InstallDir}
	}

	return res, nil
}

// detectSignals dispatches detection based on whether path points at a single
// PE file, a directory, or a UWP-package install (directory containing
// AppxManifest.xml). Aggregates positive WebView2 signals (BUG-03 / D-03).
func detectSignals(path string) []Signal {
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if !st.IsDir() {
		// Single PE input — scan its imports directly.
		if hasWebView2LoaderImport(path) {
			return []Signal{{Kind: "pe-import", Confidence: 1.0, Detail: path}}
		}
		return nil
	}
	return detectFromDirectoryLocal(path)
}

// detectFromDirectoryLocal mirrors detect.DetectFromDirectory; declared in
// this package to avoid an import cycle with pkg/webview2/detect.
func detectFromDirectoryLocal(dir string) []Signal {
	root := filepath.Clean(dir)
	var signals []Signal

	entries, _ := os.ReadDir(root)

	// 1. Top-level *.exe scan for WebView2Loader.dll import.
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".exe") {
			continue
		}
		if scanned >= dirScanMaxExesAnalyze {
			break
		}
		scanned++
		exePath := filepath.Join(root, e.Name())
		if hasWebView2LoaderImport(exePath) {
			signals = append(signals, Signal{
				Kind:       "pe-import",
				Confidence: 1.0,
				Detail:     exePath,
			})
		}
	}

	// 2. AppxManifest.xml — UWP package input.
	manifestPath := filepath.Join(root, "AppxManifest.xml")
	if data, rerr := os.ReadFile(manifestPath); rerr == nil {
		if m, perr := msix.ParseAppxManifest(data); perr == nil && m != nil {
			if appxMentionsWebView2Local(m) {
				signals = append(signals, Signal{
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
			signals = append(signals, Signal{
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
// WebView2Loader.dll. All errors are swallowed — caller treats as best-effort.
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
		if strings.EqualFold(dll, dllWebView2Loader) {
			return true
		}
	}
	return false
}

// appxMentionsWebView2Local mirrors detect.appxMentionsWebView2.
func appxMentionsWebView2Local(m *msix.AppxManifest) bool {
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
