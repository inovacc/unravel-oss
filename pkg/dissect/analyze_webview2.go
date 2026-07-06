/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"debug/pe"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/webview2"
	"github.com/inovacc/unravel-oss/pkg/webview2/analyze"
	webview2detect "github.com/inovacc/unravel-oss/pkg/webview2/detect"
)

func init() {
	RegisterAnalyzer(analyzeWebView2, detect.TypeWebView2App)
	RegisterSupplementalAnalyzer(analyzeWebView2Supplemental, detect.TypePE)
}

// analyzeWebView2 runs the full WebView2 analysis pipeline: UDF discovery,
// per-profile extraction (cache/LevelDB/Preferences), and runtime detection.
func analyzeWebView2(r *DissectResult, path string, _ Options) {
	r.runStep("webview2 analyze", func(sr *debug.StepRecorder) error {
		res, err := webview2.Analyze(path, analyze.Options{
			ExtractCache:      true,
			ExtractLevelDB:    true,
			ExtractCookies:    true,
			RejectSymlinks:    true,
			MaxProfilesToScan: 8,
		})
		if err != nil {
			return fmt.Errorf("webview2 analysis: %w", err)
		}

		r.WebView2Info = res
		sr.RecordOutput(res)
		return nil
	})
}

// analyzeWebView2Supplemental runs a cheap PE-import signal check for arbitrary
// PE binaries. If WebView2Loader.dll is imported, it delegates to the full
// analyzeWebView2 so hybrid WinUI+WebView2 apps (pitfall 9) are covered.
// Returns early without side effects when the binary does not reference WebView2.
func analyzeWebView2Supplemental(r *DissectResult, path string, opts Options) {
	// Skip if the primary WebView2 analyzer already ran (TypeWebView2App path).
	if r.WebView2Info != nil {
		return
	}

	imports := peImportsQuiet(path)
	if len(imports) == 0 {
		return
	}

	sig := webview2detect.DetectFromImports(imports)
	if sig == nil {
		return
	}

	// Positive signal found — run the full WebView2 analyzer.
	analyzeWebView2(r, path, opts)
}

// peImportsQuiet returns DLL import names from a PE file, or nil on error.
// Swallows errors; used by the supplemental analyzer to avoid penalizing
// non-WebView2 PE binaries with noisy logs.
func peImportsQuiet(path string) (imports []string) {
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

	names, err := f.ImportedLibraries()
	if err != nil {
		return nil
	}
	return names
}
