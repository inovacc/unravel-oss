/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/debug"
	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

func TestWebView2AnalyzerRegistered(t *testing.T) {
	if !HasAnalyzer(detect.TypeWebView2App) {
		t.Fatal("primary analyzer not registered for detect.TypeWebView2App")
	}
	// Supplemental analyzers are registered on TypePE; verify indirectly via the
	// fact that the PE analyzer table is non-empty (we cannot introspect
	// supplementalTable without an accessor, so a smoke check is acceptable).
	if _, ok := supplementalTable[detect.TypePE]; !ok {
		t.Fatal("supplemental analyzer not registered for detect.TypePE")
	}
}

func TestDissectWebView2App(t *testing.T) {
	r := &DissectResult{debugRec: debug.NopRecorder()}
	// Point at a non-existent path. webview2.Analyze should still return a Result
	// (never errors fatally — UDF-not-found is information), so r.WebView2Info
	// should be non-nil after the call.
	analyzeWebView2(r, "C:/nonexistent/webview2-host.exe", Options{})

	if r.WebView2Info == nil {
		t.Fatal("analyzeWebView2 did not populate r.WebView2Info")
	}
}

func TestDissectWebView2Supplemental(t *testing.T) {
	r := &DissectResult{debugRec: debug.NopRecorder()}
	// Non-existent PE file → peImportsQuiet returns nil → supplemental returns early.
	analyzeWebView2Supplemental(r, "C:/nonexistent/random-binary.exe", Options{})

	if r.WebView2Info != nil {
		t.Fatal("supplemental analyzer should skip non-WebView2 binaries; WebView2Info set unexpectedly")
	}
	if len(r.Errors) != 0 {
		t.Fatalf("supplemental analyzer should be silent on non-match; got errors: %v", r.Errors)
	}
}

func TestDissectWebView2SupplementalSkipsIfAlreadyRun(t *testing.T) {
	// If WebView2Info is already populated (primary analyzer ran), supplemental
	// must not re-run. We simulate this by pre-populating the field.
	r := &DissectResult{debugRec: debug.NopRecorder()}
	r.WebView2Info = &webview2.Result{}
	prev := r.WebView2Info
	analyzeWebView2Supplemental(r, "C:/nonexistent/binary.exe", Options{})
	if r.WebView2Info != prev {
		t.Fatal("supplemental analyzer overwrote existing WebView2Info")
	}
}
