/*
Copyright (c) 2026 Security Research
*/

package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPEImportSignal(t *testing.T) {
	tests := []struct {
		name    string
		imports []string
		want    bool
		detail  string
	}{
		{"canonical casing", []string{"KERNEL32.dll", "WebView2Loader.dll"}, true, "WebView2Loader.dll"},
		{"all lower", []string{"kernel32.dll", "webview2loader.dll"}, true, "WebView2Loader.dll"},
		{"mixed casing", []string{"KERNEL32.dll", "webview2loader.DLL"}, true, "WebView2Loader.dll"},
		{"no webview2 imports", []string{"KERNEL32.dll", "USER32.dll"}, false, ""},
		{"empty slice", nil, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := DetectFromImports(tt.imports)
			if tt.want {
				if sig == nil {
					t.Fatalf("expected signal, got nil")
				}
				if sig.Kind != "pe-import" {
					t.Errorf("Kind = %q, want pe-import", sig.Kind)
				}
				if sig.Confidence != 1.0 {
					t.Errorf("Confidence = %v, want 1.0", sig.Confidence)
				}
				if sig.Detail != tt.detail {
					t.Errorf("Detail = %q, want %q", sig.Detail, tt.detail)
				}
			} else if sig != nil {
				t.Errorf("expected nil signal, got %+v", sig)
			}
		})
	}
}

func TestLegacyWebViewNotMatched(t *testing.T) {
	imports := []string{"KERNEL32.dll", "EmbeddedBrowserWebView.dll"}

	if sig := DetectFromImports(imports); sig != nil {
		t.Errorf("DetectFromImports should NOT flag legacy WebView: got %+v", sig)
	}

	legacy := DetectLegacyWebView(imports)
	if legacy == nil {
		t.Fatalf("DetectLegacyWebView should report a signal")
	}
	if legacy.Kind != "legacy-webview" {
		t.Errorf("Kind = %q, want legacy-webview", legacy.Kind)
	}
	if legacy.Detail != "EmbeddedBrowserWebView.dll" {
		t.Errorf("Detail = %q, want EmbeddedBrowserWebView.dll", legacy.Detail)
	}
}

func TestFilePatternSignal(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "msedgewebview2.exe")
	if err := os.WriteFile(target, []byte{0x4d, 0x5a}, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	signals := DetectFromFilePatterns(dir)
	if len(signals) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(signals))
	}
	sig := signals[0]
	if sig.Kind != "file-pattern" {
		t.Errorf("Kind = %q, want file-pattern", sig.Kind)
	}
	if sig.Confidence != 0.9 {
		t.Errorf("Confidence = %v, want 0.9", sig.Confidence)
	}
	if !filepath.IsAbs(sig.Detail) {
		t.Errorf("Detail should be absolute path, got %q", sig.Detail)
	}
	if !strings.EqualFold(filepath.Base(sig.Detail), "msedgewebview2.exe") {
		t.Errorf("Detail basename = %q, want msedgewebview2.exe", filepath.Base(sig.Detail))
	}
}

func TestFilePatternEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if signals := DetectFromFilePatterns(dir); len(signals) != 0 {
		t.Errorf("expected no signals, got %+v", signals)
	}
}

func TestFilePatternDepthBound(t *testing.T) {
	// maxWalkDepth = 3; place msedgewebview2.exe at depth 4 — should NOT be found.
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c", "d")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(deep, "msedgewebview2.exe"), []byte{0x4d, 0x5a}, 0o600); err != nil {
		t.Fatalf("write deep target: %v", err)
	}
	if signals := DetectFromFilePatterns(dir); len(signals) != 0 {
		t.Errorf("expected depth-bound skip, got %+v", signals)
	}
}

func TestMultipleSignals(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "msedgewebview2.exe"), []byte{0x4d, 0x5a}, 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}

	imports := []string{"KERNEL32.dll", "WebView2Loader.dll"}
	peSig := DetectFromImports(imports)
	fileSignals := DetectFromFilePatterns(dir)

	if peSig == nil {
		t.Fatal("expected PE import signal")
	}
	if len(fileSignals) != 1 {
		t.Fatalf("expected 1 file-pattern signal, got %d", len(fileSignals))
	}
	kinds := map[string]bool{peSig.Kind: true, fileSignals[0].Kind: true}
	if !kinds["pe-import"] || !kinds["file-pattern"] {
		t.Errorf("expected pe-import + file-pattern kinds, got %v", kinds)
	}
}

func TestDetectEvergreenRuntimeCallable(t *testing.T) {
	// Smoke test: function must be callable on every platform without panicking.
	// On non-Windows it returns Mode="unknown" with nil error; on Windows the
	// outcome depends on host state so we only assert no panic and a sane Mode.
	info, _ := DetectEvergreenRuntime()
	switch info.Mode {
	case "evergreen", "unknown":
	default:
		t.Errorf("unexpected Mode = %q", info.Mode)
	}
}
