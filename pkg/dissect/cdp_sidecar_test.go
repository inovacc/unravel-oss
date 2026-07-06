/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cwv2 "github.com/inovacc/unravel-oss/pkg/capture/webview2"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	wv2 "github.com/inovacc/unravel-oss/pkg/webview2"
)

// writeSidecar writes a CDPSourceSidecar JSON at the loader-computed path for
// pkgKey, with the given PulledAt and one JS + one CSS entry by default.
func writeSidecar(t *testing.T, pkgKey string, pulledAt time.Time, js, css []cwv2.CDPSrcEntry) {
	t.Helper()
	sc := cwv2.CDPSourceSidecar{
		PulledAt: pulledAt,
		PkgKey:   pkgKey,
		JS:       js,
		CSS:      css,
	}
	data, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		t.Fatalf("marshal sidecar: %v", err)
	}
	path := cwv2.CDPSourceSidecarPath(pkgKey)
	if mkerr := os.MkdirAll(filepath.Dir(path), 0o755); mkerr != nil {
		t.Fatalf("mkdir sidecar dir: %v", mkerr)
	}
	if werr := os.WriteFile(path, data, 0o600); werr != nil {
		t.Fatalf("write sidecar: %v", werr)
	}
}

func TestLoadCDPSourceSidecar_FreshAppliesJSCSS(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	writeSidecar(t, "TESTPKG", time.Now(),
		[]cwv2.CDPSrcEntry{{URL: "https://app/x.js", Source: "function a(){}"}},
		[]cwv2.CDPSrcEntry{{URL: "https://app/x.css", Source: ".x{}"}})

	js, css, ok := loadCDPSourceSidecar("TESTPKG", 24*time.Hour)
	if !ok {
		t.Fatalf("expected ok=true for a fresh sidecar")
	}
	if js == "" {
		t.Fatalf("expected non-empty combined JS")
	}
	if len(css) != 1 || css[0].Source != ".x{}" || css[0].Path != "https://app/x.css" {
		t.Fatalf("expected 1 mapped CSSEntry, got %#v", css)
	}
}

func TestLoadCDPSourceSidecar_StaleIgnored(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	writeSidecar(t, "TESTPKG", time.Now().Add(-48*time.Hour),
		[]cwv2.CDPSrcEntry{{URL: "u", Source: "function a(){}"}}, nil)

	if _, _, ok := loadCDPSourceSidecar("TESTPKG", 24*time.Hour); ok {
		t.Fatalf("expected ok=false for a stale (48h old, maxAge 24h) sidecar")
	}
}

func TestLoadCDPSourceSidecar_AbsentHonestEmpty(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	js, css, ok := loadCDPSourceSidecar("NOPE", 24*time.Hour)
	if ok || js != "" || css != nil {
		t.Fatalf("expected honest-empty for absent sidecar, got ok=%v js=%q css=%#v", ok, js, css)
	}
}

// uwpResultWithName builds a minimal *uwp.Result whose Identity.Name (the
// value that becomes knowledge.json package_id for UWP) is name.
func uwpResultWithName(name string) *uwp.Result {
	return &uwp.Result{
		IsUWP:    true,
		Manifest: &uwp.ManifestSummary{Identity: uwp.IdentityInfo{Name: name}},
	}
}

func TestWireEBWebView_SidecarFillsWhenEmpty(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	writeSidecar(t, "TESTPKG2", time.Now(),
		[]cwv2.CDPSrcEntry{{URL: "https://app/main.js", Source: "function main(){return 1}"}},
		[]cwv2.CDPSrcEntry{{URL: "https://app/main.css", Source: ".main{color:red}"}})

	r := &DissectResult{UWPInfo: uwpResultWithName("TESTPKG2")}
	// Empty Result so the cache path is honest-empty; only the sidecar fills.
	wireEBWebViewJSAndSecrets(r, &wv2.Result{Analyzed: true}, nil)

	if r.JSAnalysis == nil {
		t.Fatalf("expected JSAnalysis filled from fresh sidecar")
	}
	if r.RecoveredCSS == nil {
		t.Fatalf("expected RecoveredCSS filled from fresh sidecar")
	}
}

// Richer-wins contract: a sidecar must NOT clobber an already-richer
// JSAnalysis, but MUST replace a materially-shallower one (the real bug:
// 4 tiny ScriptCache SW stubs were blocking the full live app bundle).
func TestWireEBWebView_SidecarRicherWins(t *testing.T) {
	t.Run("richer existing analysis is NOT clobbered", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", t.TempDir())
		writeSidecar(t, "TESTPKG3", time.Now(),
			[]cwv2.CDPSrcEntry{{URL: "https://app/main.js", Source: "function sidecar(){}"}}, nil)

		pre := &JSAnalysisResult{File: "cache-path-original", Size: 5_000_000}
		r := &DissectResult{UWPInfo: uwpResultWithName("TESTPKG3"), JSAnalysis: pre}
		wireEBWebViewJSAndSecrets(r, &wv2.Result{Analyzed: true}, nil)

		if r.JSAnalysis != pre || r.JSAnalysis.File != "cache-path-original" {
			t.Fatalf("richer existing JSAnalysis must win, got %+v", r.JSAnalysis)
		}
	})

	t.Run("shallow existing analysis IS replaced by richer sidecar", func(t *testing.T) {
		t.Setenv("LOCALAPPDATA", t.TempDir())
		big := "function sidecar(){" + strings.Repeat("var x=1;", 500) + "}"
		writeSidecar(t, "TESTPKG3B", time.Now(),
			[]cwv2.CDPSrcEntry{{URL: "https://app/main.js", Source: big}}, nil)

		pre := &JSAnalysisResult{File: "scriptcache-shallow", Size: 10}
		r := &DissectResult{UWPInfo: uwpResultWithName("TESTPKG3B"), JSAnalysis: pre}
		wireEBWebViewJSAndSecrets(r, &wv2.Result{Analyzed: true}, nil)

		if r.JSAnalysis == pre || r.JSAnalysis == nil {
			t.Fatalf("shallow JSAnalysis must be replaced by richer sidecar, got %+v", r.JSAnalysis)
		}
		if r.JSAnalysis.Size <= 10 {
			t.Fatalf("replacement JSAnalysis not richer: size=%d", r.JSAnalysis.Size)
		}
	})
}
