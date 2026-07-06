/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// v8CodeCacheHeader mirrors the synthetic header skipped by the recoverer:
// a small fixed magic-ish prefix followed by the real JS source bytes. The
// recoverer must surface the *source*, never the header (Research A1 /
// §Don't Hand-Roll — no V8 bytecode decompile).
var v8CodeCacheHeader = []byte{0xde, 0xc0, 0x17, 0xc0, 0x00, 0x00, 0x00, 0x00}

// TestRecoverCachedJS_CodeCacheAndScriptCache asserts that a profile carrying
// EBWebView "Code Cache/js" and "Service Worker/ScriptCache" cached entries
// yields recovered JS *source* entries only from Service Worker/ScriptCache.
// Code Cache/js holds V8 bytecode and is intentionally not walked.
func TestRecoverCachedJS_CodeCacheAndScriptCache(t *testing.T) {
	eb := t.TempDir()
	prof := mkProfile(t, eb, "Default")

	ccDir := filepath.Join(prof, "Code Cache", "js", "00")
	swDir := filepath.Join(prof, "Service Worker", "ScriptCache")
	for _, d := range []string{ccDir, swDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// Code Cache entry: should NOT be recovered (bytecode root retired).
	jsSrc := "function wa(){const k=crypto.subtle;return fetch('https://web.whatsapp.com/x')}"
	ccBlob := append(append([]byte{}, v8CodeCacheHeader...), []byte(jsSrc)...)
	if err := os.WriteFile(filepath.Join(ccDir, "0_abcdef01"), ccBlob, 0o600); err != nil {
		t.Fatal(err)
	}
	// Service Worker entry: should be recovered.
	swSrc := "self.addEventListener('fetch',e=>{new WebSocket('wss://w.example')})"
	swBlob := append(append([]byte{}, v8CodeCacheHeader...), []byte(swSrc)...)
	if err := os.WriteFile(filepath.Join(swDir, "1_112233"), swBlob, 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Analyze(eb, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.RecoveredJS) == 0 {
		t.Fatalf("RecoveredJS empty: Service Worker/ScriptCache JS source not recovered")
	}

	var sawCC, sawSW bool
	for _, e := range res.RecoveredJS {
		if e.Source == "" {
			t.Errorf("recovered entry %s has empty Source", e.Path)
		}
		// Header must be stripped — recovered text must contain the JS, not
		// the synthetic V8 header bytes.
		if strings.Contains(e.Source, string(v8CodeCacheHeader)) {
			t.Errorf("V8 code-cache header leaked into recovered source for %s", e.Path)
		}
		if strings.Contains(e.Source, "crypto.subtle") {
			sawCC = true
		}
		if strings.Contains(e.Source, "addEventListener") {
			sawSW = true
		}
	}
	// Code Cache/js is retired — its content must NOT appear in recovered JS.
	if sawCC {
		t.Errorf("Code Cache/js bytecode recovered as JS source (crypto.subtle marker found); Code Cache walk must be retired")
	}
	if !sawSW {
		t.Errorf("Service Worker/ScriptCache source not recovered (addEventListener marker missing)")
	}
}

// TestRecoverCachedJS_EmptyNeverSynthesizes asserts the analyzed-empty
// contract: no Code Cache dirs → no RecoveredJS, no synthesis, no error.
func TestRecoverCachedJS_EmptyNeverSynthesizes(t *testing.T) {
	eb := t.TempDir()
	mkProfile(t, eb, "Default")
	res, err := Analyze(eb, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.RecoveredJS) != 0 {
		t.Fatalf("RecoveredJS synthesized %d entries with no Code Cache on disk", len(res.RecoveredJS))
	}
}

// TestRecoverCachedJS_MalformedNoPanic asserts a malformed/garbage cache file
// is collected non-fatally (defer-recover discipline), never panics.
func TestRecoverCachedJS_MalformedNoPanic(t *testing.T) {
	eb := t.TempDir()
	prof := mkProfile(t, eb, "Default")
	ccDir := filepath.Join(prof, "Code Cache", "js")
	if err := os.MkdirAll(ccDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Truncated (header-only) and binary-garbage entries must not crash.
	if err := os.WriteFile(filepath.Join(ccDir, "0_trunc"), v8CodeCacheHeader[:4], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ccDir, "1_garbage"), []byte{0x00, 0x01, 0x02, 0xff, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(eb, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze panicked or errored on malformed cache: %v", err)
	}
	_ = res // no assertion on content: just must not panic / hard-error
}

// TestRecoverCachedJS_GatedByExtractCache asserts the walk is gated behind
// opts.ExtractCache (already plumbed through analyze_uwp.go).
func TestRecoverCachedJS_GatedByExtractCache(t *testing.T) {
	eb := t.TempDir()
	prof := mkProfile(t, eb, "Default")
	ccDir := filepath.Join(prof, "Code Cache", "js")
	if err := os.MkdirAll(ccDir, 0o700); err != nil {
		t.Fatal(err)
	}
	blob := append(append([]byte{}, v8CodeCacheHeader...), []byte("var x=1")...)
	if err := os.WriteFile(filepath.Join(ccDir, "0_x"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(eb, Options{ExtractCache: false, RejectSymlinks: true})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.RecoveredJS) != 0 {
		t.Fatalf("RecoveredJS populated despite ExtractCache=false")
	}
}

func TestRecoverProfileCachedJS_SkipsCodeCacheBytecode(t *testing.T) {
	dir := t.TempDir()
	cc := filepath.Join(dir, "Code Cache", "js")
	if err := os.MkdirAll(cc, 0o755); err != nil {
		t.Fatal(err)
	}
	garbage := append([]byte{0x30, 0x5c, 0x72, 0xa7, 0x00, 0x01},
		[]byte(`_keyhttps://x/a.js`+"\x00\x01){});\x02\x03")...)
	if err := os.WriteFile(filepath.Join(cc, "abc123_0"), garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	got := recoverProfileCachedJS(dir)
	for _, e := range got {
		if filepath.Base(filepath.Dir(e.Path)) == "js" {
			t.Fatalf("Code Cache bytecode recovered as JS source: %q", e.Path)
		}
	}
}

func TestRecoveredCSSEntry_Shape(t *testing.T) {
	e := RecoveredCSSEntry{Path: "p", Source: ".a{color:red}"}
	if e.Path == "" || e.Source == "" {
		t.Fatal("RecoveredCSSEntry fields missing")
	}
}
