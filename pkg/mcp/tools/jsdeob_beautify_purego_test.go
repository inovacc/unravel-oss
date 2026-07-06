/*
Copyright (c) 2026 Security Research

T0.4 (KB pipeline remediation): unravel_js_beautify must default to
deterministic pure-Go beautification and NOT route through the AI/sampling
seam, so headless / sub-agent callers (no sampling capability) succeed
instead of failing with "Method not found".
*/
package mcptools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJsBeautify_DefaultPureGo_NoSamplingSeam is the regression guard: with NO
// AI client configured, the default (ai=false) path must still beautify. If
// the handler reached ai.NewClient()/BeautifyAI it would error here; a clean
// beautified file proves the pure-Go default is taken.
func TestJsBeautify_DefaultPureGo_NoSamplingSeam(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "min.js")
	out := filepath.Join(dir, "out")
	const minified = `function a(b){if(b){return b*2}else{return 0}}var x=a(21);console.log(x);`
	if err := os.WriteFile(in, []byte(minified), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}

	res, _, err := handleJsBeautify(context.Background(), nil, JsBeautifyInput{Path: in, OutputDir: out, Ai: false})
	if err != nil {
		t.Fatalf("handleJsBeautify transport error: %v", err)
	}
	if res != nil && res.IsError {
		t.Fatalf("pure-Go beautify must not error with no AI configured: %+v", res)
	}

	got, rerr := os.ReadFile(filepath.Join(out, "min.js"))
	if rerr != nil {
		t.Fatalf("output file not written: %v", rerr)
	}
	if len(got) == 0 {
		t.Fatal("beautified output is empty")
	}
	// The input has zero newlines; a deterministic beautifier must add some.
	if !strings.Contains(string(got), "\n") {
		t.Errorf("expected beautified output to add line breaks; got:\n%s", got)
	}
}
