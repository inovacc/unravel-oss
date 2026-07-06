/*
Copyright (c) 2026 Security Research
*/
package components

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyAuth(t *testing.T) {
	b, c, src := Classify(SourceFile{Path: "src/auth/login.js"}, Options{})
	if b != BucketAuth {
		t.Fatalf("bucket: got %q want auth", b)
	}
	if c < 0.7 {
		t.Fatalf("confidence: got %v want >=0.7", c)
	}
	if src != "pattern" {
		t.Fatalf("source: got %q want pattern", src)
	}
}

func TestClassifyTelemetry(t *testing.T) {
	b, c, src := Classify(SourceFile{Path: "src/lib/sentry-init.ts"}, Options{})
	if b != BucketTelemetry {
		t.Fatalf("bucket: got %q want telemetry", b)
	}
	if c < 0.85 {
		t.Fatalf("confidence: got %v want >=0.85", c)
	}
	if src != "pattern" {
		t.Fatalf("source: got %q", src)
	}
}

func TestClassifyUnknownNoAI(t *testing.T) {
	b, c, src := Classify(SourceFile{Path: "src/foo/bar.go"}, Options{WithAI: false})
	if b != BucketUnknown {
		t.Fatalf("bucket: got %q want unknown", b)
	}
	if c != 0 {
		t.Fatalf("confidence: got %v want 0", c)
	}
	if src != "pattern" {
		t.Fatalf("source: got %q want pattern", src)
	}
}

func TestClassifyUserOverride(t *testing.T) {
	opts := Options{Override: map[string]Bucket{"src/x.js": BucketCrypto}}
	b, c, src := Classify(SourceFile{Path: "src/x.js"}, opts)
	if b != BucketCrypto {
		t.Fatalf("bucket: got %q want crypto", b)
	}
	if c != 1.0 {
		t.Fatalf("confidence: got %v want 1.0", c)
	}
	if src != "user-override" {
		t.Fatalf("source: got %q", src)
	}
}

func TestClassifyContentFallback(t *testing.T) {
	// Path has nothing meaningful, but content carries a pattern keyword.
	b, _, src := Classify(SourceFile{
		Path:    "src/a/b.js",
		Content: []byte("function x(){ const sentry = init(); }"),
	}, Options{})
	if b != BucketTelemetry {
		t.Fatalf("bucket: got %q want telemetry", b)
	}
	if src != "pattern" {
		t.Fatalf("source: got %q", src)
	}
}

func TestClassifyMCPInvokedAndDisabled(t *testing.T) {
	called := false
	mcp := func(_ context.Context, _ SourceFile) (Bucket, float64, error) {
		called = true
		return BucketIPC, 0.55, nil
	}
	// Disabled even though function provided.
	b, _, src := Classify(SourceFile{Path: "src/foo.go"}, Options{WithAI: false, MCPClassify: mcp})
	if called {
		t.Fatalf("MCP must not be called when WithAI=false")
	}
	if b != BucketUnknown || src != "pattern" {
		t.Fatalf("got %q/%q, want unknown/pattern", b, src)
	}
	// Enabled.
	b, c, src := Classify(SourceFile{Path: "src/foo.go"}, Options{WithAI: true, MCPClassify: mcp})
	if !called {
		t.Fatalf("MCP must be called when WithAI=true and pattern misses")
	}
	if b != BucketIPC || c != 0.55 || src != "mcp" {
		t.Fatalf("got %q/%v/%q want ipc/0.55/mcp", b, c, src)
	}
}

func TestClassifyMCPErrorLogged(t *testing.T) {
	mcp := func(_ context.Context, _ SourceFile) (Bucket, float64, error) {
		return "", 0, errors.New("network down")
	}
	b, c, src := Classify(SourceFile{Path: "src/foo.go"}, Options{WithAI: true, MCPClassify: mcp})
	if b != BucketUnknown || c != 0 || src != "pattern" {
		t.Fatalf("MCP error path: got %q/%v/%q", b, c, src)
	}
}

func TestLoadOverrideMissingFile(t *testing.T) {
	out, err := LoadOverride(filepath.Join(t.TempDir(), "nope.yaml"))
	if err != nil {
		t.Fatalf("missing file should be nil/nil, got err=%v", err)
	}
	if out != nil {
		t.Fatalf("expected nil map, got %v", out)
	}
}

func TestLoadOverrideRejectUnknownBucket(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ov.yaml")
	if err := os.WriteFile(p, []byte("src/a.js: invalidbucket\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOverride(p)
	if err == nil || !strings.Contains(err.Error(), "unknown bucket") {
		t.Fatalf("want unknown-bucket error, got %v", err)
	}
}

func TestLoadOverrideRejectsLargeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(p, make([]byte, maxOverrideBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadOverride(p)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size-limit error, got %v", err)
	}
}

func TestLoadOverrideHappyPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ov.yaml")
	body := "src/a.js: auth\nsrc/b.ts: telemetry\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOverride(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got["src/a.js"] != BucketAuth || got["src/b.ts"] != BucketTelemetry {
		t.Fatalf("bad map: %v", got)
	}
}

func TestValidBucketsHasNine(t *testing.T) {
	if n := len(ValidBuckets()); n != 9 {
		t.Fatalf("ValidBuckets count: got %d want 9", n)
	}
}
