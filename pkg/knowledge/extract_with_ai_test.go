/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/store"
)

// makeTeardownWithBeautified writes a fixture that already has a sweep-able
// beautified file plus _meta.json sidecar. Used by Test 1 (default no-MCP).
func makeTeardownWithBeautified(t *testing.T, javaPath string) string {
	t.Helper()
	td := t.TempDir()
	full := filepath.Join(td, javaPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("class Foo {}"), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{"beautify_provenance": "phase6-java"}
	mb, _ := json.Marshal(meta)
	if err := os.WriteFile(full+"._meta.json", mb, 0o644); err != nil {
		t.Fatal(err)
	}
	return td
}

// stubBeautify produces a deterministic transformation so tests can assert
// the orchestrator routed input through the right track.
func stubBeautify(tag string, counter *int) func(ctx context.Context, in []byte) ([]byte, error) {
	return func(ctx context.Context, in []byte) ([]byte, error) {
		*counter++
		out := append([]byte(tag+":"), in...)
		return out, nil
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// fakeBeautifyDeps installs counting stubs and isolates the test from the
// production beautify entries. Called per-test; the prior dep set is
// restored on cleanup.
func fakeBeautifyDeps(t *testing.T) (deps *beautifyDeps, calls *struct{ java, js, cs int }) {
	t.Helper()
	calls = &struct{ java, js, cs int }{}
	deps = &beautifyDeps{
		jBeautify:  stubBeautify("java", &calls.java),
		jsBeautify: stubBeautify("js", &calls.js),
		csBeautify: stubBeautify("cs", &calls.cs),
	}
	return deps, calls
}

func TestExtractDefaultNoMCP(t *testing.T) {
	td := makeTeardownWithBeautified(t, "decompiled/com/foo/Foo.java")
	deps, calls := fakeBeautifyDeps(t)

	dr := &dissect.DissectResult{Path: td}
	opts := ExtractOptions{WithAI: false, TeardownDir: td, Beautify: deps}
	kr := ExtractWithOptions(dr, opts)

	if calls.java+calls.js+calls.cs != 0 {
		t.Errorf("default mode invoked beautifiers: java=%d js=%d cs=%d", calls.java, calls.js, calls.cs)
	}
	if len(kr.SourceFiles) == 0 {
		t.Fatal("sweep produced no source files; want >= 1")
	}
	gotProv := false
	for _, sf := range kr.SourceFiles {
		if sf.BeautifyProvenance == "phase6-java" {
			gotProv = true
			break
		}
	}
	if !gotProv {
		t.Error("no source file with phase6-java provenance from sweep")
	}
}

func TestExtractWithAIRunsAllTracks(t *testing.T) {
	td := t.TempDir()
	deps, calls := fakeBeautifyDeps(t)

	javaIn := []byte("class A {}")
	jsIn := []byte("var b=1;")
	csIn := []byte("class C{}")

	dr := &dissect.DissectResult{Path: td}
	s := store.NewWithDir(filepath.Join(td, "cache"))
	opts := ExtractOptions{
		WithAI: true, TeardownDir: td, Beautify: deps, Store: s,
		BeautifyInputs: &BeautifyInputs{
			Java:   []BeautifyInput{{Path: "A.java", Content: javaIn}},
			JS:     []BeautifyInput{{Path: "b.js", Content: jsIn}},
			CSharp: []BeautifyInput{{Path: "C.cs", Content: csIn}},
		},
	}
	_ = ExtractWithOptions(dr, opts)

	if calls.java != 1 || calls.js != 1 || calls.cs != 1 {
		t.Fatalf("want one call per track; got java=%d js=%d cs=%d", calls.java, calls.js, calls.cs)
	}
}

func TestCacheReuseZeroTokens(t *testing.T) {
	td := t.TempDir()
	deps, calls := fakeBeautifyDeps(t)

	javaIn := []byte("class A {}")
	hash := sha256Hex(javaIn)

	s := store.NewWithDir(filepath.Join(td, "cache"))
	// Pre-populate cache with a different beautified payload to prove
	// the cached value is returned without invoking jBeautify.
	cached := []byte("CACHED-class A {}")
	if err := beautifyCachePut(s, hash, "beautify-java", "A.java", cached); err != nil {
		t.Fatalf("seed cache: %v", err)
	}

	dr := &dissect.DissectResult{Path: td}
	opts := ExtractOptions{
		WithAI: true, TeardownDir: td, Beautify: deps, Store: s,
		BeautifyInputs: &BeautifyInputs{
			Java: []BeautifyInput{{Path: "A.java", Content: javaIn}},
		},
	}
	kr := ExtractWithOptions(dr, opts)

	if calls.java != 0 {
		t.Errorf("cache hit should suppress jBeautify; calls.java=%d", calls.java)
	}
	// Verify the cached payload made it into SourceFiles.
	found := false
	for _, sf := range kr.SourceFiles {
		if string(sf.Content) == string(cached) {
			found = true
			break
		}
	}
	if !found {
		t.Error("cached payload not surfaced as SourceFile.Content")
	}
}

func TestExtractInjectsClassifierMCP(t *testing.T) {
	td := t.TempDir()
	deps, _ := fakeBeautifyDeps(t)

	dr := &dissect.DissectResult{Path: td}

	withAI := ExtractOptions{WithAI: true, TeardownDir: td, Beautify: deps}
	if got := classifierOptionsFor(withAI); got.MCPClassify == nil {
		t.Error("WithAI=true: MCPClassify must be non-nil")
	} else if !got.WithAI {
		t.Error("WithAI flag not propagated to classifier options")
	}

	noAI := ExtractOptions{WithAI: false, TeardownDir: td, Beautify: deps}
	if got := classifierOptionsFor(noAI); got.MCPClassify != nil {
		t.Error("WithAI=false: MCPClassify must be nil")
	}

	// Smoke: ExtractWithOptions runs without panic in either mode.
	_ = ExtractWithOptions(dr, withAI)
	_ = ExtractWithOptions(dr, noAI)
}

func TestCSSBypass(t *testing.T) {
	td := t.TempDir()
	deps, calls := fakeBeautifyDeps(t)

	dr := &dissect.DissectResult{Path: td}
	opts := ExtractOptions{
		WithAI: true, TeardownDir: td, Beautify: deps,
		BeautifyInputs: &BeautifyInputs{
			CSS: []BeautifyInput{{Path: "main.css", Content: []byte("body{}")}},
		},
	}
	_ = ExtractWithOptions(dr, opts)

	// CSS must NOT route through any of the three orchestrator tracks (D-16).
	if calls.java+calls.js+calls.cs != 0 {
		t.Errorf("CSS leaked into beautify tracks: java=%d js=%d cs=%d",
			calls.java, calls.js, calls.cs)
	}
}
