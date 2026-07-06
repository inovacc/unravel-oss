/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBeautifier is a programmable Pass-2 stand-in.
type fakeBeautifier struct {
	calls    int32
	response string
	err      error
}

func (f *fakeBeautifier) Beautify(ctx context.Context, prompt, input string) (string, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.err != nil {
		return "", f.err
	}
	return f.response, nil
}

func loadTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

func TestReconstruct_WebpackPatternFirstSucceeds(t *testing.T) {
	src := loadTestdata(t, "webpack_min.js")
	mock := &fakeBeautifier{response: `{"modules":[]}`}
	res, err := Reconstruct(context.Background(), src, Options{UseMCP: true, AIClient: mock})
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if res.Kind != KindWebpack {
		t.Errorf("Kind = %s, want webpack", res.Kind)
	}
	if len(res.Modules) < 2 {
		t.Errorf("got %d modules, want >=2", len(res.Modules))
	}
	if atomic.LoadInt32(&mock.calls) != 0 {
		t.Errorf("MCP fallback called %d times, want 0 (Pass 1 succeeded)", mock.calls)
	}
}

func TestReconstruct_ViteFallbackToMCP(t *testing.T) {
	// Vite fingerprint present but no factory wrappers — Pass 1 carves
	// 0 modules.
	src := []byte(`const __vite__mapDeps = (i) => i; var x = 1; var y = 2;`)
	// MCP returns a single brace-balanced range covering "var x = 1;".
	// To make it brace-balanced, propose a subrange that contains a
	// balanced { ... } block. Use a small balanced literal fixture.
	src = []byte(`const __vite__mapDeps = (i) => i; { var foo = 1; }`)
	startIdx := strings.Index(string(src), "{")
	endIdx := strings.LastIndex(string(src), "}") + 1
	resp := `{"modules":[{"start":` + itoa(startIdx) + `,"end":` + itoa(endIdx) + `,"candidate_name":"foo"}]}`
	mock := &fakeBeautifier{response: resp}
	res, err := Reconstruct(context.Background(), src, Options{UseMCP: true, AIClient: mock})
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !res.UsedMCP {
		t.Error("expected UsedMCP=true")
	}
	if len(res.Modules) != 1 {
		t.Fatalf("got %d modules, want 1", len(res.Modules))
	}
	if res.Modules[0].Source != "mcp" {
		t.Errorf("Source = %s, want mcp", res.Modules[0].Source)
	}
}

func TestReconstruct_MCPProposalRejectedByBalanceGuard(t *testing.T) {
	src := []byte(`const __vite__mapDeps = (i) => i; { var foo = 1;`)
	// Propose a range whose slice is unbalanced (`{` open, no close).
	resp := `{"modules":[{"start":34,"end":` + itoa(len(src)) + `,"candidate_name":"foo"}]}`
	mock := &fakeBeautifier{response: resp}
	res, _ := Reconstruct(context.Background(), src, Options{UseMCP: true, AIClient: mock})
	if len(res.Modules) != 0 {
		t.Errorf("expected 0 survivors, got %d", len(res.Modules))
	}
	hasReason := false
	for _, e := range res.Errors {
		if strings.Contains(e, "balance_validation_failed") {
			hasReason = true
		}
	}
	if !hasReason {
		t.Errorf("expected balance_validation_failed reason in errors %v", res.Errors)
	}
}

func TestReconstruct_MCPInvalidJSONHandled(t *testing.T) {
	src := []byte(`const __vite__mapDeps = (i) => i;`)
	mock := &fakeBeautifier{response: "not json"}
	res, err := Reconstruct(context.Background(), src, Options{UseMCP: true, AIClient: mock})
	if err != nil {
		t.Fatalf("Reconstruct should not bubble JSON error: %v", err)
	}
	if len(res.Modules) != 0 {
		t.Errorf("expected 0 modules, got %d", len(res.Modules))
	}
	hasParseErr := false
	for _, e := range res.Errors {
		if strings.Contains(e, "mcp_parse_error") || strings.Contains(e, "mcp_propose") {
			hasParseErr = true
		}
	}
	if !hasParseErr {
		t.Errorf("expected mcp_parse_error in errors, got %v", res.Errors)
	}
}

func TestReconstruct_MCPOverlappingProposals(t *testing.T) {
	src := []byte(`const __vite__mapDeps = (i) => i; { var foo = 1; } { var bar = 2; }`)
	// Two overlapping balanced ranges — second overlaps first by 1.
	resp := `{"modules":[
		{"start":34,"end":50,"candidate_name":"foo"},
		{"start":40,"end":60,"candidate_name":"bar"}
	]}`
	mock := &fakeBeautifier{response: resp}
	res, _ := Reconstruct(context.Background(), src, Options{UseMCP: true, AIClient: mock})
	// At most 1 should survive (first-wins, overlap dropped).
	if len(res.Modules) > 1 {
		t.Errorf("expected <=1 survivor (overlap dropped), got %d", len(res.Modules))
	}
}

func TestOrchestrator_LayoutNamed(t *testing.T) {
	tmp := t.TempDir()
	bundlePath := filepath.Join(tmp, "input.js")
	out := filepath.Join(tmp, "out")
	if err := os.WriteFile(bundlePath, loadTestdata(t, "webpack_min.js"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(context.Background(), RunOptions{
		Input:  bundlePath,
		Output: out,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.BundleKind != KindWebpack {
		t.Errorf("BundleKind = %s", rep.BundleKind)
	}
	if _, err := os.Stat(filepath.Join(out, "_module_index.json")); err != nil {
		t.Errorf("missing _module_index.json: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Errorf("missing manifest.json: %v", err)
	}
	// At least one unnamed module under modules/_unnamed/ or named.
	unnamedEntries, _ := os.ReadDir(filepath.Join(out, "modules", "_unnamed"))
	namedEntries, _ := os.ReadDir(filepath.Join(out, "modules"))
	count := len(unnamedEntries)
	for _, e := range namedEntries {
		if !e.IsDir() {
			count++
		}
	}
	if count < 1 {
		t.Errorf("expected >=1 module file written, got %d", count)
	}
}

func TestOrchestrator_BeautifyChained(t *testing.T) {
	tmp := t.TempDir()
	bundlePath := filepath.Join(tmp, "input.js")
	out := filepath.Join(tmp, "out")
	if err := os.WriteFile(bundlePath, loadTestdata(t, "webpack_min.js"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := int32(0)
	bf := func(ctx context.Context, src []byte, modulePath string) ([]byte, string, error) {
		atomic.AddInt32(&called, 1)
		return src, `{"name":"react"}`, nil
	}
	rep, err := Run(context.Background(), RunOptions{
		Input:        bundlePath,
		Output:       out,
		Beautify:     true,
		BeautifierFn: bf,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.BeautifyCount < 1 {
		t.Errorf("BeautifyCount = %d, want >=1", rep.BeautifyCount)
	}
	if atomic.LoadInt32(&called) < 1 {
		t.Errorf("BeautifierFn called %d times, want >=1", called)
	}
}

func TestOrchestrator_BeautifyDisabled(t *testing.T) {
	tmp := t.TempDir()
	bundlePath := filepath.Join(tmp, "input.js")
	out := filepath.Join(tmp, "out")
	if err := os.WriteFile(bundlePath, loadTestdata(t, "webpack_min.js"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := int32(0)
	bf := func(ctx context.Context, src []byte, modulePath string) ([]byte, string, error) {
		atomic.AddInt32(&called, 1)
		return src, "", nil
	}
	_, err := Run(context.Background(), RunOptions{
		Input:        bundlePath,
		Output:       out,
		Beautify:     false,
		BeautifierFn: bf,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if atomic.LoadInt32(&called) != 0 {
		t.Errorf("BeautifierFn called %d times when Beautify=false", called)
	}
}

func TestOrchestrator_AtomicWrite(t *testing.T) {
	tmp := t.TempDir()
	bundlePath := filepath.Join(tmp, "input.js")
	out := filepath.Join(tmp, "out")
	if err := os.WriteFile(bundlePath, loadTestdata(t, "esbuild_min.js"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), RunOptions{Input: bundlePath, Output: out}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Ensure no stray temp files remain in modules dir.
	entries, _ := os.ReadDir(filepath.Join(out, "modules"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("stray temp file: %s", e.Name())
		}
	}
}

func TestOrchestrator_SymlinkRejected(t *testing.T) {
	if isWindows() {
		t.Skip("symlink test skipped on Windows (requires elevated privs)")
	}
	tmp := t.TempDir()
	bundlePath := filepath.Join(tmp, "input.js")
	if err := os.WriteFile(bundlePath, loadTestdata(t, "webpack_min.js"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(tmp, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	// Pre-create a symlink at <out>/manifest.json pointing somewhere harmless.
	link := filepath.Join(out, "manifest.json")
	target := filepath.Join(tmp, "decoy")
	_ = os.WriteFile(target, []byte("decoy"), 0o644)
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	_, _ = Run(context.Background(), RunOptions{Input: bundlePath, Output: out})
	// The symlink should still point to target, not have been clobbered.
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("symlink replaced — atomic-write guard failed")
	}
}

func TestOrchestrator_PathTraversalRejected(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "out")
	_, err := Run(context.Background(), RunOptions{
		Input:  "../../etc/passwd",
		Output: out,
	})
	if err == nil {
		t.Fatal("expected path-traversal rejection")
	}
	if !strings.Contains(err.Error(), "..") {
		t.Errorf("error = %v, want '..' rejection", err)
	}
}

func TestManifest_BundleKindAndIdMap(t *testing.T) {
	tmp := t.TempDir()
	bundlePath := filepath.Join(tmp, "input.js")
	out := filepath.Join(tmp, "out")
	if err := os.WriteFile(bundlePath, loadTestdata(t, "webpack_min.js"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(context.Background(), RunOptions{Input: bundlePath, Output: out}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("manifest unmarshal: %v", err)
	}
	if m.BundleKind != KindWebpack {
		t.Errorf("manifest.BundleKind = %s", m.BundleKind)
	}
	if m.ModuleIDRecoveredName == nil {
		t.Error("manifest.ModuleIDRecoveredName is nil")
	}
}

func TestReconstruct_ProposalDeepNestingBounded(t *testing.T) {
	// 100k consecutive `{` characters — must not hang.
	src := make([]byte, 100_000)
	for i := range src {
		src[i] = '{'
	}
	// Wrap with a vite fingerprint so the recogniser triggers.
	full := append([]byte("__vite__mapDeps;"), src...)
	resp := `{"modules":[{"start":0,"end":` + itoa(len(full)) + `,"candidate_name":null}]}`
	mock := &fakeBeautifier{response: resp}
	done := make(chan struct{})
	go func() {
		_, _ = Reconstruct(context.Background(), full, Options{UseMCP: true, AIClient: mock})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Reconstruct hung on pathological input")
	}
}

// helpers

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

func isWindows() bool { return os.PathSeparator == '\\' }
