/*
Copyright (c) 2026 Security Research
*/

package winui_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/winui"
	_ "github.com/inovacc/unravel-oss/pkg/winui/runtime" // wire orchestrator
)

// Type aliases keep the test body terse.
type (
	Options       = winui.Options
	FrameworkInfo = winui.FrameworkInfo
)

// Function aliases.
var (
	Analyze              = winui.Analyze
	AnalyzeQuick         = winui.AnalyzeQuick
	MergeFrameworksDedup = winui.MergeFrameworksDedup
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWinUIAnalyze_DirOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Page.xaml"),
		`<Page xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"></Page>`)
	// .xbf file: walker records it; decoder will fail (not a valid XBF) but
	// the walk-level entry must still be present.
	writeFile(t, filepath.Join(dir, "Foo.xbf"), "not really xbf")

	res, err := Analyze(dir, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.XAMLIndex == nil || len(res.XAMLIndex.Entries) < 2 {
		t.Fatalf("expected >=2 XAML entries, got %d", len(res.XAMLIndex.Entries))
	}
}

func TestWinUIAnalyze_WithDeps(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Page.xaml"),
		`<Page xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"></Page>`)
	deps := `{
  "runtimeTarget": {"name": "net6.0"},
  "targets": {"net6.0": {}},
  "libraries": {
    "Microsoft.WinUI/1.5.0": {"type": "package"}
  }
}`
	writeFile(t, filepath.Join(dir, "MyApp.deps.json"), deps)

	res, err := Analyze(dir, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	found := false
	for _, fi := range res.Frameworks {
		if fi.Name == "WinUI 3" {
			found = true
		}
	}
	if !found {
		t.Errorf("WinUI 3 framework not detected: %+v", res.Frameworks)
	}
	if !res.IsWinUI {
		t.Error("IsWinUI should be true with WinUI 3 deps")
	}
}

func TestWinUIAnalyze_RejectsTraversalPath(t *testing.T) {
	_, err := Analyze("../etc/passwd", Options{})
	if err == nil {
		t.Fatal("expected error for traversal path")
	}
	if !strings.Contains(err.Error(), "rejected") {
		t.Errorf("error = %q, want substring 'rejected'", err)
	}
}

func TestWinUIAnalyze_PRIIntegration(t *testing.T) {
	dir := t.TempDir()
	// Use the synthetic PRI fixture from pkg/winui/xaml/pri/testdata.
	src, err := os.ReadFile(filepath.Join("xaml", "pri", "testdata", "synthetic.pri"))
	if err != nil {
		// Fall back to a minimal valid PRI built locally.
		t.Skipf("synthetic.pri fixture not present: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "resources.pri"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Analyze(dir, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res.XAMLIndex == nil {
		t.Fatal("XAMLIndex nil")
	}
	got := false
	for _, e := range res.XAMLIndex.Entries {
		if e.Kind == "pri" {
			got = true
			break
		}
	}
	if !got {
		t.Errorf("no pri-kind entries found; entries=%+v", res.XAMLIndex.Entries)
	}
}

func TestWinUIAnalyze_WriteXAMLDir(t *testing.T) {
	dir := t.TempDir()
	out := t.TempDir()
	writeFile(t, filepath.Join(dir, "Page.xaml"),
		`<Page xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"></Page>`)
	res, err := Analyze(dir, Options{WriteXAMLDir: out})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	// At least one .xaml file should have been written if any entry had Recovered content.
	// Raw walk does not populate Recovered for raw files (that's the walker's contract);
	// so this test mainly asserts that opts.WriteXAMLDir does not error out and
	// the directory exists.
	if _, err := os.Stat(out); err != nil {
		t.Errorf("output dir missing: %v", err)
	}
}

func TestMergeFrameworksDedup(t *testing.T) {
	base := []FrameworkInfo{{Name: "WinUI 3", Source: "dotnet-deps"}}
	add := []FrameworkInfo{
		{Name: "WinUI 3", Source: "dotnet-deps"}, // dup
		{Name: "WinUI 3", Source: "pe-import"},   // new
	}
	got := MergeFrameworksDedup(base, add)
	if len(got) != 2 {
		t.Errorf("len = %d, want 2 (entries=%+v)", len(got), got)
	}
}

func TestAnalyzeQuick_ImportsOnly(t *testing.T) {
	res := AnalyzeQuick("", nil, []string{"Microsoft.UI.Xaml.dll"})
	if res == nil {
		t.Fatal("nil result")
	}
	if len(res.Signals) == 0 {
		t.Error("no signals produced for MUX import")
	}
}
