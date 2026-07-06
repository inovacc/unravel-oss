/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

const sampleXAML = `<?xml version="1.0" encoding="utf-8"?>
<Page xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
  <Grid>
    <Button Content="OK" />
    <TextBlock Text="{Binding Name}" />
  </Grid>
</Page>`

func TestWalkDirectory_RawXAML(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "Page1.xaml"), []byte(sampleXAML))
	writeFile(t, filepath.Join(root, "subdir", "Page2.xaml"), []byte(sampleXAML))
	writeFile(t, filepath.Join(root, "Foo.xbf"), []byte("XBF\x00stub"))
	writeFile(t, filepath.Join(root, "README.md"), []byte("hi"))

	idx, err := WalkDirectory(root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if got := len(idx.Entries); got != 3 {
		t.Fatalf("want 3 entries, got %d (%+v)", got, idx.Entries)
	}
	kinds := map[string]int{}
	for _, e := range idx.Entries {
		kinds[e.Kind]++
	}
	if kinds["raw"] != 2 || kinds["xbf"] != 1 {
		t.Fatalf("kind histogram unexpected: %+v", kinds)
	}
}

func TestWalkDirectory_DepthBound(t *testing.T) {
	root := t.TempDir()
	deep := root
	for range 7 {
		deep = filepath.Join(deep, "d")
	}
	writeFile(t, filepath.Join(deep, "Deep.xaml"), []byte(sampleXAML))

	// Default MaxDepth=6 should NOT include Deep.xaml at depth 8.
	idx, err := WalkDirectory(root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, e := range idx.Entries {
		if strings.Contains(e.Path, "Deep.xaml") {
			t.Fatalf("default depth should exclude Deep.xaml; got %+v", idx.Entries)
		}
	}

	// MaxDepth=10 should include it.
	idx2, err := WalkDirectory(root, WalkOptions{MaxDepth: 10})
	if err != nil {
		t.Fatalf("walk2: %v", err)
	}
	found := false
	for _, e := range idx2.Entries {
		if strings.HasSuffix(e.Path, "Deep.xaml") {
			found = true
		}
	}
	if !found {
		t.Fatalf("MaxDepth=10 should include Deep.xaml; got %+v", idx2.Entries)
	}
}

func TestWalkDirectory_SymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privileged on Windows; skipped")
	}
	root := t.TempDir()
	target := filepath.Join(root, "real")
	writeFile(t, filepath.Join(target, "Real.xaml"), []byte(sampleXAML))
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	idx, err := WalkDirectory(root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	hasNotice := false
	for _, e := range idx.Errors {
		if strings.Contains(e, "symlink rejected") {
			hasNotice = true
		}
	}
	if !hasNotice {
		t.Fatalf("expected symlink-rejected notice in idx.Errors; got %+v", idx.Errors)
	}
	// Should still see Real.xaml directly (not via the symlink).
	count := 0
	for _, e := range idx.Entries {
		if strings.HasSuffix(e.Path, "Real.xaml") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("want 1 Real.xaml entry (direct), got %d (%+v)", count, idx.Entries)
	}
}

func TestWalkDirectory_OversizedFile(t *testing.T) {
	root := t.TempDir()
	big := make([]byte, 32<<20)
	copy(big, []byte("<?xml"))
	writeFile(t, filepath.Join(root, "Big.xaml"), big)

	idx, err := WalkDirectory(root, WalkOptions{})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(idx.Entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(idx.Entries))
	}
	e := idx.Entries[0]
	if e.Kind != "raw" {
		t.Fatalf("want kind raw, got %q", e.Kind)
	}
	if len(e.Errors) == 0 || !strings.Contains(strings.Join(e.Errors, "|"), "exceeds limit") {
		t.Fatalf("want size-limit error; got %+v", e.Errors)
	}
	if len(e.ResourceKeys) != 0 || len(e.ControlTypes) != 0 {
		t.Fatalf("oversized file should not be parsed; got %+v", e)
	}
}

func TestWalkDirectory_RootNotDir(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "x.txt")
	writeFile(t, f, []byte("hi"))
	if _, err := WalkDirectory(f, WalkOptions{}); err == nil {
		t.Fatalf("want error walking a file as root")
	}
}

func TestWalkDirectory_TraversalRejected(t *testing.T) {
	if _, err := WalkDirectory("foo/../bar", WalkOptions{}); err == nil {
		t.Fatalf("want error on '..' in root")
	}
}
