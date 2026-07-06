/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteMarkdown_AtomicNoTmpLeftBehind(t *testing.T) {
	r, err := Validate("testdata/synthetic_criteria.json", "testdata/synthetic_capture.json")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "report.md")
	if err := WriteMarkdown(r, out); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("output not present: %v", err)
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file leaked: %v", err)
	}
}

func TestRenderMarkdown_TextOnlyBadges(t *testing.T) {
	r, err := Validate("testdata/synthetic_criteria.json", "testdata/synthetic_capture.json")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	md := RenderMarkdown(r)
	for _, want := range []string{"**[BLOCK]**", "**[FLAG]**", "**[PASS]**", "## Summary", "## Findings"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in rendered markdown", want)
		}
	}
}

func TestWriteMarkdown_RejectsSymlink(t *testing.T) {
	r, _ := Validate("testdata/synthetic_criteria.json", "testdata/synthetic_capture.json")
	dir := t.TempDir()
	target := filepath.Join(dir, "target.md")
	link := filepath.Join(dir, "report.md")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		// Symlinks may be unsupported on Windows without privileges. Skip.
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := WriteMarkdown(r, link); err == nil {
		t.Errorf("expected symlink rejection, got nil")
	}
}
