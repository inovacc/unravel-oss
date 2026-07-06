/*
Copyright (c) 2026 Security Research

diff_visual_test.go — Phase 8 additive Visual Regressions hook tests.
*/
package knowledge

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	visualdiff "github.com/inovacc/unravel-oss/pkg/capture/diff"
)

func mkSolidPNG(t *testing.T, w, h int, c color.RGBA) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("png encode: %v", err)
	}
	return buf.Bytes()
}

// emptyKB makes a minimal but valid KB directory with no visual/ tree.
func emptyKB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// Required: a directory with at least one JSON file or empty is fine; Diff
	// just walks .json files.
	return dir
}

// kbWithVisual creates a KB with visual/<runID>/Login/default/{screenshot.png,
// tree.json, layout.json}.
func kbWithVisual(t *testing.T, runID string, c color.RGBA) string {
	t.Helper()
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "visual", runID, "Login", "default")
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "screenshot.png"), mkSolidPNG(t, 32, 32, c), 0o644); err != nil {
		t.Fatalf("write png: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "tree.json"),
		[]byte(`{"tag":"div","dom_path":"/root","children":[]}`), 0o644); err != nil {
		t.Fatalf("write tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "layout.json"),
		[]byte(`[{"dom_path":"/a","x":0,"y":0,"w":100,"h":50}]`), 0o644); err != nil {
		t.Fatalf("write layout: %v", err)
	}
	// latest.txt pointer
	if err := os.WriteFile(filepath.Join(dir, "visual", "latest.txt"),
		[]byte(runID), 0o644); err != nil {
		t.Fatalf("write latest.txt: %v", err)
	}
	return dir
}

func TestDiffNoVisual(t *testing.T) {
	oldDir := emptyKB(t)
	newDir := emptyKB(t)
	d, err := Diff(oldDir, newDir)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if d.Visual != nil {
		t.Fatalf("expected Visual nil, got %+v", d.Visual)
	}
	if d.SchemaVersion != DiffSchemaVersion {
		t.Fatalf("schema version drifted: got %d want %d", d.SchemaVersion, DiffSchemaVersion)
	}
}

func TestDiffWithVisual(t *testing.T) {
	red := color.RGBA{R: 200, A: 255}
	oldDir := kbWithVisual(t, "run-001", red)
	newDir := kbWithVisual(t, "run-002", red)

	d, err := Diff(oldDir, newDir)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if d.Visual == nil {
		t.Fatalf("expected Visual non-nil")
	}
	if _, ok := d.Visual.States["Login/default"]; !ok {
		t.Fatalf("missing Login/default in visual states; got %+v", d.Visual.States)
	}
	// Phase 7 4-dim engine remains intact.
	if d.SchemaVersion != DiffSchemaVersion {
		t.Fatalf("schema version drifted: got %d want %d", d.SchemaVersion, DiffSchemaVersion)
	}
}

func TestDiffOldOnly(t *testing.T) {
	red := color.RGBA{R: 200, A: 255}
	oldDir := kbWithVisual(t, "run-only", red)
	newDir := emptyKB(t)
	d, err := Diff(oldDir, newDir)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if d.Visual == nil {
		t.Fatalf("expected Visual non-nil even when only old has visual data")
	}
	// All states present on old must surface as Removed.
	if len(d.Visual.Removed) == 0 {
		t.Fatalf("expected at least one removed state, got %+v", d.Visual)
	}
}

func TestDiffMarkdown_NoSection(t *testing.T) {
	d := &DiffResult{SchemaVersion: DiffSchemaVersion, OldPath: "a", NewPath: "b"}
	md := RenderMarkdownReport(d)
	if strings.Contains(md, "## Visual Regressions") {
		t.Fatalf("did not expect Visual Regressions section, got:\n%s", md)
	}
}

func TestDiffMarkdown_WithSection(t *testing.T) {
	d := &DiffResult{
		SchemaVersion: DiffSchemaVersion,
		OldPath:       "a",
		NewPath:       "b",
		Visual: &visualdiff.VisualResult{
			OldRunID: "run-old",
			NewRunID: "run-new",
			States: map[string]*visualdiff.StateVisualDiff{
				"Login/default": {
					Image: &visualdiff.ImageDiff{HashDistance: 20, Severity: visualdiff.SeverityBLOCK},
				},
				"Signup/default": {
					Image: &visualdiff.ImageDiff{HashDistance: 8, Severity: visualdiff.SeverityFLAG},
				},
				"Home/default": {
					Image: &visualdiff.ImageDiff{HashDistance: 0, Severity: visualdiff.SeverityPASS},
				},
			},
			Added:   []string{"NewState/default"},
			Removed: []string{"OldState/default"},
			Summary: "1 added, 1 removed, 3 compared",
		},
	}
	md := RenderMarkdownReport(d)
	if !strings.Contains(md, "## Visual Regressions") {
		t.Fatalf("missing Visual Regressions section")
	}
	for _, badge := range []string{"**[BLOCK]**", "**[FLAG]**", "**[PASS]**"} {
		if !strings.Contains(md, badge) {
			t.Errorf("missing badge %q in markdown:\n%s", badge, md)
		}
	}
}

func TestDiffSchemaVersionUnchanged(t *testing.T) {
	if DiffSchemaVersion != 2 {
		t.Fatalf("DiffSchemaVersion changed: got %d want 2", DiffSchemaVersion)
	}
}

func TestDiffMarkdown_NoEmojis(t *testing.T) {
	d := &DiffResult{
		SchemaVersion: DiffSchemaVersion,
		OldPath:       "a",
		NewPath:       "b",
		Visual: &visualdiff.VisualResult{
			States: map[string]*visualdiff.StateVisualDiff{
				"X/y": {
					Image: &visualdiff.ImageDiff{HashDistance: 9, Severity: visualdiff.SeverityFLAG},
				},
			},
			Summary: "test",
		},
	}
	md := RenderMarkdownReport(d)
	for _, r := range md {
		// Reject emoji ranges: Misc Symbols & Pictographs, Emoticons,
		// Supplemental Symbols & Pictographs.
		if (r >= 0x1F000 && r <= 0x1FFFF) || (r >= 0x2600 && r <= 0x27BF) {
			t.Fatalf("emoji rune U+%04X found in markdown output", r)
		}
		if !utf8.ValidRune(r) {
			t.Fatalf("invalid rune in markdown output")
		}
	}
}
