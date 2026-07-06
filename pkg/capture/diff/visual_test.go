/*
Copyright (c) 2026 Security Research

visual_test.go — Phase 8 visual diff unit tests.
*/
package diff

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

// makeSolidPNG produces a w×h solid-color PNG.
func makeSolidPNG(t *testing.T, w, h int, c color.RGBA) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// makeJitteredPNG returns the same image with a single 1-pixel adjacent-color
// tweak — close enough to a re-encode with sub-pixel AA jitter that dHash
// distance stays within the PASS threshold.
func makeJitteredPNG(t *testing.T, w, h int, c color.RGBA) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, c)
		}
	}
	// Tweak two corner pixels only — minimal perturbation.
	jc := color.RGBA{R: c.R ^ 0x01, G: c.G, B: c.B, A: c.A}
	img.Set(0, 0, jc)
	img.Set(w-1, h-1, jc)
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// makeGradientPNG produces a horizontal red→blue gradient.
func makeGradientPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			f := uint8((x * 255) / w)
			img.Set(x, y, color.RGBA{R: 255 - f, G: 0, B: f, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

// makeCheckerPNG produces a checkerboard (visually very different from
// gradient → many high-bit Hamming differences after dHash).
func makeCheckerPNG(t *testing.T, w, h, cell int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			if ((x/cell)+(y/cell))%2 == 0 {
				img.Set(x, y, color.RGBA{R: 255, G: 255, B: 255, A: 255})
			} else {
				img.Set(x, y, color.RGBA{A: 255})
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return buf.Bytes()
}

func TestDiffImages_Identical(t *testing.T) {
	red := color.RGBA{R: 255, A: 255}
	a := makeSolidPNG(t, 64, 64, red)
	b := append([]byte(nil), a...)
	id, err := DiffImages(a, b)
	if err != nil {
		t.Fatalf("DiffImages: %v", err)
	}
	if !id.SHA256Match || !id.PHashMatch || id.HashDistance != 0 {
		t.Fatalf("expected identical match, got %+v", id)
	}
	if id.Severity != SeverityPASS {
		t.Fatalf("severity = %s, want PASS", id.Severity)
	}
}

func TestDiffImages_AAJitter(t *testing.T) {
	red := color.RGBA{R: 200, G: 30, B: 30, A: 255}
	a := makeSolidPNG(t, 64, 64, red)
	b := makeJitteredPNG(t, 64, 64, red)
	id, err := DiffImages(a, b)
	if err != nil {
		t.Fatalf("DiffImages: %v", err)
	}
	if id.SHA256Match {
		t.Fatalf("expected SHA mismatch for jittered PNG")
	}
	if id.HashDistance > DHashHammingPASS {
		t.Fatalf("expected dHash distance <= %d for AA jitter, got %d", DHashHammingPASS, id.HashDistance)
	}
	if id.Severity != SeverityPASS {
		t.Fatalf("severity = %s, want PASS", id.Severity)
	}
	if !id.PHashMatch {
		t.Fatalf("PHashMatch should be true for distance <= PASS threshold")
	}
}

func TestDiffImages_Different(t *testing.T) {
	a := makeGradientPNG(t, 64, 64)
	b := makeCheckerPNG(t, 64, 64, 8)
	id, err := DiffImages(a, b)
	if err != nil {
		t.Fatalf("DiffImages: %v", err)
	}
	if id.SHA256Match {
		t.Fatalf("expected SHA mismatch")
	}
	if id.PHashMatch {
		t.Fatalf("PHashMatch should be false for visually different PNGs")
	}
	if id.HashDistance <= DHashHammingFLAG {
		t.Fatalf("expected distance > %d, got %d", DHashHammingFLAG, id.HashDistance)
	}
	if id.Severity != SeverityBLOCK {
		t.Fatalf("severity = %s, want BLOCK", id.Severity)
	}
}

func TestDiffImages_DecodeFailure(t *testing.T) {
	bad := []byte("not a png")
	good := makeSolidPNG(t, 16, 16, color.RGBA{R: 1, A: 255})
	if _, err := DiffImages(bad, good); err == nil {
		t.Fatalf("expected decode error for bogus old png")
	}
	if _, err := DiffImages(good, bad); err == nil {
		t.Fatalf("expected decode error for bogus new png")
	}
}

func TestDiffImages_OversizedRejected(t *testing.T) {
	// A buffer larger than MaxImageBytes triggers the cap check before decode.
	huge := make([]byte, MaxImageBytes+1)
	if _, err := DiffImages(huge, huge); err == nil {
		t.Fatalf("expected oversize rejection")
	}
}

func TestTreeDiff_AddedRemoved(t *testing.T) {
	oldJSON := []byte(`{"tag":"div","dom_path":"/root","children":[
        {"tag":"a","dom_path":"/root/A","children":[]},
        {"tag":"b","dom_path":"/root/B","children":[]}
    ]}`)
	newJSON := []byte(`{"tag":"div","dom_path":"/root","children":[
        {"tag":"a","dom_path":"/root/A","children":[]},
        {"tag":"c","dom_path":"/root/C","children":[]}
    ]}`)
	td, err := DiffTrees(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("DiffTrees: %v", err)
	}
	if len(td.Added) != 1 || td.Added[0] != "/root/C" {
		t.Fatalf("Added = %v", td.Added)
	}
	if len(td.Removed) != 1 || td.Removed[0] != "/root/B" {
		t.Fatalf("Removed = %v", td.Removed)
	}
	if td.Severity != SeverityFLAG {
		t.Fatalf("severity = %s, want FLAG", td.Severity)
	}
}

func TestTreeDiff_Moved(t *testing.T) {
	// Same dom_path but different tag = moved/changed element.
	oldJSON := []byte(`{"tag":"div","dom_path":"/root","children":[
        {"tag":"span","dom_path":"/root/A","children":[]}
    ]}`)
	newJSON := []byte(`{"tag":"div","dom_path":"/root","children":[
        {"tag":"button","dom_path":"/root/A","children":[]}
    ]}`)
	td, err := DiffTrees(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("DiffTrees: %v", err)
	}
	if len(td.Moved) != 1 || td.Moved[0] != "/root/A" {
		t.Fatalf("Moved = %v", td.Moved)
	}
}

func TestBoundsDiff_PixelMovement(t *testing.T) {
	oldJSON := []byte(`[{"dom_path":"/a","x":0,"y":0,"w":100,"h":50}]`)
	newJSON := []byte(`[{"dom_path":"/a","x":0,"y":5,"w":100,"h":50}]`)
	ld, err := DiffLayouts(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("DiffLayouts: %v", err)
	}
	if len(ld.Movements) != 1 || ld.Movements[0].DY != 5 {
		t.Fatalf("Movements = %+v", ld.Movements)
	}
	if ld.Severity != SeverityFLAG {
		t.Fatalf("severity = %s, want FLAG", ld.Severity)
	}

	// Sub-threshold movement must not be recorded.
	subJSON := []byte(`[{"dom_path":"/a","x":0,"y":2,"w":100,"h":50}]`)
	ld2, err := DiffLayouts(oldJSON, subJSON)
	if err != nil {
		t.Fatalf("DiffLayouts: %v", err)
	}
	if len(ld2.Movements) != 0 {
		t.Fatalf("expected no movements for <4px shift, got %v", ld2.Movements)
	}
}

func TestBoundsDiff_SizeChange(t *testing.T) {
	oldJSON := []byte(`[{"dom_path":"/a","x":0,"y":0,"w":100,"h":50}]`)
	newJSON := []byte(`[{"dom_path":"/a","x":0,"y":0,"w":120,"h":50}]`) // +20% width
	ld, err := DiffLayouts(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("DiffLayouts: %v", err)
	}
	if len(ld.SizeChanges) != 1 || ld.SizeChanges[0].DW != 20 {
		t.Fatalf("SizeChanges = %+v", ld.SizeChanges)
	}
	// Sub-threshold (5%) must not be recorded.
	subJSON := []byte(`[{"dom_path":"/a","x":0,"y":0,"w":105,"h":50}]`)
	ld2, err := DiffLayouts(oldJSON, subJSON)
	if err != nil {
		t.Fatalf("DiffLayouts: %v", err)
	}
	if len(ld2.SizeChanges) != 0 {
		t.Fatalf("expected no size changes for 5%% delta, got %+v", ld2.SizeChanges)
	}
}

func TestSeverity_Mapping(t *testing.T) {
	cases := []struct {
		dist int
		want Severity
	}{
		{0, SeverityPASS},
		{5, SeverityPASS},
		{6, SeverityFLAG},
		{8, SeverityFLAG},
		{15, SeverityFLAG},
		{16, SeverityBLOCK},
		{20, SeverityBLOCK},
	}
	for _, c := range cases {
		got := severityForHamming(c.dist)
		if got != c.want {
			t.Errorf("severityForHamming(%d) = %s, want %s", c.dist, got, c.want)
		}
	}
}

func TestCompare_TwoStateDirs(t *testing.T) {
	tmp := t.TempDir()
	oldRun := filepath.Join(tmp, "run-old")
	newRun := filepath.Join(tmp, "run-new")
	for _, root := range []string{oldRun, newRun} {
		dir := filepath.Join(root, "Login", "default")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	red := color.RGBA{R: 200, A: 255}
	pngOld := makeSolidPNG(t, 64, 64, red)
	pngNew := makeJitteredPNG(t, 64, 64, red)

	tree := []byte(`{"tag":"div","dom_path":"/root","children":[]}`)
	layoutOld := []byte(`[{"dom_path":"/a","x":0,"y":0,"w":100,"h":50}]`)
	layoutNew := []byte(`[{"dom_path":"/a","x":0,"y":10,"w":100,"h":50}]`)

	writeFile(t, filepath.Join(oldRun, "Login", "default", "screenshot.png"), pngOld)
	writeFile(t, filepath.Join(newRun, "Login", "default", "screenshot.png"), pngNew)
	writeFile(t, filepath.Join(oldRun, "Login", "default", "tree.json"), tree)
	writeFile(t, filepath.Join(newRun, "Login", "default", "tree.json"), tree)
	writeFile(t, filepath.Join(oldRun, "Login", "default", "layout.json"), layoutOld)
	writeFile(t, filepath.Join(newRun, "Login", "default", "layout.json"), layoutNew)

	res, err := CompareVisual(oldRun, newRun)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	sd, ok := res.States["Login/default"]
	if !ok {
		t.Fatalf("missing Login/default in result; got %v", res.States)
	}
	if sd.Image == nil || sd.Tree == nil || sd.Layout == nil {
		t.Fatalf("expected all three sub-diffs populated, got %+v", sd)
	}
	if sd.Image.Severity != SeverityPASS {
		t.Errorf("image severity = %s, want PASS", sd.Image.Severity)
	}
	if len(sd.Layout.Movements) != 1 {
		t.Errorf("layout movements = %v", sd.Layout.Movements)
	}
}

func TestCompare_StateAddedRemoved(t *testing.T) {
	tmp := t.TempDir()
	oldRun := filepath.Join(tmp, "run-old")
	newRun := filepath.Join(tmp, "run-new")
	if err := os.MkdirAll(filepath.Join(oldRun, "Login", "default"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(newRun, "Login", "default"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(newRun, "Signup", "default"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	res, err := CompareVisual(oldRun, newRun)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(res.Added) != 1 || res.Added[0] != "Signup/default" {
		t.Fatalf("Added = %v", res.Added)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("Removed = %v", res.Removed)
	}
}

func TestCompare_PathTraversalRejected(t *testing.T) {
	if _, err := CompareVisual("../evil", "."); err == nil {
		t.Fatalf("expected traversal rejection")
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
