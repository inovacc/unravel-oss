/*
Copyright (c) 2026 Security Research
*/
package bun

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildBunPE wraps a .bun section blob in a minimal PE so Analyze/Extract can
// parse it through the normal PE-section path.
func buildBunPE(t *testing.T, section []byte) string {
	t.Helper()
	pe := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".text", data: make([]byte, 512)},
		{name: ".bun", data: section},
	})
	return writeTempFile(t, "app.exe", pe)
}

// TestExtract_PathTraversal_Skipped feeds a Bun binary whose module-graph entry
// names point outside outputDir (POSIX `..` escape and a Windows volume-rooted
// path). The extractor MUST skip those entries rather than write outside the
// destination dir (arbitrary file write). Finding #1.
func TestExtract_PathTraversal_Skipped(t *testing.T) {
	section := buildBunSectionData([]struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "../escape.txt", contents: "PWNED", loader: LoaderJS},
		{path: "C:/Windows/Temp/escape2.txt", contents: "PWNED", loader: LoaderJS},
		{path: "legit.js", contents: "ok", loader: LoaderJS},
	}, 2)

	path := buildBunPE(t, section)

	// Sandbox: outputDir is a subdir of root. The "../escape.txt" entry, if not
	// contained, would land in root (one level up) — still inside our sandbox,
	// so a regression cannot pollute the real filesystem. We then assert root
	// holds nothing but the out/ subtree.
	root := t.TempDir()
	out := filepath.Join(root, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}

	if _, err := Extract(path, out, false); err != nil {
		t.Fatalf("Extract returned error: %v", err)
	}

	// Nothing must escape out/: the only entry in root besides out/ would be a
	// leaked escape file.
	if _, err := os.Stat(filepath.Join(root, "escape.txt")); err == nil {
		t.Fatalf("path traversal: ../escape.txt escaped outputDir into %s", root)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read root: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "out" {
			t.Fatalf("unexpected entry escaped into root: %s", e.Name())
		}
	}

	// Every written file must stay under out/.
	_ = filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(out, p)
		if relErr != nil || strings.HasPrefix(rel, "..") {
			t.Fatalf("file %s escaped outputDir (rel=%s)", p, rel)
		}
		return nil
	})

	// The legit entry should still be extracted.
	if _, err := os.Stat(filepath.Join(out, "legit.js")); err != nil {
		t.Fatalf("legit entry not extracted: %v", err)
	}
}

// TestExtractBunSectionPE_OverflowDataLength feeds a .bun section whose u64
// data_length has the high bit set (0xFFFFFFFFFFFFFFFF). A signed-int narrowing
// of the bound check would slice sectionData[8:7] and panic. Finding #5.
func TestExtractBunSectionPE_OverflowDataLength(t *testing.T) {
	section := make([]byte, 24)
	binary.LittleEndian.PutUint64(section[0:8], 0xFFFFFFFFFFFFFFFF)
	pe := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".bun", data: section},
	})

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("extractBunSectionPE panicked on overflow data_length: %v", r)
		}
	}()

	if _, err := extractBunSectionPE(pe); err == nil {
		t.Fatalf("expected error for oversized data_length, got nil")
	}
}

// TestAnalyze_ModuleOffsetWrap crafts a module-graph blob whose name
// StringPointer offset+length wraps in uint32 (nameOff=0xFFFFFFFF, nameLen=2).
// A uint32 bound check is bypassed and rawBytes[0xFFFFFFFF:1] panics. The
// contents path is exercised the same way. Finding #6.
func TestAnalyze_ModuleOffsetWrap(t *testing.T) {
	// Build a minimal valid blob first, then corrupt one module entry's name
	// pointer to the wrapping (0xFFFFFFFF, 2) values.
	section := buildBunSectionData([]struct {
		path     string
		contents string
		loader   byte
	}{
		{path: "index.js", contents: "x", loader: LoaderJS},
	}, 0)

	// section = [u64 data_length][blob]. The module entry lives inside the
	// blob; rather than hand-locate it, rebuild a blob where the single module
	// entry carries wrapping offsets. We patch the first 8 bytes of the first
	// module entry. Locate the modules region via the Offsets struct.
	blob := section[sectionHdrSz:]
	trailerStart := len(blob) - trailerSize
	offsStart := trailerStart - offsetsSize
	offs := blob[offsStart:trailerStart]
	modulesPtrOffset := binary.LittleEndian.Uint32(offs[8:12])

	entry := blob[modulesPtrOffset : modulesPtrOffset+moduleSize]
	binary.LittleEndian.PutUint32(entry[0:4], 0xFFFFFFFF)  // nameOff
	binary.LittleEndian.PutUint32(entry[4:8], 0x2)         // nameLen -> wraps to 1
	binary.LittleEndian.PutUint32(entry[8:12], 0xFFFFFFFF) // contentsOff
	binary.LittleEndian.PutUint32(entry[12:16], 0x2)       // contentsLen -> wraps to 1

	pe := buildMinimalPE([]struct {
		name string
		data []byte
	}{
		{name: ".text", data: make([]byte, 512)},
		{name: ".bun", data: section},
	})
	path := writeTempFile(t, "wrap.exe", pe)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Analyze panicked on wrapping module offsets: %v", r)
		}
	}()

	// Must not panic; the wrapping entry is simply skipped.
	if _, err := Analyze(path); err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}
}
