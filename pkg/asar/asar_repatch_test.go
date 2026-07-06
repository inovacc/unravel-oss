/*
Copyright (c) 2026 Security Research
*/

package asar

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// buildFixtureASAR writes a minimal ASAR with two files (a.txt, b.txt) at path.
func buildFixtureASAR(t *testing.T, path string, aBytes, bBytes []byte) {
	t.Helper()

	var data []byte
	aOff := int64(len(data))
	data = append(data, aBytes...)
	bOff := int64(len(data))
	data = append(data, bBytes...)

	hdr := Header{
		Files: map[string]*FileEntry{
			"a.txt": {Offset: fmt.Sprintf("%d", aOff), Size: int64(len(aBytes))},
			"b.txt": {Offset: fmt.Sprintf("%d", bOff), Size: int64(len(bBytes))},
		},
	}
	hdrJSON, err := json.Marshal(hdr)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	padLen := (4 - (len(hdrJSON) % 4)) % 4
	padded := make([]byte, len(hdrJSON)+padLen)
	copy(padded, hdrJSON)
	for i := len(hdrJSON); i < len(padded); i++ {
		padded[i] = ' '
	}

	prefix := make([]byte, 16)
	headerSize := uint32(8 + len(padded))
	binary.LittleEndian.PutUint32(prefix[0:4], 4)
	binary.LittleEndian.PutUint32(prefix[4:8], headerSize)
	binary.LittleEndian.PutUint32(prefix[8:12], headerSize-4)
	binary.LittleEndian.PutUint32(prefix[12:16], uint32(len(hdrJSON)))

	out := append(append(prefix, padded...), data...)
	if err := os.WriteFile(path, out, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func readEntry(t *testing.T, path, name string) []byte {
	t.Helper()
	f, hdr, _, dataOff, err := OpenAndParse(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	entry := hdr.Files[name]
	if entry == nil {
		t.Fatalf("entry %s missing", name)
	}
	var off int64
	_, _ = fmt.Sscanf(entry.Offset, "%d", &off)
	b, err := ReadFileContent(f, dataOff, off, entry.Size)
	if err != nil {
		t.Fatalf("read content: %v", err)
	}
	return b
}

func TestRepatch_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.asar")
	dst := filepath.Join(dir, "dst.asar")

	a := []byte("alpha-content")
	b := []byte("bravo-content-original")
	buildFixtureASAR(t, src, a, b)

	repl := []byte("BRAVO-REPLACED")
	if err := Repatch(src, dst, map[string][]byte{"b.txt": repl}); err != nil {
		t.Fatalf("Repatch: %v", err)
	}

	gotA := readEntry(t, dst, "a.txt")
	if !bytes.Equal(gotA, a) {
		t.Errorf("a.txt mutated: got %q want %q", gotA, a)
	}
	gotB := readEntry(t, dst, "b.txt")
	if !bytes.Equal(gotB, repl) {
		t.Errorf("b.txt not replaced: got %q want %q", gotB, repl)
	}
}

func TestRepatch_MissingEntry(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.asar")
	dst := filepath.Join(dir, "dst.asar")
	buildFixtureASAR(t, src, []byte("a"), []byte("b"))

	err := Repatch(src, dst, map[string][]byte{"nope.txt": []byte("x")})
	if !errors.Is(err, ErrAsarRepatchEntryNotFound) {
		t.Fatalf("want ErrAsarRepatchEntryNotFound, got %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("dst should not exist on error, stat=%v", statErr)
	}
}

func TestRepatch_RejectsSamePath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.asar")
	buildFixtureASAR(t, src, []byte("a"), []byte("b"))

	if err := Repatch(src, src, nil); !errors.Is(err, ErrAsarRepatchSamePath) {
		t.Fatalf("want ErrAsarRepatchSamePath, got %v", err)
	}
}

func TestRepatch_AtomicityOnSrcMissing(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "dst.asar")
	err := Repatch(filepath.Join(dir, "does-not-exist.asar"), dst, nil)
	if err == nil {
		t.Fatal("want error on missing src")
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Errorf("dst should not exist on error, stat=%v", statErr)
	}
}

func TestRepatchWithPreloadInject(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.asar")
	dst := filepath.Join(dir, "dst.asar")
	buildFixtureASAR(t, src, []byte("main"), []byte("old-preload"))

	js := []byte("// new preload\n")
	// fixture uses b.txt as the "preload" placeholder for path testing
	if err := RepatchWithPreloadInject(src, dst, "b.txt", js); err != nil {
		t.Fatalf("RepatchWithPreloadInject: %v", err)
	}
	got := readEntry(t, dst, "b.txt")
	if !bytes.Equal(got, js) {
		t.Errorf("preload not replaced: got %q", got)
	}
}
