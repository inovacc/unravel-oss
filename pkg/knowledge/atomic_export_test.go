/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomicExported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.txt")
	if err := WriteFileAtomic(p, []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("expected hello, got %q", got)
	}
}

func TestWriteJSONAtomicExported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "out.json")
	if err := WriteJSONAtomic(p, map[string]int{"a": 1}); err != nil {
		t.Fatalf("WriteJSONAtomic: %v", err)
	}
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) == "" {
		t.Fatal("empty file")
	}
}
