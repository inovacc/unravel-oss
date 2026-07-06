/*
Copyright (c) 2026 Security Research
*/
package asar

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadFileContent_NegativeSizeRejected feeds a negative entry Size (as an
// attacker would by setting "size": -1 in the ASAR header JSON). Without a guard
// this reaches make([]byte, size) -> "makeslice: len out of range" panic, which
// crashes the MCP asar_search handler. The reader MUST return an error instead.
// Finding #3.
func TestReadFileContent_NegativeSizeRejected(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(p, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatalf("open temp: %v", err)
	}
	defer func() { _ = f.Close() }()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ReadFileContent panicked on negative size: %v", r)
		}
	}()

	for _, tc := range []struct {
		name                         string
		dataOffset, fileOffset, size int64
	}{
		{"negative size", 0, 0, -1},
		{"negative file offset", 0, -1, 4},
		{"negative data offset", -1, 0, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ReadFileContent(f, tc.dataOffset, tc.fileOffset, tc.size); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}
