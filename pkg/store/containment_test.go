/*
Copyright (c) 2026 Security Research

Path-containment guard tests (hardening finding #9). Store.Put and
Store.ReadFile join caller-supplied entry names to the entry directory; a
name of "../../evil" would otherwise escape it (arbitrary-file write/read).
*/
package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContainedJoin(t *testing.T) {
	root := filepath.Clean(t.TempDir())
	tests := []struct {
		name    string
		entry   string
		wantErr bool
	}{
		{"simple file", "result.json", false},
		{"nested file", "sub/file.json", false},
		{"deep nested", "a/b/c.bin", false},
		{"dot-slash prefix", "./result.json", false},
		{"parent escape", "../evil", true},
		{"deep parent escape", "../../evil", true},
		{"nested then escape", "sub/../../evil", true},
		{"bare parent", "..", true},
		{"absolute path", absForTest(), true},
		{"empty name", "", true},
		// Portable-store safety: names legal on Linux but dangerous when the
		// hash-keyed store is materialised on Windows must be rejected on every
		// OS (finding #9 / NTFS-ADS follow-up).
		{"ntfs ads stream", "good.txt::$DATA", true},
		{"drive-letter colon", "C:evil", true},
		{"backslash separator", `sub\evil`, true},
		{"reserved device con", "CON", true},
		{"reserved device nul with ext", "nul.txt", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := containedJoin(root, tc.entry)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("containedJoin(%q, %q) = %q, want error", root, tc.entry, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("containedJoin(%q, %q) unexpected error: %v", root, tc.entry, err)
			}
			rel, relErr := filepath.Rel(root, got)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				t.Fatalf("containedJoin(%q, %q) = %q escaped root", root, tc.entry, got)
			}
		})
	}
}

func absForTest() string {
	if os.PathSeparator == '\\' {
		return `C:\Windows\System32\evil`
	}
	return "/etc/evil"
}

// TestPut_RejectsTraversalName proves a malicious entry name cannot write
// outside the entry dir via Store.Put.
func TestPut_RejectsTraversalName(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "hello")

	canary := filepath.Join(filepath.Dir(s.baseDir), "escaped.txt")
	data := map[string][]byte{"../../../escaped.txt": []byte("pwned")}

	if _, err := s.Put(src, "dissect", nil, data); err == nil {
		t.Fatalf("Put with traversal name should error")
	}
	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("traversal name wrote outside entry dir: %s exists", canary)
	}
}

// TestReadFile_RejectsTraversalName proves Store.ReadFile cannot read outside
// the entry dir via a crafted filename.
func TestReadFile_RejectsTraversalName(t *testing.T) {
	s := testStore(t)
	src := writeSourceFile(t, "hello")

	e, err := s.Put(src, "dissect", nil, map[string][]byte{"result.json": []byte("{}")})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Plant a secret one level above the entry dir.
	secret := filepath.Join(filepath.Dir(e.CacheDir), "secret.txt")
	if err := os.WriteFile(secret, []byte("topsecret"), 0o644); err != nil {
		t.Fatalf("plant secret: %v", err)
	}

	if got, err := s.ReadFile(e.ID, "../secret.txt"); err == nil {
		t.Fatalf("ReadFile with traversal name should error, got %q", got)
	}
}
