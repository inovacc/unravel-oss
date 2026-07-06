/*
Copyright (c) 2026 Security Research
*/
package ipc

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateToken_UniqueAndLong(t *testing.T) {
	a, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	b, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken (second): %v", err)
	}
	if a == b {
		t.Fatal("two tokens identical — not random")
	}
	if len(a) != 43 { // 32 bytes base64url (no pad) == 43 chars
		t.Fatalf("token wrong length: got %d, want 43", len(a))
	}
}

func TestWriteTokenFile_RoundTripAndPerms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	tok := "deadbeef-token"
	if err := WriteTokenFile(path, tok); err != nil {
		t.Fatalf("WriteTokenFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != tok {
		t.Fatalf("round-trip mismatch: %q != %q", got, tok)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("perm = %v, want 0600", fi.Mode().Perm())
		}
	}
}
