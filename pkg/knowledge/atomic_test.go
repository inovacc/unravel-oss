/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAtomicWriteRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	// Use string concatenation — filepath.Join would Clean away the ".." segments
	// before they ever reach writeFileAtomic, defeating the test.
	sep := string(os.PathSeparator)
	cases := []string{
		dir + sep + ".." + sep + "escape.txt",
		dir + sep + "sub" + sep + ".." + sep + ".." + sep + ".." + sep + "escape.txt",
	}
	for _, p := range cases {
		err := writeFileAtomic(p, []byte("x"), 0o644)
		if !errors.Is(err, errPathTraversal) {
			t.Fatalf("path %q: want errPathTraversal, got %v", p, err)
		}
	}
}

func TestAtomicWriteRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires symlink privilege on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "real.txt")
	if err := os.WriteFile(target, []byte("real"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := writeFileAtomic(link, []byte("attacker"), 0o644)
	if !errors.Is(err, errSymlinkReject) {
		t.Fatalf("want errSymlinkReject, got %v", err)
	}
	// Original symlink target must remain untouched.
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != "real" {
		t.Fatalf("target was overwritten: %q", string(got))
	}
}

func TestAtomicWriteTempThenRename(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.txt")
	if err := writeFileAtomic(dest, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("got %q want hello", string(got))
	}
	// Temp file must not linger.
	tmp := dest + ".tmp"
	if _, err := os.Stat(tmp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tmp lingered: %v", err)
	}
}

func TestWriteJSONAtomic(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "doc.json")
	type doc struct {
		A int `json:"a"`
	}
	if err := writeJSONAtomic(dest, doc{A: 7}); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := "{\n  \"a\": 7\n}"
	if string(data) != want {
		t.Fatalf("got %q want %q", string(data), want)
	}
}
