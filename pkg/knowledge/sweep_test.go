/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTeardownFile is a small fixture helper that writes a beautified file
// alongside its sibling _meta.json record under teardown/.
func writeTeardownFile(t *testing.T, root, rel string, content []byte, meta map[string]any) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if meta != nil {
		mb, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full+"._meta.json", mb, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSweepReadsBeautifiedTree(t *testing.T) {
	td := t.TempDir()
	writeTeardownFile(t, td, "decompiled/java/com/foo/Bar.java",
		[]byte("package com.foo;\nclass Bar {}\n"),
		map[string]any{
			"beautify_provenance": "phase6-java",
			"raw_source_path":     "raw/java/com/foo/Bar.java",
		})

	got, err := SweepTeardown(td)
	if err != nil {
		t.Fatalf("SweepTeardown: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 source file, got %d", len(got))
	}
	sf := got[0]
	if !strings.HasSuffix(filepath.ToSlash(sf.Path), "Bar.java") {
		t.Errorf("path: want suffix Bar.java, got %q", sf.Path)
	}
	if sf.BeautifyProvenance != "phase6-java" {
		t.Errorf("provenance: got %q", sf.BeautifyProvenance)
	}
	if sf.RawSourcePath != "raw/java/com/foo/Bar.java" {
		t.Errorf("raw path: got %q", sf.RawSourcePath)
	}
	if len(sf.Content) == 0 {
		t.Error("content empty")
	}
}

func TestSweepIgnoresRawDecompiler(t *testing.T) {
	td := t.TempDir()
	// Files without an accompanying _meta.json should be ignored.
	writeTeardownFile(t, td, "raw/jadx/Foo.java", []byte("orphan"), nil)
	writeTeardownFile(t, td, "raw/apktool/AndroidManifest.xml", []byte("<m/>"), nil)

	got, err := SweepTeardown(td)
	if err != nil {
		t.Fatalf("SweepTeardown: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want 0 source files, got %d", len(got))
	}
}

func TestSweepRejectsTraversal(t *testing.T) {
	td := t.TempDir()
	writeTeardownFile(t, td, "decompiled/x.java",
		[]byte("ok"),
		map[string]any{
			"beautify_provenance": "phase6-java",
			"raw_source_path":     "../../escape.txt",
		})

	got, err := SweepTeardown(td)
	if err != nil {
		t.Fatalf("SweepTeardown: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].RawSourcePath != "" {
		t.Errorf("traversal not sanitized; got %q", got[0].RawSourcePath)
	}
}

func TestSweepBoundedMetaSize(t *testing.T) {
	td := t.TempDir()
	full := filepath.Join(td, "huge.java")
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// >256 KiB _meta.json
	big := bytes.Repeat([]byte("a"), 300*1024)
	if err := os.WriteFile(full+"._meta.json", big, 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := SweepTeardown(td)
	if err != nil {
		t.Fatalf("SweepTeardown returned error %v; want graceful skip", err)
	}
	// Oversized meta is rejected and the file is not emitted.
	if len(got) != 0 {
		t.Fatalf("want 0 (oversize meta rejected), got %d", len(got))
	}
}
