/*
Copyright (c) 2026 Security Research
*/

package xaml

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

func TestWriteXAML_PathSanitization(t *testing.T) {
	out := t.TempDir()
	bad := winui.XAMLEntry{
		Path:      "../../etc/passwd",
		Kind:      "pe-embedded",
		Recovered: "<Page/>",
	}
	if err := WriteXAML(bad, "", out); err == nil {
		t.Fatalf("want traversal-rejection error")
	}
	// Confirm nothing landed outside outputDir.
	parent := filepath.Dir(out)
	if _, err := os.Stat(filepath.Join(parent, "passwd")); err == nil {
		t.Fatalf("file leaked outside outputDir")
	}
}

func TestWriteXAML_AtomicWrite_PEEmbedded(t *testing.T) {
	out := t.TempDir()
	e := winui.XAMLEntry{Path: "Page1.xaml", Kind: "pe-embedded", Recovered: "<Page/>"}
	if err := WriteXAML(e, "", out); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "Page1.xaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "<Page/>" {
		t.Fatalf("want <Page/>, got %q", got)
	}
	// No leftover temp files.
	ents, _ := os.ReadDir(out)
	for _, en := range ents {
		if filepath.Ext(en.Name()) != ".xaml" {
			t.Fatalf("leftover file: %q", en.Name())
		}
	}
}

func TestWriteXAML_FilenameCollision(t *testing.T) {
	out := t.TempDir()
	e := winui.XAMLEntry{Path: "Page.xaml", Kind: "pe-embedded", Recovered: "<a/>"}
	for i := range 3 {
		if err := WriteXAML(e, "", out); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	for _, want := range []string{"Page.xaml", "Page.1.xaml", "Page.2.xaml"} {
		if _, err := os.Stat(filepath.Join(out, want)); err != nil {
			t.Fatalf("missing %s: %v", want, err)
		}
	}
}

func TestWriteXAML_RawCopiesSource(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	src := filepath.Join(root, "sub", "Page.xaml")
	body := []byte("<Page xmlns:x=\"http://schemas.microsoft.com/winfx/2006/xaml\"/>")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	e := winui.XAMLEntry{Path: filepath.Join("sub", "Page.xaml"), Kind: "raw"}
	if err := WriteXAML(e, root, out); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(out, "sub_Page.xaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("content mismatch")
	}
}

func TestWriteXAML_OutputDirRequired(t *testing.T) {
	if err := WriteXAML(winui.XAMLEntry{Path: "x.xaml", Recovered: "<a/>", Kind: "pe-embedded"}, "", ""); err == nil {
		t.Fatalf("want error on empty outputDir")
	}
}
