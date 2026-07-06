package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCountFile_Simple(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cpp")

	// 7 non-empty lines: include, blank, comment, code x4
	content := "#include <iostream>\n\n// This is a comment\nint main() {\n    std::cout << \"Hello\" << std::endl;\n    return 0;\n}"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountFile(path)
	if err != nil {
		t.Fatalf("CountFile() error = %v", err)
	}

	if stats.Lines != 7 {
		t.Errorf("Lines = %d, want 7", stats.Lines)
	}

	if stats.Blanks != 1 {
		t.Errorf("Blanks = %d, want 1", stats.Blanks)
	}

	if stats.Comments != 1 {
		t.Errorf("Comments = %d, want 1", stats.Comments)
	}

	if stats.Code != 5 {
		t.Errorf("Code = %d, want 5", stats.Code)
	}
}

func TestCountFile_BlockComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cpp")

	content := `/*
 * Multi-line
 * block comment
 */
int x = 42;
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountFile(path)
	if err != nil {
		t.Fatalf("CountFile() error = %v", err)
	}

	if stats.Comments != 4 {
		t.Errorf("Comments = %d, want 4", stats.Comments)
	}

	if stats.Code != 1 {
		t.Errorf("Code = %d, want 1", stats.Code)
	}
}

func TestCountFile_MixedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cpp")

	content := `int x = 42; // inline comment
int y = 0; /* block */ int z = 1;
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountFile(path)
	if err != nil {
		t.Fatalf("CountFile() error = %v", err)
	}

	// Both lines have code + comment = mixed, counted as code
	if stats.Code != 2 {
		t.Errorf("Code = %d, want 2", stats.Code)
	}
}

func TestCountFile_StringWithComment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.cpp")

	// The // inside the string should NOT be treated as a comment
	content := `std::string s = "hello // world";
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountFile(path)
	if err != nil {
		t.Fatalf("CountFile() error = %v", err)
	}

	if stats.Code != 1 {
		t.Errorf("Code = %d, want 1", stats.Code)
	}

	if stats.Comments != 0 {
		t.Errorf("Comments = %d, want 0", stats.Comments)
	}
}

func TestCountFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.cpp")

	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountFile(path)
	if err != nil {
		t.Fatalf("CountFile() error = %v", err)
	}

	if stats.Lines != 0 {
		t.Errorf("Lines = %d, want 0", stats.Lines)
	}
}

func TestCountFile_AllBlanks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blank.cpp")

	if err := os.WriteFile(path, []byte("\n\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	stats, err := CountFile(path)
	if err != nil {
		t.Fatalf("CountFile() error = %v", err)
	}

	if stats.Blanks != 3 {
		t.Errorf("Blanks = %d, want 3", stats.Blanks)
	}

	if stats.Code != 0 {
		t.Errorf("Code = %d, want 0", stats.Code)
	}
}

func TestLOCStats_Add(t *testing.T) {
	a := LOCStats{Lines: 10, Code: 7, Comments: 2, Blanks: 1}
	b := LOCStats{Lines: 5, Code: 3, Comments: 1, Blanks: 1}

	a.Add(b)

	if a.Lines != 15 {
		t.Errorf("Lines = %d, want 15", a.Lines)
	}

	if a.Code != 10 {
		t.Errorf("Code = %d, want 10", a.Code)
	}

	if a.Comments != 3 {
		t.Errorf("Comments = %d, want 3", a.Comments)
	}

	if a.Blanks != 2 {
		t.Errorf("Blanks = %d, want 2", a.Blanks)
	}
}
