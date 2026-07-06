package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner_Scan(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	createFile(t, dir, "main.cpp", "#include <iostream>\nint main() {}")
	createFile(t, dir, "util.h", "#pragma once\nvoid util();")
	createFile(t, dir, "readme.txt", "not a C++ file")
	createFile(t, dir, "data.json", "{}")

	// Create subdirectory with a file
	subDir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, subDir, "helper.hpp", "template<typename T> class Helper {};")

	scanner := NewScanner(dir)

	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(files) != 3 {
		t.Errorf("Scan() got %d files, want 3", len(files))

		for _, f := range files {
			t.Logf("  %s", f.RelPath)
		}
	}

	// Check that non-source files are excluded
	for _, f := range files {
		ext := filepath.Ext(f.Path)
		if _, ok := allExtensions[ext]; !ok {
			t.Errorf("unexpected file extension: %s", f.Path)
		}
	}
}

func TestScanner_ExcludesDirs(t *testing.T) {
	dir := t.TempDir()

	createFile(t, dir, "main.cpp", "int main() {}")

	// Create .git directory with a file
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, gitDir, "HEAD.cpp", "should be excluded")

	// Create build directory
	buildDir := filepath.Join(dir, "build")
	if err := os.MkdirAll(buildDir, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, buildDir, "gen.cpp", "should be excluded")

	// Create cmake-build-debug directory
	cmakeDir := filepath.Join(dir, "cmake-build-debug")
	if err := os.MkdirAll(cmakeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, cmakeDir, "gen.cpp", "should be excluded")

	scanner := NewScanner(dir)

	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(files) != 1 {
		t.Errorf("Scan() got %d files, want 1", len(files))

		for _, f := range files {
			t.Logf("  %s", f.RelPath)
		}
	}
}

func TestScanner_MaxDepth(t *testing.T) {
	dir := t.TempDir()

	createFile(t, dir, "root.cpp", "int main() {}")

	level1 := filepath.Join(dir, "level1")
	if err := os.MkdirAll(level1, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, level1, "l1.cpp", "void l1() {}")

	level2 := filepath.Join(level1, "level2")
	if err := os.MkdirAll(level2, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, level2, "l2.cpp", "void l2() {}")

	scanner := NewScanner(dir)
	scanner.MaxDepth = 1

	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	// Should only get root.cpp (depth 0) since MaxDepth=1 skips level1/
	if len(files) != 1 {
		t.Errorf("Scan() with MaxDepth=1 got %d files, want 1", len(files))

		for _, f := range files {
			t.Logf("  %s", f.RelPath)
		}
	}
}

func TestClassifyLanguage(t *testing.T) {
	tests := []struct {
		ext  string
		want string
	}{
		{".c", "C Source"},
		{".cpp", "C++ Source"},
		{".cc", "C++ Source"},
		{".h", "C/C++ Header"},
		{".hpp", "C++ Header"},
		{".hxx", "C++ Header"},
	}

	for _, tt := range tests {
		got := classifyLanguage(tt.ext)
		if got != tt.want {
			t.Errorf("classifyLanguage(%q) = %q, want %q", tt.ext, got, tt.want)
		}
	}
}

func TestScanner_CFiles(t *testing.T) {
	dir := t.TempDir()

	createFile(t, dir, "main.c", "#include <stdio.h>\nint main() { return 0; }")
	createFile(t, dir, "util.c", "#include <stdlib.h>\nvoid util() {}")
	createFile(t, dir, "header.h", "#pragma once\nvoid util();")
	createFile(t, dir, "app.cpp", "#include <iostream>\nint main() {}")

	scanner := NewScanner(dir)

	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(files) != 4 {
		t.Errorf("Scan() got %d files, want 4", len(files))

		for _, f := range files {
			t.Logf("  %s (%s)", f.RelPath, f.Language)
		}
	}

	// Check language classification
	langCount := make(map[string]int)
	for _, f := range files {
		langCount[f.Language]++
	}

	if langCount["C Source"] != 2 {
		t.Errorf("expected 2 C Source files, got %d", langCount["C Source"])
	}

	if langCount["C/C++ Header"] != 1 {
		t.Errorf("expected 1 C/C++ Header file, got %d", langCount["C/C++ Header"])
	}

	if langCount["C++ Source"] != 1 {
		t.Errorf("expected 1 C++ Source file, got %d", langCount["C++ Source"])
	}
}

func TestSourceFileRelPath(t *testing.T) {
	dir := t.TempDir()

	sub := filepath.Join(dir, "src", "net")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	createFile(t, sub, "socket.cpp", "void connect() {}")

	scanner := NewScanner(dir)

	files, err := scanner.Scan()
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}

	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}

	want := "src/net/socket.cpp"
	if files[0].RelPath != want {
		t.Errorf("RelPath = %q, want %q", files[0].RelPath, want)
	}
}

func createFile(t *testing.T, dir, name, content string) {
	t.Helper()

	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
