package analysis

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildSymbolTable_Classes(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "person.cpp", `#include <string>

class Person {
public:
    Person(const std::string& name);
    ~Person();
    std::string getName() const;
    virtual void greet();
private:
    std::string name_;
};
`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "person.cpp"), RelPath: "person.cpp"},
	}

	st := BuildSymbolTable(files)

	if len(st.Classes) == 0 {
		t.Fatal("expected at least one class")
	}

	person, ok := st.Classes["Person"]
	if !ok {
		t.Fatal("Person class not found")
	}

	if person.Kind != "class" {
		t.Errorf("kind = %q, want 'class'", person.Kind)
	}

	if person.File != "person.cpp" {
		t.Errorf("file = %q, want 'person.cpp'", person.File)
	}
}

func TestBuildSymbolTable_Enums(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "types.h", `enum Color { Red, Green, Blue };
enum class Direction { North, South, East, West };
`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "types.h"), RelPath: "types.h"},
	}

	st := BuildSymbolTable(files)

	if len(st.Enums) < 2 {
		t.Fatalf("expected at least 2 enums, got %d", len(st.Enums))
	}

	color, ok := st.Enums["Color"]
	if !ok {
		t.Fatal("Color enum not found")
	}

	if color.Scoped {
		t.Error("Color should not be scoped")
	}

	dir2, ok := st.Enums["Direction"]
	if !ok {
		t.Fatal("Direction enum not found")
	}

	if !dir2.Scoped {
		t.Error("Direction should be scoped (enum class)")
	}
}

func TestBuildSymbolTable_Namespaces(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "a.cpp", `namespace mylib {
void foo();
}`)

	writeTestFile(t, dir, "b.cpp", `namespace mylib {
void bar();
}`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "a.cpp"), RelPath: "a.cpp"},
		{Path: filepath.Join(dir, "b.cpp"), RelPath: "b.cpp"},
	}

	st := BuildSymbolTable(files)

	ns, ok := st.Namespaces["mylib"]
	if !ok {
		t.Fatal("mylib namespace not found")
	}

	if len(ns.Files) != 2 {
		t.Errorf("namespace files = %d, want 2", len(ns.Files))
	}
}

func TestBuildSymbolTable_Structs(t *testing.T) {
	dir := t.TempDir()

	writeTestFile(t, dir, "point.h", `struct Point {
    int x;
    int y;
};
`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "point.h"), RelPath: "point.h"},
	}

	st := BuildSymbolTable(files)

	point, ok := st.Classes["Point"]
	if !ok {
		t.Fatal("Point struct not found in classes")
	}

	if point.Kind != "struct" {
		t.Errorf("kind = %q, want 'struct'", point.Kind)
	}
}

func TestBuildSymbolTable_DuplicateNames(t *testing.T) {
	dir := t.TempDir()

	// Two files with same class name
	if err := os.MkdirAll(filepath.Join(dir, "a"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(filepath.Join(dir, "b"), 0o755); err != nil {
		t.Fatal(err)
	}

	writeTestFile(t, filepath.Join(dir, "a"), "node.h", `class Node {};`)
	writeTestFile(t, filepath.Join(dir, "b"), "node.h", `class Node {};`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "a", "node.h"), RelPath: "a/node.h"},
		{Path: filepath.Join(dir, "b", "node.h"), RelPath: "b/node.h"},
	}

	st := BuildSymbolTable(files)

	// Should have both, one with qualified name
	if len(st.Classes) < 2 {
		t.Errorf("expected 2 classes for duplicate names, got %d", len(st.Classes))
	}
}
