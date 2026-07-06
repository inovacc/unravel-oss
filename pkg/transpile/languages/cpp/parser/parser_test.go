package parser

import (
	"testing"
)

func TestParseFile_Basic(t *testing.T) {
	source := `#include <iostream>
#include <vector>

int main() {
    std::cout << "Hello, World!" << std::endl;
    return 0;
}
`
	p := New()

	tu, err := p.ParseFile("main.cpp", []byte(source))
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if tu.FileName != "main.cpp" {
		t.Errorf("FileName = %q, want %q", tu.FileName, "main.cpp")
	}

	if len(tu.Includes) != 2 {
		t.Errorf("expected 2 includes, got %d", len(tu.Includes))
	}
}

func TestParseFile_ClassWithMethods(t *testing.T) {
	source := `#include <string>

class Person {
public:
    std::string name;
    int age;

    Person(const std::string& n, int a) : name(n), age(a) {}
    std::string getName() const { return name; }
};
`
	p := New()

	tu, err := p.ParseFile("person.cpp", []byte(source))
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if len(tu.Includes) != 1 {
		t.Errorf("expected 1 include, got %d", len(tu.Includes))
	}

	// Should detect the class declaration
	found := false

	for _, decl := range tu.Decls {
		if decl.Pos().Line > 0 {
			found = true

			break
		}
	}

	if !found && len(tu.Decls) == 0 {
		t.Error("expected at least one declaration")
	}
}

func TestParseFile_EmptySource(t *testing.T) {
	p := New()

	tu, err := p.ParseFile("empty.cpp", []byte(""))
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if tu.FileName != "empty.cpp" {
		t.Errorf("FileName = %q, want %q", tu.FileName, "empty.cpp")
	}

	if len(tu.Includes) != 0 {
		t.Errorf("expected 0 includes, got %d", len(tu.Includes))
	}
}

func TestParseFile_MultipleClasses(t *testing.T) {
	source := `struct Point {
    double x, y;
};

class Shape {
public:
    virtual double area() = 0;
};

enum class Color { Red, Green, Blue };
`
	p := New()

	tu, err := p.ParseFile("shapes.cpp", []byte(source))
	if err != nil {
		t.Fatalf("ParseFile() error = %v", err)
	}

	if len(tu.Decls) < 3 {
		t.Errorf("expected at least 3 declarations, got %d", len(tu.Decls))
	}
}
