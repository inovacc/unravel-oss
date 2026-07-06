package parser

import (
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/javamodel"
)

func TestParseSimpleClass(t *testing.T) {
	source, err := os.ReadFile("../../../testdata/java/simple_class.java")
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	p := New()

	module, err := p.ParseFile("simple_class.java", source)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if module.FileName != "simple_class.java" {
		t.Errorf("filename = %q, want %q", module.FileName, "simple_class.java")
	}

	if module.Package != "com.example" {
		t.Errorf("package = %q, want %q", module.Package, "com.example")
	}

	if len(module.Imports) != 2 {
		t.Errorf("imports = %d, want 2", len(module.Imports))
	}

	if len(module.Types) != 1 {
		t.Fatalf("types = %d, want 1", len(module.Types))
	}

	cls := module.Types[0]
	if cls.Type != javamodel.NodeClass {
		t.Errorf("type = %q, want %q", cls.Type, javamodel.NodeClass)
	}

	if cls.Name != "SimpleClass" {
		t.Errorf("name = %q, want %q", cls.Name, "SimpleClass")
	}

	// Should have fields, constructor, methods
	if len(cls.Children) == 0 {
		t.Error("expected class to have children (fields, methods)")
	}

	var fieldCount, methodCount, constructorCount int

	for _, child := range cls.Children {
		switch child.Type {
		case javamodel.NodeField:
			fieldCount++
		case javamodel.NodeMethod:
			methodCount++
		case javamodel.NodeConstructor:
			constructorCount++
		}
	}

	if fieldCount < 3 {
		t.Errorf("fields = %d, want >= 3", fieldCount)
	}

	if constructorCount != 1 {
		t.Errorf("constructors = %d, want 1", constructorCount)
	}

	if methodCount < 4 {
		t.Errorf("methods = %d, want >= 4", methodCount)
	}
}

func TestParseInterface(t *testing.T) {
	source, err := os.ReadFile("../../../testdata/java/interface.java")
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	p := New()

	module, err := p.ParseFile("interface.java", source)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(module.Types) != 1 {
		t.Fatalf("types = %d, want 1", len(module.Types))
	}

	iface := module.Types[0]
	if iface.Type != javamodel.NodeInterface {
		t.Errorf("type = %q, want %q", iface.Type, javamodel.NodeInterface)
	}

	if iface.Name != "Repository" {
		t.Errorf("name = %q, want %q", iface.Name, "Repository")
	}

	if len(iface.TypeParams) != 2 {
		t.Errorf("type params = %d, want 2", len(iface.TypeParams))
	}

	// Should have 6 methods
	if len(iface.Children) != 6 {
		t.Errorf("methods = %d, want 6", len(iface.Children))
	}
}

func TestParseEnum(t *testing.T) {
	source, err := os.ReadFile("../../../testdata/java/enum.java")
	if err != nil {
		t.Fatalf("read test file: %v", err)
	}

	p := New()

	module, err := p.ParseFile("enum.java", source)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(module.Types) != 1 {
		t.Fatalf("types = %d, want 1", len(module.Types))
	}

	enum := module.Types[0]
	if enum.Type != javamodel.NodeEnum {
		t.Errorf("type = %q, want %q", enum.Type, javamodel.NodeEnum)
	}

	if enum.Name != "Status" {
		t.Errorf("name = %q, want %q", enum.Name, "Status")
	}

	// Should have 4 enum constants + other members
	var constCount int

	for _, child := range enum.Children {
		if child.Type == javamodel.NodeField {
			if child.Metadata != nil && child.Metadata["kind"] == "enum_constant" {
				constCount++
			}
		}
	}

	if constCount != 4 {
		t.Errorf("enum constants = %d, want 4", constCount)
	}
}

func TestParseError(t *testing.T) {
	p := New()

	_, err := p.ParseFile("bad.java", []byte("this is not valid java {{{{"))
	if err == nil {
		t.Error("expected parse error for invalid Java")
	}
}
