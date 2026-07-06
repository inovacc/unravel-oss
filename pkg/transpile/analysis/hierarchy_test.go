package analysis

import (
	"testing"
)

func TestBuildHierarchy_Simple(t *testing.T) {
	symbols := &SymbolTable{
		Classes: map[string]*ClassInfo{
			"Animal": {
				Name:       "Animal",
				Kind:       "class",
				File:       "animal.h",
				HasVirtual: true,
				HasPure:    true,
				Methods:    []string{"speak"},
			},
			"Dog": {
				Name:        "Dog",
				Kind:        "class",
				File:        "dog.h",
				BaseClasses: []string{"Animal"},
				Methods:     []string{"speak", "fetch"},
			},
			"Cat": {
				Name:        "Cat",
				Kind:        "class",
				File:        "cat.h",
				BaseClasses: []string{"Animal"},
				Methods:     []string{"speak", "purr"},
			},
		},
		Functions:  make(map[string]*FunctionInfo),
		Enums:      make(map[string]*EnumInfo),
		Namespaces: make(map[string]*NamespaceInfo),
		Typedefs:   make(map[string]*TypedefInfo),
	}

	h := BuildHierarchy(symbols)

	// Animal should be a root (no parents in codebase)
	if len(h.Roots) != 1 {
		t.Errorf("roots = %d, want 1", len(h.Roots))
	}

	animal := h.ByName["Animal"]
	if animal == nil {
		t.Fatal("Animal not found")
	}

	if len(animal.Children) != 2 {
		t.Errorf("Animal children = %d, want 2", len(animal.Children))
	}

	// Dog and Cat should have Animal as parent
	dog := h.ByName["Dog"]
	if dog == nil {
		t.Fatal("Dog not found")
	}

	if len(dog.Parents) != 1 {
		t.Errorf("Dog parents = %d, want 1", len(dog.Parents))
	}
}

func TestBuildHierarchy_InterfaceCandidates(t *testing.T) {
	symbols := &SymbolTable{
		Classes: map[string]*ClassInfo{
			"Shape": {
				Name:       "Shape",
				Kind:       "class",
				File:       "shape.h",
				HasPure:    true,
				HasVirtual: true,
				Methods:    []string{"area", "perimeter"},
			},
			"Circle": {
				Name:        "Circle",
				Kind:        "class",
				File:        "circle.h",
				BaseClasses: []string{"Shape"},
				Methods:     []string{"area", "perimeter"},
			},
			"Utility": {
				Name:    "Utility",
				Kind:    "class",
				File:    "util.h",
				Methods: []string{"helper"},
			},
		},
		Functions:  make(map[string]*FunctionInfo),
		Enums:      make(map[string]*EnumInfo),
		Namespaces: make(map[string]*NamespaceInfo),
		Typedefs:   make(map[string]*TypedefInfo),
	}

	h := BuildHierarchy(symbols)

	candidates := h.InterfaceCandidates()
	if len(candidates) != 1 {
		t.Errorf("interface candidates = %d, want 1", len(candidates))
	}

	if len(candidates) > 0 && candidates[0].Name != "Shape" {
		t.Errorf("candidate = %q, want 'Shape'", candidates[0].Name)
	}
}

func TestBuildHierarchy_Depth(t *testing.T) {
	symbols := &SymbolTable{
		Classes: map[string]*ClassInfo{
			"A": {Name: "A", Kind: "class", File: "a.h"},
			"B": {Name: "B", Kind: "class", File: "b.h", BaseClasses: []string{"A"}},
			"C": {Name: "C", Kind: "class", File: "c.h", BaseClasses: []string{"B"}},
		},
		Functions:  make(map[string]*FunctionInfo),
		Enums:      make(map[string]*EnumInfo),
		Namespaces: make(map[string]*NamespaceInfo),
		Typedefs:   make(map[string]*TypedefInfo),
	}

	h := BuildHierarchy(symbols)

	depth := h.Depth()
	if depth != 3 {
		t.Errorf("depth = %d, want 3", depth)
	}
}

func TestBuildHierarchy_ExternalParent(t *testing.T) {
	symbols := &SymbolTable{
		Classes: map[string]*ClassInfo{
			"MyWidget": {
				Name:        "MyWidget",
				Kind:        "class",
				File:        "widget.h",
				BaseClasses: []string{"QWidget"}, // external, not in codebase
			},
		},
		Functions:  make(map[string]*FunctionInfo),
		Enums:      make(map[string]*EnumInfo),
		Namespaces: make(map[string]*NamespaceInfo),
		Typedefs:   make(map[string]*TypedefInfo),
	}

	h := BuildHierarchy(symbols)

	widget := h.ByName["MyWidget"]
	if widget == nil {
		t.Fatal("MyWidget not found")
	}

	// Should have no resolved parents but should have parent name recorded
	if len(widget.Parents) != 0 {
		t.Errorf("resolved parents = %d, want 0", len(widget.Parents))
	}

	if len(widget.ParentNames) != 1 || widget.ParentNames[0] != "QWidget" {
		t.Errorf("parent names = %v, want [QWidget]", widget.ParentNames)
	}

	// MyWidget should still be a root (no resolved parents)
	if len(h.Roots) != 1 {
		t.Errorf("roots = %d, want 1", len(h.Roots))
	}
}

func TestBuildHierarchy_Empty(t *testing.T) {
	symbols := &SymbolTable{
		Classes:    make(map[string]*ClassInfo),
		Functions:  make(map[string]*FunctionInfo),
		Enums:      make(map[string]*EnumInfo),
		Namespaces: make(map[string]*NamespaceInfo),
		Typedefs:   make(map[string]*TypedefInfo),
	}

	h := BuildHierarchy(symbols)

	if len(h.Roots) != 0 {
		t.Errorf("roots = %d, want 0", len(h.Roots))
	}

	if h.Depth() != 0 {
		t.Errorf("depth = %d, want 0", h.Depth())
	}
}
