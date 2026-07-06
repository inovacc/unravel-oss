package ast

import (
	"testing"
)

func TestBuildFromSource_CIncludes(t *testing.T) {
	source := `#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mymodule.h"
`
	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	if len(tu.Includes) != 4 {
		t.Fatalf("expected 4 includes, got %d", len(tu.Includes))
	}

	tests := []struct {
		path   string
		system bool
	}{
		{"stdio.h", true},
		{"stdlib.h", true},
		{"string.h", true},
		{"mymodule.h", false},
	}

	for i, tt := range tests {
		inc := tu.Includes[i]
		if inc.Path != tt.path {
			t.Errorf("include[%d].Path = %q, want %q", i, inc.Path, tt.path)
		}

		if inc.System != tt.system {
			t.Errorf("include[%d].System = %v, want %v", i, inc.System, tt.system)
		}
	}
}

func TestBuildFromSource_FuncPtrTypedef(t *testing.T) {
	source := `typedef int (*comparator_t)(const void*, const void*);
typedef void (*callback_t)(int, const char*);`

	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	var funcPtrs []*FuncPtrDecl

	for _, decl := range tu.Decls {
		if fp, ok := decl.(*FuncPtrDecl); ok {
			funcPtrs = append(funcPtrs, fp)
		}
	}

	if len(funcPtrs) != 2 {
		t.Fatalf("expected 2 function pointer typedefs, got %d", len(funcPtrs))
	}

	if funcPtrs[0].Name != "comparator_t" {
		t.Errorf("first func ptr name = %q, want %q", funcPtrs[0].Name, "comparator_t")
	}

	if funcPtrs[0].ReturnType == nil || funcPtrs[0].ReturnType.Name != "int" {
		t.Error("expected return type 'int' for comparator_t")
	}

	if funcPtrs[1].Name != "callback_t" {
		t.Errorf("second func ptr name = %q, want %q", funcPtrs[1].Name, "callback_t")
	}

	if funcPtrs[1].ReturnType == nil || funcPtrs[1].ReturnType.Name != "void" {
		t.Error("expected return type 'void' for callback_t")
	}
}

func TestBuildFromSource_ExternDecl(t *testing.T) {
	source := `extern int global_count;
extern "C" {
}`

	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	var externs []*ExternDecl

	for _, decl := range tu.Decls {
		if ed, ok := decl.(*ExternDecl); ok {
			externs = append(externs, ed)
		}
	}

	if len(externs) != 2 {
		t.Fatalf("expected 2 extern declarations, got %d", len(externs))
	}

	// First: extern int global_count;
	if externs[0].Var == nil {
		t.Fatal("expected non-nil Var for extern variable")
	}

	if externs[0].Var.Name != "global_count" {
		t.Errorf("extern var name = %q, want %q", externs[0].Var.Name, "global_count")
	}

	// Second: extern "C" {
	if externs[1].Linkage != "C" {
		t.Errorf("extern linkage = %q, want %q", externs[1].Linkage, "C")
	}
}

func TestBuildFromSource_CStructTypedef(t *testing.T) {
	source := `typedef struct node {
    int value;
    struct node* next;
} Node;

struct point {
    double x;
    double y;
};`

	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	// Should detect named struct declarations
	var classes []*Class

	for _, decl := range tu.Decls {
		if cls, ok := decl.(*Class); ok {
			classes = append(classes, cls)
		}
	}

	// The builder should detect the named structs "node" and "point"
	foundNode := false
	foundPoint := false

	for _, cls := range classes {
		if cls.Name == "node" && cls.Kind == ClassKindStruct {
			foundNode = true
		}

		if cls.Name == "point" && cls.Kind == ClassKindStruct {
			foundPoint = true
		}
	}

	if !foundNode {
		t.Error("expected to find struct node")
	}

	if !foundPoint {
		t.Error("expected to find struct point")
	}
}

func TestBuildFromSource_CFunction(t *testing.T) {
	source := `int add(int a, int b) {
    return a + b;
}

void print_message(const char* msg) {
    printf("%s\n", msg);
}`

	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	var funcs []*Function

	for _, decl := range tu.Decls {
		if fn, ok := decl.(*Function); ok {
			funcs = append(funcs, fn)
		}
	}

	if len(funcs) < 2 {
		t.Fatalf("expected at least 2 functions, got %d", len(funcs))
	}

	// Check add function
	var foundAdd, foundPrint bool

	for _, fn := range funcs {
		if fn.Name == "add" {
			foundAdd = true

			if fn.ReturnType == nil || fn.ReturnType.Name != "int" {
				t.Error("expected add return type = int")
			}

			if len(fn.Params) != 2 {
				t.Errorf("add params = %d, want 2", len(fn.Params))
			}
		}

		if fn.Name == "print_message" {
			foundPrint = true
		}
	}

	if !foundAdd {
		t.Error("expected to find function 'add'")
	}

	if !foundPrint {
		t.Error("expected to find function 'print_message'")
	}
}

func TestBuildFromSource_CEnum(t *testing.T) {
	// C named enum (the builder detects named enums)
	source := `enum LogLevel {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR
};

enum Color { RED, GREEN, BLUE };`

	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	var enums []*Enum

	for _, decl := range tu.Decls {
		if e, ok := decl.(*Enum); ok {
			enums = append(enums, e)
		}
	}

	if len(enums) != 2 {
		t.Fatalf("expected 2 enums, got %d", len(enums))
	}

	foundLogLevel := false
	foundColor := false

	for _, e := range enums {
		if e.Name == "LogLevel" {
			foundLogLevel = true

			if e.Scoped {
				t.Error("C enum should not be scoped")
			}
		}

		if e.Name == "Color" {
			foundColor = true

			if e.Scoped {
				t.Error("C enum should not be scoped")
			}
		}
	}

	if !foundLogLevel {
		t.Error("expected to find enum LogLevel")
	}

	if !foundColor {
		t.Error("expected to find enum Color")
	}
}

func TestNodeTypes_CSpecific(t *testing.T) {
	tests := []struct {
		node     Node
		wantType string
	}{
		{&GotoStmt{Label: "cleanup"}, "GotoStmt"},
		{&LabelStmt{Label: "cleanup"}, "LabelStmt"},
		{&ExternDecl{Linkage: "C"}, "ExternDecl"},
		{&FuncPtrDecl{Name: "callback_t"}, "FuncPtrDecl"},
		{&BitField{Name: "flags", Width: 3}, "BitField"},
	}

	for _, tt := range tests {
		t.Run(tt.wantType, func(t *testing.T) {
			if got := tt.node.nodeType(); got != tt.wantType {
				t.Errorf("nodeType() = %q, want %q", got, tt.wantType)
			}
		})
	}
}

func TestTypeRef_CExtensions(t *testing.T) {
	// Test FuncPtr field
	ref := &TypeRef{
		Name:    "callback_t",
		FuncPtr: true,
	}
	if !ref.FuncPtr {
		t.Error("expected FuncPtr = true")
	}

	// Test ArraySize field
	arrRef := &TypeRef{
		Name:      "int",
		ArraySize: "10",
	}
	if arrRef.ArraySize != "10" {
		t.Errorf("ArraySize = %q, want %q", arrRef.ArraySize, "10")
	}

	// Test Volatile field
	volRef := &TypeRef{
		Name:     "int",
		Volatile: true,
	}
	if !volRef.Volatile {
		t.Error("expected Volatile = true")
	}

	// Test Restrict field
	restRef := &TypeRef{
		Name:     "int",
		Pointer:  true,
		Restrict: true,
	}
	if !restRef.Restrict {
		t.Error("expected Restrict = true")
	}
}

func TestBuildFromSource_GotoKeywordNotFunction(t *testing.T) {
	source := `void foo() {
    goto cleanup;
cleanup:
    return;
}`
	b := NewBuilder()
	tu := b.BuildFromSource("test.c", source)

	// "goto" should NOT be extracted as a function name
	for _, decl := range tu.Decls {
		if fn, ok := decl.(*Function); ok {
			if fn.Name == "goto" {
				t.Error("goto should not be extracted as a function name")
			}
		}
	}
}
