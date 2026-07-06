package ast

import (
	"testing"
)

func TestBuildFromSource_Includes(t *testing.T) {
	source := `#include <iostream>
#include <vector>
#include "myheader.h"
`
	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	if len(tu.Includes) != 3 {
		t.Fatalf("expected 3 includes, got %d", len(tu.Includes))
	}

	tests := []struct {
		path   string
		system bool
	}{
		{"iostream", true},
		{"vector", true},
		{"myheader.h", false},
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

func TestBuildFromSource_FileName(t *testing.T) {
	b := NewBuilder()
	tu := b.BuildFromSource("main.cpp", "")

	if tu.FileName != "main.cpp" {
		t.Errorf("FileName = %q, want %q", tu.FileName, "main.cpp")
	}
}

func TestParseTypeRef(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantName  string
		wantConst bool
		wantPtr   bool
		wantRef   bool
	}{
		{"simple", "int", "int", false, false, false},
		{"const", "const int", "int", true, false, false},
		{"pointer", "int*", "int", false, true, false},
		{"reference", "int&", "int", false, false, true},
		{"const pointer", "const int*", "int", true, true, false},
		{"empty", "", "void", false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := ParseTypeRef(tt.input)

			if ref.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", ref.Name, tt.wantName)
			}

			if ref.Const != tt.wantConst {
				t.Errorf("Const = %v, want %v", ref.Const, tt.wantConst)
			}

			if ref.Pointer != tt.wantPtr {
				t.Errorf("Pointer = %v, want %v", ref.Pointer, tt.wantPtr)
			}

			if ref.Reference != tt.wantRef {
				t.Errorf("Reference = %v, want %v", ref.Reference, tt.wantRef)
			}
		})
	}
}

func TestParseTypeRef_Templates(t *testing.T) {
	ref := ParseTypeRef("std::vector<int>")

	if ref.Name != "std::vector" {
		t.Errorf("Name = %q, want %q", ref.Name, "std::vector")
	}

	if len(ref.TemplateArgs) != 1 {
		t.Fatalf("expected 1 template arg, got %d", len(ref.TemplateArgs))
	}

	if ref.TemplateArgs[0].Name != "int" {
		t.Errorf("template arg = %q, want %q", ref.TemplateArgs[0].Name, "int")
	}
}

func TestParseTypeRef_MapTemplate(t *testing.T) {
	ref := ParseTypeRef("std::map<std::string, int>")

	if ref.Name != "std::map" {
		t.Errorf("Name = %q, want %q", ref.Name, "std::map")
	}

	if len(ref.TemplateArgs) != 2 {
		t.Fatalf("expected 2 template args, got %d", len(ref.TemplateArgs))
	}

	if ref.TemplateArgs[0].Name != "std::string" {
		t.Errorf("first arg = %q, want %q", ref.TemplateArgs[0].Name, "std::string")
	}

	if ref.TemplateArgs[1].Name != "int" {
		t.Errorf("second arg = %q, want %q", ref.TemplateArgs[1].Name, "int")
	}
}

func TestBuildFromSource_ClassDecl(t *testing.T) {
	source := `class MyClass {
public:
    int x;
};`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	found := false

	for _, decl := range tu.Decls {
		if cls, ok := decl.(*Class); ok {
			if cls.Name == "MyClass" && cls.Kind == ClassKindClass {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected to find class MyClass in declarations")
	}
}

func TestBuildFromSource_StructDecl(t *testing.T) {
	source := `struct Point {
    double x, y;
};`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	found := false

	for _, decl := range tu.Decls {
		if cls, ok := decl.(*Class); ok {
			if cls.Name == "Point" && cls.Kind == ClassKindStruct {
				found = true
			}
		}
	}

	if !found {
		t.Error("expected to find struct Point in declarations")
	}
}

func TestBuildFromSource_EnumDecl(t *testing.T) {
	source := `enum Color { Red, Green, Blue };
enum class Direction { North, South, East, West };`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	var enums []*Enum

	for _, decl := range tu.Decls {
		if e, ok := decl.(*Enum); ok {
			enums = append(enums, e)
		}
	}

	if len(enums) != 2 {
		t.Fatalf("expected 2 enums, got %d", len(enums))
	}

	if enums[0].Name != "Color" || enums[0].Scoped {
		t.Errorf("first enum: name=%q scoped=%v, want Color/false", enums[0].Name, enums[0].Scoped)
	}

	if enums[1].Name != "Direction" || !enums[1].Scoped {
		t.Errorf("second enum: name=%q scoped=%v, want Direction/true", enums[1].Name, enums[1].Scoped)
	}
}

func TestBuildFromSource_TemplateClass(t *testing.T) {
	source := `template <typename T>
class Container {
    T value;
};`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	found := false

	for _, decl := range tu.Decls {
		if cls, ok := decl.(*Class); ok {
			if cls.Name == "Container" && len(cls.TemplateParams) == 1 {
				if cls.TemplateParams[0].Name == "T" {
					found = true
				}
			}
		}
	}

	if !found {
		t.Error("expected to find template class Container<T>")
	}
}

func TestBuildFromSource_NamespaceDecl(t *testing.T) {
	source := `namespace mylib {
    class Foo {};
}`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	var foundNamespace bool

	for _, decl := range tu.Decls {
		if ns, ok := decl.(*Namespace); ok {
			if ns.Name == "mylib" {
				foundNamespace = true
			}
		}
	}

	if !foundNamespace {
		t.Error("expected to find namespace mylib")
	}
}

func TestBuildFromSource_UsingDecl(t *testing.T) {
	source := `using namespace std;
using std::cout;`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	var usingDecls []*UsingDecl

	for _, decl := range tu.Decls {
		if u, ok := decl.(*UsingDecl); ok {
			usingDecls = append(usingDecls, u)
		}
	}

	if len(usingDecls) != 2 {
		t.Fatalf("expected 2 using declarations, got %d", len(usingDecls))
	}

	if !usingDecls[0].Namespace {
		t.Error("expected first using to be namespace")
	}

	if usingDecls[0].Name != "std" {
		t.Errorf("first using name = %q, want %q", usingDecls[0].Name, "std")
	}
}

func TestBuildFromSource_TypedefDecl(t *testing.T) {
	source := `typedef unsigned long size_type;`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	var foundTypedef bool

	for _, decl := range tu.Decls {
		if td, ok := decl.(*TypedefDecl); ok {
			if td.Name == "size_type" {
				foundTypedef = true

				if td.Underlying == nil {
					t.Error("expected non-nil underlying type")
				}
			}
		}
	}

	if !foundTypedef {
		t.Error("expected to find typedef size_type")
	}
}

func TestBuildFromSource_UsingAlias(t *testing.T) {
	source := `using IntVec = std::vector<int>;`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	var foundAlias bool

	for _, decl := range tu.Decls {
		if td, ok := decl.(*TypedefDecl); ok {
			if td.Name == "IntVec" {
				foundAlias = true
			}
		}
	}

	if !foundAlias {
		t.Error("expected to find using alias IntVec")
	}
}

func TestBuildFromSource_UnionDecl(t *testing.T) {
	source := `union Variant {
    int i;
    float f;
};`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	var foundUnion bool

	for _, decl := range tu.Decls {
		if cls, ok := decl.(*Class); ok {
			if cls.Name == "Variant" && cls.Kind == ClassKindUnion {
				foundUnion = true
			}
		}
	}

	if !foundUnion {
		t.Error("expected to find union Variant")
	}
}

func TestBuildFromSource_MultipleIncludes(t *testing.T) {
	source := `#include <iostream>
#include <vector>
#include <string>
#include <map>
#include "local.h"
#include "another.h"`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	if len(tu.Includes) != 6 {
		t.Errorf("expected 6 includes, got %d", len(tu.Includes))
	}

	systemCount := 0

	for _, inc := range tu.Includes {
		if inc.System {
			systemCount++
		}
	}

	if systemCount != 4 {
		t.Errorf("expected 4 system includes, got %d", systemCount)
	}
}

func TestBuildFromSource_IncludePositions(t *testing.T) {
	source := `// comment
#include <iostream>
#include <vector>`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	if len(tu.Includes) != 2 {
		t.Fatalf("expected 2 includes, got %d", len(tu.Includes))
	}

	if tu.Includes[0].Pos().Line != 2 {
		t.Errorf("first include line = %d, want 2", tu.Includes[0].Pos().Line)
	}

	if tu.Includes[1].Pos().Line != 3 {
		t.Errorf("second include line = %d, want 3", tu.Includes[1].Pos().Line)
	}
}

func TestBuildFromSource_MultipleDeclarations(t *testing.T) {
	source := `#include <iostream>

namespace mylib {
}

class Foo {};
struct Bar {};
enum Color { Red };

using namespace std;`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	if len(tu.Includes) != 1 {
		t.Errorf("expected 1 include, got %d", len(tu.Includes))
	}

	if len(tu.Decls) == 0 {
		t.Fatal("expected some declarations")
	}

	types := make(map[string]int)

	for _, decl := range tu.Decls {
		switch decl.(type) {
		case *Class:
			types["class"]++
		case *Enum:
			types["enum"]++
		case *Namespace:
			types["namespace"]++
		case *UsingDecl:
			types["using"]++
		}
	}

	if types["class"] != 2 {
		t.Errorf("expected 2 class/struct, got %d", types["class"])
	}

	if types["enum"] != 1 {
		t.Errorf("expected 1 enum, got %d", types["enum"])
	}

	if types["namespace"] != 1 {
		t.Errorf("expected 1 namespace, got %d", types["namespace"])
	}
}

func TestParseTypeRef_RValueRef(t *testing.T) {
	ref := ParseTypeRef("int&&")

	if ref.Name != "int" {
		t.Errorf("Name = %q, want %q", ref.Name, "int")
	}

	if !ref.RValueRef {
		t.Error("expected RValueRef = true")
	}

	if ref.Reference {
		t.Error("expected Reference = false for rvalue ref")
	}
}

func TestParseTypeRef_TrailingConst(t *testing.T) {
	ref := ParseTypeRef("int const")

	if ref.Name != "int" {
		t.Errorf("Name = %q, want %q", ref.Name, "int")
	}

	if !ref.Const {
		t.Error("expected Const = true")
	}
}

func TestParseTypeRef_ConstPointer(t *testing.T) {
	ref := ParseTypeRef("const char*")

	if ref.Name != "char" {
		t.Errorf("Name = %q, want %q", ref.Name, "char")
	}

	if !ref.Const {
		t.Error("expected Const = true")
	}

	if !ref.Pointer {
		t.Error("expected Pointer = true")
	}
}

func TestParseTypeRef_NestedTemplates(t *testing.T) {
	ref := ParseTypeRef("std::map<std::string, std::vector<int>>")

	if ref.Name != "std::map" {
		t.Errorf("Name = %q, want %q", ref.Name, "std::map")
	}

	if len(ref.TemplateArgs) != 2 {
		t.Fatalf("expected 2 template args, got %d", len(ref.TemplateArgs))
	}

	if ref.TemplateArgs[0].Name != "std::string" {
		t.Errorf("first arg = %q, want %q", ref.TemplateArgs[0].Name, "std::string")
	}

	if ref.TemplateArgs[1].Name != "std::vector" {
		t.Errorf("second arg = %q, want %q", ref.TemplateArgs[1].Name, "std::vector")
	}

	if len(ref.TemplateArgs[1].TemplateArgs) != 1 {
		t.Fatalf("expected 1 nested template arg, got %d", len(ref.TemplateArgs[1].TemplateArgs))
	}
}

func TestParseTemplateParams_Multiple(t *testing.T) {
	params := parseTemplateParams("template<typename T, class U>")

	if len(params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(params))
	}

	if params[0].Kind != "typename" || params[0].Name != "T" {
		t.Errorf("first param: kind=%q name=%q, want typename/T", params[0].Kind, params[0].Name)
	}

	if params[1].Kind != "class" || params[1].Name != "U" {
		t.Errorf("second param: kind=%q name=%q, want class/U", params[1].Kind, params[1].Name)
	}
}

func TestParseTemplateParams_SingleNoKeyword(t *testing.T) {
	params := parseTemplateParams("template<T>")

	if len(params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(params))
	}

	if params[0].Kind != "typename" {
		t.Errorf("Kind = %q, want %q", params[0].Kind, "typename")
	}

	if params[0].Name != "T" {
		t.Errorf("Name = %q, want %q", params[0].Name, "T")
	}
}

func TestParseTemplateParams_Empty(t *testing.T) {
	params := parseTemplateParams("template<>")

	if len(params) != 0 {
		t.Errorf("expected 0 params, got %d", len(params))
	}
}

func TestNodeTypes(t *testing.T) {
	tests := []struct {
		node     Node
		wantType string
	}{
		{&TranslationUnit{}, "TranslationUnit"},
		{&Include{}, "Include"},
		{&Namespace{}, "Namespace"},
		{&UsingDecl{}, "UsingDecl"},
		{&TypedefDecl{}, "TypedefDecl"},
		{&Class{}, "Class"},
		{&Enum{}, "Enum"},
		{&EnumValue{}, "EnumValue"},
		{&Function{}, "Function"},
		{&Method{}, "Method"},
		{&Constructor{}, "Constructor"},
		{&Destructor{}, "Destructor"},
		{&OperatorOverload{}, "OperatorOverload"},
		{&Parameter{}, "Parameter"},
		{&Variable{}, "Variable"},
		{&Field{}, "Field"},
		{&TemplateDecl{}, "TemplateDecl"},
		{&IfStmt{}, "IfStmt"},
		{&ForStmt{}, "ForStmt"},
		{&RangeForStmt{}, "RangeForStmt"},
		{&WhileStmt{}, "WhileStmt"},
		{&DoWhileStmt{}, "DoWhileStmt"},
		{&SwitchStmt{}, "SwitchStmt"},
		{&CaseClause{}, "CaseClause"},
		{&ReturnStmt{}, "ReturnStmt"},
		{&BreakStmt{}, "BreakStmt"},
		{&ContinueStmt{}, "ContinueStmt"},
		{&TryBlock{}, "TryBlock"},
		{&CatchClause{}, "CatchClause"},
		{&ThrowExpr{}, "ThrowExpr"},
		{&LambdaExpr{}, "LambdaExpr"},
		{&Assignment{}, "Assignment"},
		{&BinaryExpr{}, "BinaryExpr"},
		{&UnaryExpr{}, "UnaryExpr"},
		{&CallExpr{}, "CallExpr"},
		{&MemberExpr{}, "MemberExpr"},
		{&ScopeExpr{}, "ScopeExpr"},
		{&IndexExpr{}, "IndexExpr"},
		{&CastExpr{}, "CastExpr"},
		{&NewExpr{}, "NewExpr"},
		{&DeleteExpr{}, "DeleteExpr"},
		{&Literal{}, "Literal"},
		{&Identifier{}, "Identifier"},
		{&RawExpr{}, "RawExpr"},
		{&RawStmt{}, "RawStmt"},
		{&ExprStmt{}, "ExprStmt"},
	}

	for _, tt := range tests {
		t.Run(tt.wantType, func(t *testing.T) {
			if got := tt.node.nodeType(); got != tt.wantType {
				t.Errorf("nodeType() = %q, want %q", got, tt.wantType)
			}
		})
	}
}

func TestBaseNodePos(t *testing.T) {
	node := &Include{
		baseNode: baseNode{Position: Position{Line: 10, Column: 5}},
		Path:     "test.h",
	}

	pos := node.Pos()
	if pos.Line != 10 || pos.Column != 5 {
		t.Errorf("Pos() = {%d, %d}, want {10, 5}", pos.Line, pos.Column)
	}
}

func TestExprNodeInterface(t *testing.T) {
	// Verify all expression types implement Expr
	exprs := []Expr{
		&Assignment{},
		&BinaryExpr{},
		&UnaryExpr{},
		&CallExpr{},
		&MemberExpr{},
		&ScopeExpr{},
		&IndexExpr{},
		&CastExpr{},
		&NewExpr{},
		&DeleteExpr{},
		&Literal{},
		&Identifier{},
		&RawExpr{},
		&LambdaExpr{},
	}

	for _, e := range exprs {
		e.exprNode() // should not panic
		_ = e.nodeType()
		_ = e.Pos()
	}
}

func TestBuildFromSource_IncludeWithSpaces(t *testing.T) {
	source := `  #  include  <iostream>`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	if len(tu.Includes) != 1 {
		t.Fatalf("expected 1 include, got %d", len(tu.Includes))
	}

	if tu.Includes[0].Path != "iostream" {
		t.Errorf("Path = %q, want %q", tu.Includes[0].Path, "iostream")
	}
}

func TestBuildFromSource_EmptySource(t *testing.T) {
	b := NewBuilder()
	tu := b.BuildFromSource("empty.cpp", "")

	if tu.FileName != "empty.cpp" {
		t.Errorf("FileName = %q, want %q", tu.FileName, "empty.cpp")
	}

	if len(tu.Includes) != 0 {
		t.Errorf("expected 0 includes, got %d", len(tu.Includes))
	}

	if len(tu.Decls) != 0 {
		t.Errorf("expected 0 decls, got %d", len(tu.Decls))
	}
}

func TestBuildFromSource_EnumClassScoped(t *testing.T) {
	source := `enum class Status { OK, Error };`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	found := false

	for _, decl := range tu.Decls {
		if e, ok := decl.(*Enum); ok && e.Name == "Status" {
			found = true

			if !e.Scoped {
				t.Error("expected Scoped = true for enum class")
			}
		}
	}

	if !found {
		t.Error("expected enum class Status")
	}
}

func TestBuildFromSource_TemplateMultipleParams(t *testing.T) {
	source := `template <typename K, typename V>
class Map {};`

	b := NewBuilder()
	tu := b.BuildFromSource("test.cpp", source)

	for _, decl := range tu.Decls {
		if cls, ok := decl.(*Class); ok && cls.Name == "Map" {
			if len(cls.TemplateParams) != 2 {
				t.Errorf("expected 2 template params, got %d", len(cls.TemplateParams))
			}

			return
		}
	}

	t.Error("expected template class Map")
}
