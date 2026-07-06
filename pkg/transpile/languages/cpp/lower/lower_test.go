package lower

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/ast"
)

func TestLower_EmptyTranslationUnit(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{FileName: "test.cpp"}

	mod := l.Lower(tu)

	if mod.PackageName != "main" {
		t.Errorf("PackageName = %q, want %q", mod.PackageName, "main")
	}

	if mod.SourceFile != "test.cpp" {
		t.Errorf("SourceFile = %q, want %q", mod.SourceFile, "test.cpp")
	}
}

func TestLower_IncludeMapping(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Includes: []*ast.Include{
			{Path: "iostream", System: true},
			{Path: "vector", System: true},
			{Path: "myheader.h", System: false},
		},
	}

	mod := l.Lower(tu)

	hasFmt := false

	for _, imp := range mod.Imports {
		if imp.Path == "fmt" {
			hasFmt = true
		}
	}

	if !hasFmt {
		t.Error("expected 'fmt' import from <iostream>")
	}
}

func TestLowerType_Primitives(t *testing.T) {
	l := NewLowerer()

	tests := []struct {
		input string
		want  string
	}{
		{"int", "int"},
		{"double", "float64"},
		{"float", "float32"},
		{"bool", "bool"},
		{"char", "byte"},
		{"long", "int64"},
		{"void", ""},
		{"auto", "any"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ref := l.lowerType(&ast.TypeRef{Name: tt.input})
			if ref.Name != tt.want {
				t.Errorf("lowerType(%q) = %q, want %q", tt.input, ref.Name, tt.want)
			}
		})
	}
}

func TestLowerType_Vector(t *testing.T) {
	l := NewLowerer()
	ref := l.lowerType(&ast.TypeRef{
		Name:         "std::vector",
		TemplateArgs: []*ast.TypeRef{{Name: "int"}},
	})

	if ref.Kind != ir.KindSlice {
		t.Errorf("Kind = %q, want %q", ref.Kind, ir.KindSlice)
	}

	if ref.ElemType == nil || ref.ElemType.Name != "int" {
		t.Error("expected ElemType = int")
	}
}

func TestLowerType_Map(t *testing.T) {
	l := NewLowerer()
	ref := l.lowerType(&ast.TypeRef{
		Name: "std::map",
		TemplateArgs: []*ast.TypeRef{
			{Name: "std::string"},
			{Name: "int"},
		},
	})

	if ref.Kind != ir.KindMap {
		t.Errorf("Kind = %q, want %q", ref.Kind, ir.KindMap)
	}

	if ref.KeyType == nil || ref.KeyType.Name != "string" {
		t.Error("expected KeyType = string")
	}

	if ref.ValType == nil || ref.ValType.Name != "int" {
		t.Error("expected ValType = int")
	}
}

func TestLowerType_String(t *testing.T) {
	l := NewLowerer()
	ref := l.lowerType(&ast.TypeRef{Name: "std::string"})

	if ref.Name != "string" {
		t.Errorf("lowerType(std::string) = %q, want %q", ref.Name, "string")
	}
}

func TestLowerType_SmartPointers(t *testing.T) {
	l := NewLowerer()

	for _, name := range []string{"std::unique_ptr", "std::shared_ptr"} {
		ref := l.lowerType(&ast.TypeRef{
			Name:         name,
			TemplateArgs: []*ast.TypeRef{{Name: "MyClass"}},
		})

		if ref.Kind != ir.KindPointer {
			t.Errorf("lowerType(%s) Kind = %q, want %q", name, ref.Kind, ir.KindPointer)
		}
	}
}

func TestLower_ClassToStruct(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Point",
				Fields: []*ast.Field{
					{Name: "x", Type: &ast.TypeRef{Name: "double"}, Access: "public"},
					{Name: "y", Type: &ast.TypeRef{Name: "double"}, Access: "public"},
				},
			},
		},
	}

	mod := l.Lower(tu)

	found := false

	for _, decl := range mod.Decls {
		if td, ok := decl.(*ir.TypeDecl); ok && td.Name == "Point" {
			found = true

			if td.Kind != ir.TypeDeclStruct {
				t.Errorf("Kind = %q, want %q", td.Kind, ir.TypeDeclStruct)
			}

			if len(td.Fields) != 2 {
				t.Errorf("expected 2 fields, got %d", len(td.Fields))
			}
		}
	}

	if !found {
		t.Error("expected to find Point struct declaration")
	}
}

func TestLower_EnumToConst(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Enum{
				Name:   "Color",
				Scoped: true,
				Values: []*ast.EnumValue{
					{Name: "Red"},
					{Name: "Green"},
					{Name: "Blue"},
				},
			},
		},
	}

	mod := l.Lower(tu)

	found := false

	for _, decl := range mod.Decls {
		if td, ok := decl.(*ir.TypeDecl); ok && td.Name == "Color" {
			found = true

			if td.Kind != ir.TypeDeclEnum {
				t.Errorf("Kind = %q, want %q", td.Kind, ir.TypeDeclEnum)
			}

			if len(td.Values) != 3 {
				t.Errorf("expected 3 values, got %d", len(td.Values))
			}
		}
	}

	if !found {
		t.Error("expected to find Color enum declaration")
	}
}

func TestExportName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"get_value", "GetValue"},
		{"set_name", "SetName"},
		{"doSomething", "DoSomething"},
		{"x", "X"},
		{"", ""},
		{"my_long_name", "MyLongName"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := exportName(tt.input)
			if got != tt.want {
				t.Errorf("exportName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestOperatorMethodName(t *testing.T) {
	tests := []struct {
		op   string
		want string
	}{
		{"+", "Add"},
		{"-", "Sub"},
		{"==", "Equal"},
		{"<", "Less"},
		{"<<", "String"},
		{"[]", "At"},
		{"()", "Call"},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			got := operatorMethodName(tt.op)
			if got != tt.want {
				t.Errorf("operatorMethodName(%q) = %q, want %q", tt.op, got, tt.want)
			}
		})
	}
}

func TestMapPrimitiveType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"int", "int"},
		{"double", "float64"},
		{"float", "float32"},
		{"bool", "bool"},
		{"char", "byte"},
		{"unsigned int", "uint"},
		{"size_t", "uint"},
		{"int64_t", "int64"},
		{"CustomType", "CustomType"},
		{"long", "int64"},
		{"long", "int64"},
		{"long int", "int64"},
		{"short", "int16"},
		{"int16_t", "int16"},
		{"int32_t", "int"},
		{"uint32_t", "uint"},
		{"unsigned long", "uint64"},
		{"unsigned long", "uint64"},
		{"uint64_t", "uint64"},
		{"unsigned short", "uint16"},
		{"uint16_t", "uint16"},
		{"int8_t", "byte"},
		{"unsigned char", "byte"},
		{"uint8_t", "byte"},
		{"wchar_t", "rune"},
		{"char16_t", "rune"},
		{"char32_t", "rune"},
		{"long double", "float64"},
		{"void", ""},
		{"auto", "any"},
		{"nullptr_t", "any"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapPrimitiveType(tt.input)
			if got != tt.want {
				t.Errorf("mapPrimitiveType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestOperatorMethodName_All(t *testing.T) {
	tests := []struct {
		op   string
		want string
	}{
		{"+", "Add"},
		{"-", "Sub"},
		{"*", "Mul"},
		{"/", "Div"},
		{"%", "Mod"},
		{"==", "Equal"},
		{"!=", "NotEqual"},
		{"<", "Less"},
		{"<=", "LessEqual"},
		{">", "Greater"},
		{">=", "GreaterEqual"},
		{"<<", "String"},
		{">>", "Read"},
		{"[]", "At"},
		{"()", "Call"},
		{"++", "Inc"},
		{"--", "Dec"},
		{"!", "Not"},
		{"~", "Complement"},
		{"&", "BitAnd"},
		{"|", "BitOr"},
		{"^", "BitXor"},
		{"=", "Set"},
		{"+=", "AddAssign"},
		{"-=", "SubAssign"},
		{"??", "Op??"},
	}

	for _, tt := range tests {
		t.Run(tt.op, func(t *testing.T) {
			got := operatorMethodName(tt.op)
			if got != tt.want {
				t.Errorf("operatorMethodName(%q) = %q, want %q", tt.op, got, tt.want)
			}
		})
	}
}

func TestLower_FunctionDecl(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Function{
				Name:       "add",
				ReturnType: &ast.TypeRef{Name: "int"},
				Params: []*ast.Parameter{
					{Name: "a", Type: &ast.TypeRef{Name: "int"}},
					{Name: "b", Type: &ast.TypeRef{Name: "int"}},
				},
				Body: []ast.Node{
					&ast.ReturnStmt{Value: &ast.BinaryExpr{
						Left:     &ast.Identifier{Name: "a"},
						Operator: "+",
						Right:    &ast.Identifier{Name: "b"},
					}},
				},
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	fn, ok := mod.Decls[0].(*ir.FuncDecl)
	if !ok {
		t.Fatalf("expected *ir.FuncDecl, got %T", mod.Decls[0])
	}

	if fn.Name != "Add" {
		t.Errorf("Name = %q, want %q", fn.Name, "Add")
	}

	if len(fn.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(fn.Params))
	}

	if len(fn.Returns) != 1 {
		t.Errorf("expected 1 return, got %d", len(fn.Returns))
	}

	if len(fn.Body) != 1 {
		t.Errorf("expected 1 body stmt, got %d", len(fn.Body))
	}
}

func TestLower_FunctionWithTemplateParams(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Function{
				Name:       "identity",
				ReturnType: &ast.TypeRef{Name: "void"},
				TemplateParams: []*ast.TemplateParam{
					{Kind: "typename", Name: "T"},
				},
			},
		},
	}

	mod := l.Lower(tu)
	fn := mod.Decls[0].(*ir.FuncDecl)

	if len(fn.TypeParams) != 1 || fn.TypeParams[0] != "T" {
		t.Errorf("TypeParams = %v, want [T]", fn.TypeParams)
	}
}

func TestLower_FunctionVoidReturn(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Function{
				Name:       "doNothing",
				ReturnType: &ast.TypeRef{Name: "void"},
			},
		},
	}

	mod := l.Lower(tu)
	fn := mod.Decls[0].(*ir.FuncDecl)

	if len(fn.Returns) != 0 {
		t.Errorf("expected 0 returns for void function, got %d", len(fn.Returns))
	}
}

func TestLower_ClassWithConstructor(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Widget",
				Constructors: []*ast.Constructor{
					{
						Params: []*ast.Parameter{
							{Name: "name", Type: &ast.TypeRef{Name: "std::string"}},
						},
						Access: "public",
					},
				},
			},
		},
	}

	mod := l.Lower(tu)

	var foundCtor bool

	for _, decl := range mod.Decls {
		if fn, ok := decl.(*ir.FuncDecl); ok && fn.Name == "NewWidget" {
			foundCtor = true

			if len(fn.Params) != 1 {
				t.Errorf("expected 1 param, got %d", len(fn.Params))
			}

			if len(fn.Returns) != 1 {
				t.Errorf("expected 1 return, got %d", len(fn.Returns))
			}

			if fn.Returns[0].Type.Kind != ir.KindPointer {
				t.Errorf("expected pointer return type, got %v", fn.Returns[0].Type.Kind)
			}
		}
	}

	if !foundCtor {
		t.Error("expected NewWidget constructor function")
	}
}

func TestLower_ClassWithDestructor(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Resource",
				Destructor: &ast.Destructor{
					Virtual: true,
					Access:  "public",
				},
			},
		},
	}

	mod := l.Lower(tu)

	var foundClose bool

	for _, decl := range mod.Decls {
		if fn, ok := decl.(*ir.FuncDecl); ok && fn.Name == "Close" {
			foundClose = true

			if fn.Receiver == nil {
				t.Error("expected receiver on Close method")
			} else if fn.Receiver.Name != "r" {
				t.Errorf("receiver name = %q, want %q", fn.Receiver.Name, "r")
			}

			if fn.Comment == "" {
				t.Error("expected comment on Close method")
			}
		}
	}

	if !foundClose {
		t.Error("expected Close method from destructor")
	}
}

func TestLower_ClassWithMethod(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Calculator",
				Methods: []*ast.Method{
					{
						Name:       "compute",
						ReturnType: &ast.TypeRef{Name: "double"},
						Params: []*ast.Parameter{
							{Name: "x", Type: &ast.TypeRef{Name: "double"}},
						},
						Const:  true,
						Access: "public",
					},
				},
			},
		},
	}

	mod := l.Lower(tu)

	var foundMethod bool

	for _, decl := range mod.Decls {
		if fn, ok := decl.(*ir.FuncDecl); ok && fn.Name == "Compute" {
			foundMethod = true

			if fn.Receiver == nil {
				t.Fatal("expected receiver")
			}

			if fn.Receiver.Name != "c" {
				t.Errorf("receiver = %q, want %q", fn.Receiver.Name, "c")
			}

			if len(fn.Params) != 1 {
				t.Errorf("params = %d, want 1", len(fn.Params))
			}

			if len(fn.Returns) != 1 {
				t.Errorf("returns = %d, want 1", len(fn.Returns))
			}
		}
	}

	if !foundMethod {
		t.Error("expected Compute method")
	}
}

func TestLower_ClassWithOperator(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Vec2",
				Operators: []*ast.OperatorOverload{
					{
						Operator:   "+",
						ReturnType: &ast.TypeRef{Name: "Vec2"},
						Params: []*ast.Parameter{
							{Name: "other", Type: &ast.TypeRef{Name: "Vec2", Reference: true, Const: true}},
						},
						Access: "public",
					},
				},
			},
		},
	}

	mod := l.Lower(tu)

	var foundOp bool

	for _, decl := range mod.Decls {
		if fn, ok := decl.(*ir.FuncDecl); ok && fn.Name == "Add" {
			foundOp = true

			if fn.Receiver == nil {
				t.Fatal("expected receiver")
			}

			if fn.Comment == "" {
				t.Error("expected comment about operator")
			}
		}
	}

	if !foundOp {
		t.Error("expected Add method from operator+")
	}
}

func TestLower_ClassWithPureVirtualExtractsInterface(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Shape",
				Methods: []*ast.Method{
					{
						Name:       "area",
						ReturnType: &ast.TypeRef{Name: "double"},
						Pure:       true,
						Virtual:    true,
						Access:     "public",
					},
					{
						Name:       "perimeter",
						ReturnType: &ast.TypeRef{Name: "double"},
						Pure:       true,
						Virtual:    true,
						Access:     "public",
					},
				},
			},
		},
	}

	mod := l.Lower(tu)

	var foundInterface bool

	for _, decl := range mod.Decls {
		if td, ok := decl.(*ir.TypeDecl); ok && td.Kind == ir.TypeDeclInterface {
			foundInterface = true

			if td.Name != "Shapeer" {
				t.Errorf("interface name = %q, want %q", td.Name, "Shapeer")
			}

			if len(td.Methods) != 2 {
				t.Errorf("expected 2 interface methods, got %d", len(td.Methods))
			}
		}
	}

	if !foundInterface {
		t.Error("expected interface extracted from abstract class")
	}
}

func TestLower_ClassWithInheritance(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Derived",
				BaseClasses: []*ast.BaseClass{
					{Name: "Base", Access: "public"},
				},
			},
		},
	}

	mod := l.Lower(tu)

	for _, decl := range mod.Decls {
		if td, ok := decl.(*ir.TypeDecl); ok && td.Name == "Derived" {
			if len(td.Embedded) != 1 || td.Embedded[0] != "Base" {
				t.Errorf("Embedded = %v, want [Base]", td.Embedded)
			}

			return
		}
	}

	t.Error("expected Derived struct")
}

func TestLower_ClassWithTemplateParams(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Class{
				Kind: ast.ClassKindClass,
				Name: "Container",
				TemplateParams: []*ast.TemplateParam{
					{Kind: "typename", Name: "T"},
					{Kind: "typename", Name: "Alloc"},
				},
			},
		},
	}

	mod := l.Lower(tu)

	for _, decl := range mod.Decls {
		if td, ok := decl.(*ir.TypeDecl); ok && td.Name == "Container" {
			if len(td.TypeParams) != 2 {
				t.Errorf("TypeParams = %v, want 2 params", td.TypeParams)
			}

			return
		}
	}

	t.Error("expected Container type decl")
}

func TestLower_Namespace(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Namespace{
				Name: "mylib",
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) == 0 {
		t.Fatal("expected at least 1 decl from namespace")
	}

	// First decl should be a comment about the namespace
	raw, ok := mod.Decls[0].(*ir.RawStmt)
	if !ok {
		t.Fatalf("expected *ir.RawStmt, got %T", mod.Decls[0])
	}

	if raw.Comment == "" {
		t.Error("expected comment about namespace")
	}
}

func TestLower_Variable(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.Variable{
				Name:  "count",
				Type:  &ast.TypeRef{Name: "int"},
				Const: true,
				Init:  &ast.Literal{Kind: "int", Value: "42"},
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	vd, ok := mod.Decls[0].(*ir.VarDecl)
	if !ok {
		t.Fatalf("expected *ir.VarDecl, got %T", mod.Decls[0])
	}

	if vd.Name != "count" {
		t.Errorf("Name = %q, want %q", vd.Name, "count")
	}

	if !vd.Const {
		t.Error("expected const = true")
	}

	if vd.Value == nil {
		t.Error("expected non-nil value")
	}
}

func TestLower_UsingDecl(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.UsingDecl{Name: "std", Namespace: true},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	raw, ok := mod.Decls[0].(*ir.RawStmt)
	if !ok {
		t.Fatalf("expected *ir.RawStmt, got %T", mod.Decls[0])
	}

	if raw.Comment == "" {
		t.Error("expected comment about using declaration")
	}
}

func TestLower_TypedefDecl(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.TypedefDecl{
				Name:       "IntVec",
				Underlying: &ast.TypeRef{Name: "std::vector<int>"},
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	td, ok := mod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("expected *ir.TypeDecl, got %T", mod.Decls[0])
	}

	if td.Name != "IntVec" {
		t.Errorf("Name = %q, want %q", td.Name, "IntVec")
	}
}

func TestLower_UnsupportedDecl(t *testing.T) {
	l := NewLowerer()
	// TemplateDecl is a node type that lowerDecl doesn't explicitly handle
	tu := &ast.TranslationUnit{
		FileName: "test.cpp",
		Decls: []ast.Node{
			&ast.TemplateDecl{},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	raw, ok := mod.Decls[0].(*ir.RawStmt)
	if !ok {
		t.Fatalf("expected *ir.RawStmt, got %T", mod.Decls[0])
	}

	if raw.Text == "" {
		t.Error("expected unsupported declaration comment")
	}
}

func TestLowerStmt_ReturnWithValue(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.ReturnStmt{
		Value: &ast.Literal{Kind: "int", Value: "42"},
	})

	if len(stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(stmts))
	}

	ret, ok := stmts[0].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("expected *ir.ReturnStmt, got %T", stmts[0])
	}

	if len(ret.Values) != 1 {
		t.Errorf("expected 1 return value, got %d", len(ret.Values))
	}
}

func TestLowerStmt_ReturnEmpty(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.ReturnStmt{})

	ret := stmts[0].(*ir.ReturnStmt)
	if len(ret.Values) != 0 {
		t.Errorf("expected 0 return values, got %d", len(ret.Values))
	}
}

func TestLowerStmt_IfStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.IfStmt{
		Condition: &ast.BinaryExpr{
			Left:     &ast.Identifier{Name: "x"},
			Operator: ">",
			Right:    &ast.Literal{Kind: "int", Value: "0"},
		},
		Then: []ast.Node{
			&ast.ReturnStmt{Value: &ast.Literal{Kind: "bool", Value: "true"}},
		},
		Else: []ast.Node{
			&ast.ReturnStmt{Value: &ast.Literal{Kind: "bool", Value: "false"}},
		},
	})

	ifStmt, ok := stmts[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected *ir.IfStmt, got %T", stmts[0])
	}

	if len(ifStmt.Then) != 1 {
		t.Errorf("Then = %d stmts, want 1", len(ifStmt.Then))
	}

	if len(ifStmt.Else) != 1 {
		t.Errorf("Else = %d stmts, want 1", len(ifStmt.Else))
	}
}

func TestLowerStmt_ForStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.ForStmt{
		Condition: &ast.BinaryExpr{
			Left:     &ast.Identifier{Name: "i"},
			Operator: "<",
			Right:    &ast.Literal{Kind: "int", Value: "10"},
		},
		Post: &ast.UnaryExpr{Operator: "++", Operand: &ast.Identifier{Name: "i"}, Prefix: false},
		Body: []ast.Node{},
	})

	forStmt, ok := stmts[0].(*ir.ForStmt)
	if !ok {
		t.Fatalf("expected *ir.ForStmt, got %T", stmts[0])
	}

	if forStmt.Cond == nil {
		t.Error("expected non-nil Cond")
	}

	if forStmt.Post == nil {
		t.Error("expected non-nil Post")
	}
}

func TestLowerStmt_RangeForStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.RangeForStmt{
		VarName: "item",
		Range:   &ast.Identifier{Name: "items"},
		Body:    []ast.Node{},
	})

	rangeStmt, ok := stmts[0].(*ir.RangeStmt)
	if !ok {
		t.Fatalf("expected *ir.RangeStmt, got %T", stmts[0])
	}

	if rangeStmt.Value != "item" {
		t.Errorf("Value = %q, want %q", rangeStmt.Value, "item")
	}
}

func TestLowerStmt_WhileStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.WhileStmt{
		Condition: &ast.Identifier{Name: "running"},
		Body:      []ast.Node{},
	})

	forStmt, ok := stmts[0].(*ir.ForStmt)
	if !ok {
		t.Fatalf("expected *ir.ForStmt from while, got %T", stmts[0])
	}

	if forStmt.Cond == nil {
		t.Error("expected non-nil Cond")
	}
}

func TestLowerStmt_DoWhileStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.DoWhileStmt{
		Condition: &ast.Identifier{Name: "running"},
		Body: []ast.Node{
			&ast.ExprStmt{Expr: &ast.Identifier{Name: "process"}},
		},
	})

	forStmt, ok := stmts[0].(*ir.ForStmt)
	if !ok {
		t.Fatalf("expected *ir.ForStmt from do-while, got %T", stmts[0])
	}

	// Body should end with an if !cond { break }
	if len(forStmt.Body) < 2 {
		t.Fatalf("expected at least 2 body stmts (original + break check), got %d", len(forStmt.Body))
	}

	lastStmt, ok := forStmt.Body[len(forStmt.Body)-1].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected *ir.IfStmt at end of do-while body, got %T", forStmt.Body[len(forStmt.Body)-1])
	}

	if len(lastStmt.Then) != 1 {
		t.Fatalf("expected 1 stmt in break check, got %d", len(lastStmt.Then))
	}

	branch, ok := lastStmt.Then[0].(*ir.BranchStmt)
	if !ok {
		t.Fatalf("expected *ir.BranchStmt, got %T", lastStmt.Then[0])
	}

	if branch.Kind != "break" {
		t.Errorf("expected break, got %q", branch.Kind)
	}
}

func TestLowerStmt_SwitchStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.SwitchStmt{
		Condition: &ast.Identifier{Name: "x"},
		Cases: []*ast.CaseClause{
			{Value: &ast.Literal{Kind: "int", Value: "1"}, Body: []ast.Node{
				&ast.ReturnStmt{Value: &ast.Literal{Kind: "string", Value: `"one"`}},
			}},
			{Default: true, Body: []ast.Node{
				&ast.ReturnStmt{Value: &ast.Literal{Kind: "string", Value: `"other"`}},
			}},
		},
	})

	switchStmt, ok := stmts[0].(*ir.SwitchStmt)
	if !ok {
		t.Fatalf("expected *ir.SwitchStmt, got %T", stmts[0])
	}

	if len(switchStmt.Cases) != 2 {
		t.Errorf("expected 2 cases, got %d", len(switchStmt.Cases))
	}

	if switchStmt.Cases[1].Default != true {
		t.Error("expected second case to be default")
	}
}

func TestLowerStmt_TryCatch(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.TryBlock{
		Body: []ast.Node{
			&ast.ExprStmt{Expr: &ast.Identifier{Name: "riskyOp"}},
		},
		Catches: []*ast.CatchClause{
			{ParamType: &ast.TypeRef{Name: "std::exception"}, ParamName: "e"},
			{}, // catch(...)
		},
	})

	if len(stmts) < 3 {
		t.Fatalf("expected at least 3 stmts (body + 2 catch comments), got %d", len(stmts))
	}
}

func TestLowerStmt_ThrowWithValue(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.ThrowExpr{
		Value: &ast.Literal{Kind: "string", Value: `"error occurred"`},
	})

	ret, ok := stmts[0].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("expected *ir.ReturnStmt, got %T", stmts[0])
	}

	if len(ret.Values) != 1 {
		t.Errorf("expected 1 return value, got %d", len(ret.Values))
	}
}

func TestLowerStmt_ThrowRethrow(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.ThrowExpr{})

	ret, ok := stmts[0].(*ir.ReturnStmt)
	if !ok {
		t.Fatalf("expected *ir.ReturnStmt, got %T", stmts[0])
	}

	if len(ret.Values) != 1 {
		t.Errorf("expected 1 return value (err), got %d", len(ret.Values))
	}

	ident, ok := ret.Values[0].(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr, got %T", ret.Values[0])
	}

	if ident.Name != "err" {
		t.Errorf("expected 'err', got %q", ident.Name)
	}
}

func TestLowerStmt_BreakContinue(t *testing.T) {
	l := NewLowerer()

	breakStmts := l.lowerStmt(&ast.BreakStmt{})

	branch, ok := breakStmts[0].(*ir.BranchStmt)
	if !ok {
		t.Fatalf("expected *ir.BranchStmt, got %T", breakStmts[0])
	}

	if branch.Kind != "break" {
		t.Errorf("Kind = %q, want %q", branch.Kind, "break")
	}

	contStmts := l.lowerStmt(&ast.ContinueStmt{})

	branch, ok = contStmts[0].(*ir.BranchStmt)
	if !ok {
		t.Fatalf("expected *ir.BranchStmt, got %T", contStmts[0])
	}

	if branch.Kind != "continue" {
		t.Errorf("Kind = %q, want %q", branch.Kind, "continue")
	}
}

func TestLowerStmt_ExprStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.ExprStmt{
		Expr: &ast.Identifier{Name: "foo"},
	})

	es, ok := stmts[0].(*ir.ExprStmt)
	if !ok {
		t.Fatalf("expected *ir.ExprStmt, got %T", stmts[0])
	}

	ident, ok := es.Expr.(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr, got %T", es.Expr)
	}

	if ident.Name != "foo" {
		t.Errorf("Name = %q, want %q", ident.Name, "foo")
	}
}

func TestLowerStmt_RawStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.RawStmt{Text: "asm volatile"})

	raw, ok := stmts[0].(*ir.RawStmt)
	if !ok {
		t.Fatalf("expected *ir.RawStmt, got %T", stmts[0])
	}

	if raw.Text != "asm volatile" {
		t.Errorf("Text = %q, want %q", raw.Text, "asm volatile")
	}
}

func TestLowerStmt_VariableInBody(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.Variable{
		Name: "x",
		Type: &ast.TypeRef{Name: "int"},
		Init: &ast.Literal{Kind: "int", Value: "5"},
	})

	vd, ok := stmts[0].(*ir.VarDecl)
	if !ok {
		t.Fatalf("expected *ir.VarDecl, got %T", stmts[0])
	}

	if vd.Name != "x" {
		t.Errorf("Name = %q, want %q", vd.Name, "x")
	}
}

func TestLowerExpr_Nil(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(nil)

	ident, ok := result.(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr, got %T", result)
	}

	if ident.Name != "nil" {
		t.Errorf("Name = %q, want %q", ident.Name, "nil")
	}
}

func TestLowerExpr_Literal(t *testing.T) {
	l := NewLowerer()

	// Regular literal
	result := l.lowerExpr(&ast.Literal{Kind: "int", Value: "42"})

	lit, ok := result.(*ir.LiteralExpr)
	if !ok {
		t.Fatalf("expected *ir.LiteralExpr, got %T", result)
	}

	if lit.Value != "42" {
		t.Errorf("Value = %q, want %q", lit.Value, "42")
	}

	// nullptr
	result = l.lowerExpr(&ast.Literal{Kind: "nullptr", Value: "nullptr"})

	ident, ok := result.(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr for nullptr, got %T", result)
	}

	if ident.Name != "nil" {
		t.Errorf("Name = %q, want %q", ident.Name, "nil")
	}

	// char literal → string
	result = l.lowerExpr(&ast.Literal{Kind: "char", Value: "'a'"})

	lit, ok = result.(*ir.LiteralExpr)
	if !ok {
		t.Fatalf("expected *ir.LiteralExpr, got %T", result)
	}

	if lit.Kind != "string" {
		t.Errorf("Kind = %q, want %q", lit.Kind, "string")
	}
}

func TestLowerExpr_Identifier(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.Identifier{Name: "myVar"})

	ident, ok := result.(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr, got %T", result)
	}

	if ident.Name != "myVar" {
		t.Errorf("Name = %q, want %q", ident.Name, "myVar")
	}
}

func TestLowerExpr_BinaryExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.BinaryExpr{
		Left:     &ast.Identifier{Name: "a"},
		Operator: "+",
		Right:    &ast.Identifier{Name: "b"},
	})

	bin, ok := result.(*ir.BinaryExpr)
	if !ok {
		t.Fatalf("expected *ir.BinaryExpr, got %T", result)
	}

	if bin.Op != "+" {
		t.Errorf("Op = %q, want %q", bin.Op, "+")
	}
}

func TestLowerExpr_UnaryExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.UnaryExpr{
		Operator: "!",
		Operand:  &ast.Identifier{Name: "flag"},
		Prefix:   true,
	})

	unary, ok := result.(*ir.UnaryExpr)
	if !ok {
		t.Fatalf("expected *ir.UnaryExpr, got %T", result)
	}

	if unary.Op != "!" {
		t.Errorf("Op = %q, want %q", unary.Op, "!")
	}

	if !unary.Prefix {
		t.Error("expected Prefix = true")
	}
}

func TestLowerExpr_CallExpr_Simple(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.CallExpr{
		Func: &ast.Identifier{Name: "printf"},
		Args: []ast.Expr{
			&ast.Literal{Kind: "string", Value: `"hello"`},
		},
	})

	call, ok := result.(*ir.CallExpr)
	if !ok {
		t.Fatalf("expected *ir.CallExpr, got %T", result)
	}

	if call.Func != "printf" {
		t.Errorf("Func = %q, want %q", call.Func, "printf")
	}

	if len(call.Args) != 1 {
		t.Errorf("Args = %d, want 1", len(call.Args))
	}
}

func TestLowerExpr_CallExpr_MemberFunc(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.CallExpr{
		Func: &ast.MemberExpr{
			Object: &ast.Identifier{Name: "vec"},
			Member: "push_back",
		},
		Args: []ast.Expr{&ast.Literal{Kind: "int", Value: "42"}},
	})

	mc, ok := result.(*ir.MethodCallExpr)
	if !ok {
		t.Fatalf("expected *ir.MethodCallExpr, got %T", result)
	}

	if mc.Method != "push_back" {
		t.Errorf("Method = %q, want %q", mc.Method, "push_back")
	}
}

func TestLowerExpr_CallExpr_ScopeResolution(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.CallExpr{
		Func: &ast.ScopeExpr{Scope: "std", Name: "sort"},
		Args: []ast.Expr{},
	})

	call, ok := result.(*ir.CallExpr)
	if !ok {
		t.Fatalf("expected *ir.CallExpr, got %T", result)
	}

	if call.Func != "sort.Slice" {
		t.Errorf("Func = %q, want %q", call.Func, "sort.Slice")
	}
}

func TestLowerExpr_MemberExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.MemberExpr{
		Object: &ast.Identifier{Name: "obj"},
		Member: "field",
	})

	sel, ok := result.(*ir.SelectorExpr)
	if !ok {
		t.Fatalf("expected *ir.SelectorExpr, got %T", result)
	}

	if sel.Sel != "field" {
		t.Errorf("Sel = %q, want %q", sel.Sel, "field")
	}
}

func TestLowerExpr_ScopeExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.ScopeExpr{
		Scope: "std",
		Name:  "cout",
	})

	ident, ok := result.(*ir.IdentExpr)
	if !ok {
		t.Fatalf("expected *ir.IdentExpr, got %T", result)
	}

	if ident.Name != "fmt.Print" {
		t.Errorf("Name = %q, want %q", ident.Name, "fmt.Print")
	}
}

func TestLowerExpr_IndexExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.IndexExpr{
		Object: &ast.Identifier{Name: "arr"},
		Index:  &ast.Literal{Kind: "int", Value: "0"},
	})

	idx, ok := result.(*ir.IndexExpr)
	if !ok {
		t.Fatalf("expected *ir.IndexExpr, got %T", result)
	}

	if idx.X == nil || idx.Index == nil {
		t.Error("expected non-nil X and Index")
	}
}

func TestLowerExpr_Assignment(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.Assignment{
		Target:   &ast.Identifier{Name: "x"},
		Operator: "=",
		Value:    &ast.Literal{Kind: "int", Value: "5"},
	})

	raw, ok := result.(*ir.RawExpr)
	if !ok {
		t.Fatalf("expected *ir.RawExpr, got %T", result)
	}

	if raw.Text == "" {
		t.Error("expected non-empty text")
	}
}

func TestLowerExpr_NewExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.NewExpr{
		Type: &ast.TypeRef{Name: "MyClass"},
	})

	addr, ok := result.(*ir.AddressExpr)
	if !ok {
		t.Fatalf("expected *ir.AddressExpr, got %T", result)
	}

	if addr.X == nil {
		t.Error("expected non-nil X")
	}
}

func TestLowerExpr_DeleteExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.DeleteExpr{
		Operand: &ast.Identifier{Name: "ptr"},
	})

	raw, ok := result.(*ir.RawExpr)
	if !ok {
		t.Fatalf("expected *ir.RawExpr, got %T", result)
	}

	if raw.Text == "" {
		t.Error("expected non-empty text about GC")
	}
}

func TestLowerExpr_CastExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.CastExpr{
		Kind:    "static_cast",
		Type:    &ast.TypeRef{Name: "int"},
		Operand: &ast.Identifier{Name: "x"},
	})

	call, ok := result.(*ir.CallExpr)
	if !ok {
		t.Fatalf("expected *ir.CallExpr, got %T", result)
	}

	if call.Func != "int" {
		t.Errorf("Func = %q, want %q", call.Func, "int")
	}

	if len(call.Args) != 1 {
		t.Errorf("Args = %d, want 1", len(call.Args))
	}
}

func TestLowerExpr_LambdaExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.LambdaExpr{
		Params: []*ast.Parameter{
			{Name: "x", Type: &ast.TypeRef{Name: "int"}},
		},
		ReturnType: &ast.TypeRef{Name: "int"},
		Body: []ast.Node{
			&ast.ReturnStmt{Value: &ast.Identifier{Name: "x"}},
		},
	})

	fn, ok := result.(*ir.FuncLitExpr)
	if !ok {
		t.Fatalf("expected *ir.FuncLitExpr, got %T", result)
	}

	if len(fn.Params) != 1 {
		t.Errorf("Params = %d, want 1", len(fn.Params))
	}

	if len(fn.Returns) != 1 {
		t.Errorf("Returns = %d, want 1", len(fn.Returns))
	}

	if len(fn.Body) != 1 {
		t.Errorf("Body = %d, want 1", len(fn.Body))
	}
}

func TestLowerExpr_LambdaVoidReturn(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.LambdaExpr{
		ReturnType: &ast.TypeRef{Name: "void"},
	})

	fn, ok := result.(*ir.FuncLitExpr)
	if !ok {
		t.Fatalf("expected *ir.FuncLitExpr, got %T", result)
	}

	if len(fn.Returns) != 0 {
		t.Errorf("expected no returns for void lambda, got %d", len(fn.Returns))
	}
}

func TestLowerExpr_RawExpr(t *testing.T) {
	l := NewLowerer()
	result := l.lowerExpr(&ast.RawExpr{Text: "complex_macro()"})

	raw, ok := result.(*ir.RawExpr)
	if !ok {
		t.Fatalf("expected *ir.RawExpr, got %T", result)
	}

	if raw.Text != "complex_macro()" {
		t.Errorf("Text = %q, want %q", raw.Text, "complex_macro()")
	}
}

func TestMapStdFunction(t *testing.T) {
	l := NewLowerer()

	tests := []struct {
		scope string
		name  string
		want  string
	}{
		{"std", "cout", "fmt.Print"},
		{"std", "endl", `"\n"`},
		{"std", "sort", "sort.Slice"},
		{"std", "make_unique", "new"},
		{"std", "make_shared", "new"},
		{"std", "move", ""},
		{"std", "to_string", "fmt.Sprint"},
		{"std", "stoi", "strconv.Atoi"},
		{"std", "stof", "strconv.ParseFloat"},
		{"std", "stod", "strconv.ParseFloat"},
		{"std", "min", "min"},
		{"std", "max", "max"},
		{"std", "abs", "math.Abs"},
		{"std", "swap", "/* swap */"},
		{"std", "find", "slices.Index"},
		{"std", "begin", ""},
		{"std", "end", ""},
		{"std", "lock_guard", "sync.Mutex"},
		{"std", "unique_lock", "sync.Mutex"},
		{"std", "thread", "go"},
		{"std", "async", "go"},
		{"std", "this_thread::sleep_for", "time.Sleep"},
		{"std", "unknown_func", "std.unknown_func"},
		{"boost", "filesystem", "boost.filesystem"},
	}

	for _, tt := range tests {
		t.Run(tt.scope+"::"+tt.name, func(t *testing.T) {
			got := l.mapStdFunction(tt.scope, tt.name)
			if got != tt.want {
				t.Errorf("mapStdFunction(%q, %q) = %q, want %q", tt.scope, tt.name, got, tt.want)
			}
		})
	}
}

func TestLowerType_AdditionalContainers(t *testing.T) {
	l := NewLowerer()

	tests := []struct {
		name     string
		typeRef  *ast.TypeRef
		wantKind ir.TypeKind
		wantName string
	}{
		{
			name:     "nil type",
			typeRef:  nil,
			wantKind: ir.KindPrimitive,
			wantName: "any",
		},
		{
			name:     "set",
			typeRef:  &ast.TypeRef{Name: "std::set", TemplateArgs: []*ast.TypeRef{{Name: "int"}}},
			wantKind: ir.KindMap,
		},
		{
			name:     "unordered_set",
			typeRef:  &ast.TypeRef{Name: "std::unordered_set", TemplateArgs: []*ast.TypeRef{{Name: "std::string"}}},
			wantKind: ir.KindMap,
		},
		{
			name:     "optional",
			typeRef:  &ast.TypeRef{Name: "std::optional", TemplateArgs: []*ast.TypeRef{{Name: "int"}}},
			wantKind: ir.KindPointer,
		},
		{
			name:     "pair",
			typeRef:  &ast.TypeRef{Name: "std::pair"},
			wantKind: ir.KindStruct,
		},
		{
			name:     "tuple",
			typeRef:  &ast.TypeRef{Name: "std::tuple"},
			wantKind: ir.KindStruct,
		},
		{
			name:     "function",
			typeRef:  &ast.TypeRef{Name: "std::function"},
			wantKind: ir.KindFunc,
		},
		{
			name:     "mutex",
			typeRef:  &ast.TypeRef{Name: "std::mutex"},
			wantKind: ir.KindStruct,
			wantName: "sync.Mutex",
		},
		{
			name:     "atomic",
			typeRef:  &ast.TypeRef{Name: "std::atomic"},
			wantKind: ir.KindStruct,
			wantName: "atomic.Value",
		},
		{
			name:     "thread",
			typeRef:  &ast.TypeRef{Name: "std::thread"},
			wantKind: ir.KindPrimitive,
		},
		{
			name:     "pointer type",
			typeRef:  &ast.TypeRef{Name: "MyClass", Pointer: true},
			wantKind: ir.KindPointer,
		},
		{
			name:     "reference type",
			typeRef:  &ast.TypeRef{Name: "int", Reference: true},
			wantKind: ir.KindPrimitive,
			wantName: "int",
		},
		{
			name:     "rvalue reference",
			typeRef:  &ast.TypeRef{Name: "std::string", RValueRef: true},
			wantKind: ir.KindPrimitive,
			wantName: "string",
		},
		{
			name:     "unordered_map",
			typeRef:  &ast.TypeRef{Name: "std::unordered_map", TemplateArgs: []*ast.TypeRef{{Name: "std::string"}, {Name: "int"}}},
			wantKind: ir.KindMap,
		},
		{
			name:     "vector no template args",
			typeRef:  &ast.TypeRef{Name: "vector"},
			wantKind: ir.KindSlice,
		},
		{
			name:     "map single arg",
			typeRef:  &ast.TypeRef{Name: "map", TemplateArgs: []*ast.TypeRef{{Name: "int"}}},
			wantKind: ir.KindMap,
		},
		{
			name:     "unique_ptr no args",
			typeRef:  &ast.TypeRef{Name: "unique_ptr"},
			wantKind: ir.KindPointer,
		},
		{
			name:     "optional no args",
			typeRef:  &ast.TypeRef{Name: "optional"},
			wantKind: ir.KindPointer,
		},
		{
			name:     "set no args",
			typeRef:  &ast.TypeRef{Name: "set"},
			wantKind: ir.KindMap,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := l.lowerType(tt.typeRef)
			if ref.Kind != tt.wantKind {
				t.Errorf("Kind = %q, want %q", ref.Kind, tt.wantKind)
			}

			if tt.wantName != "" && ref.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", ref.Name, tt.wantName)
			}
		})
	}
}

func TestLower_IncludeMapping_AllHeaders(t *testing.T) {
	l := NewLowerer()

	tests := []struct {
		header  string
		wantPkg string
		system  bool
	}{
		{"iostream", "fmt", true},
		{"cstdio", "fmt", true},
		{"stdio.h", "fmt", true},
		{"fstream", "os", true},
		{"cstdlib", "os", true},
		{"string", "strings", true},
		{"algorithm", "sort", true},
		{"cmath", "math", true},
		{"math.h", "math", true},
		{"thread", "sync", true},
		{"mutex", "sync", true},
		{"atomic", "sync/atomic", true},
		{"chrono", "time", true},
		{"ctime", "time", true},
		{"regex", "regexp", true},
		{"filesystem", "os", true},
		{"sstream", "fmt", true},
		{"iomanip", "fmt", true},
		{"exception", "errors", true},
		{"stdexcept", "errors", true},
		{"random", "math/rand", true},
		{"json/json.h", "encoding/json", true},
		{"nlohmann/json.hpp", "encoding/json", true},
		{"myheader.h", "", false}, // non-system
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			tu := &ast.TranslationUnit{
				FileName: "test.cpp",
				Includes: []*ast.Include{
					{Path: tt.header, System: tt.system},
				},
			}
			mod := l.Lower(tu)

			if tt.wantPkg == "" {
				if len(mod.Imports) != 0 {
					t.Errorf("expected 0 imports for non-system header, got %d", len(mod.Imports))
				}

				return
			}

			found := false

			for _, imp := range mod.Imports {
				if imp.Path == tt.wantPkg {
					found = true
				}
			}

			if !found {
				t.Errorf("expected import %q for header %q", tt.wantPkg, tt.header)
			}
		})
	}
}
