package lower

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/pymodel"
)

func TestLowerDataclass(t *testing.T) {
	mod := &pymodel.Module{
		FileName: "models.py",
		Body: []*pymodel.Node{
			{
				Type:       pymodel.NodeClass,
				Name:       "User",
				Decorators: []string{"dataclass"},
				Metadata:   map[string]string{"bases": ""},
				Children: []*pymodel.Node{
					{Type: pymodel.NodeAssign, Name: "name", Metadata: map[string]string{"type_hint": "str"}},
					{Type: pymodel.NodeAssign, Name: "age", Metadata: map[string]string{"type_hint": "int"}},
					{Type: pymodel.NodeAssign, Name: "tags", Metadata: map[string]string{"type_hint": "list[str]"}},
				},
			},
		},
	}

	l := NewLowerer()
	irMod, err := l.Lower(mod)
	if err != nil {
		t.Fatal(err)
	}

	if irMod.PackageName != "models" {
		t.Errorf("package = %q, want %q", irMod.PackageName, "models")
	}

	if len(irMod.Decls) < 1 {
		t.Fatal("expected at least 1 declaration")
	}

	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}

	if td.Kind != ir.TypeDeclStruct {
		t.Errorf("kind = %q, want %q", td.Kind, ir.TypeDeclStruct)
	}

	if td.Name != "User" {
		t.Errorf("name = %q, want %q", td.Name, "User")
	}

	if len(td.Fields) != 3 {
		t.Fatalf("fields = %d, want 3", len(td.Fields))
	}

	if td.Fields[0].Name != "Name" || td.Fields[0].Type.Name != "string" {
		t.Errorf("field[0] = %q:%v, want Name:string", td.Fields[0].Name, td.Fields[0].Type)
	}

	if td.Fields[2].Type.Kind != ir.KindSlice {
		t.Errorf("field[2].type.kind = %q, want slice", td.Fields[2].Type.Kind)
	}
}

func TestLowerEnum(t *testing.T) {
	mod := &pymodel.Module{
		FileName: "status.py",
		Body: []*pymodel.Node{
			{
				Type:     pymodel.NodeClass,
				Name:     "Color",
				Metadata: map[string]string{"bases": "Enum"},
				Children: []*pymodel.Node{
					{Type: pymodel.NodeAssign, Name: "RED", Value: `"red"`},
					{Type: pymodel.NodeAssign, Name: "GREEN", Value: `"green"`},
					{Type: pymodel.NodeAssign, Name: "BLUE", Value: `"blue"`},
				},
			},
		},
	}

	l := NewLowerer()
	irMod, err := l.Lower(mod)
	if err != nil {
		t.Fatal(err)
	}

	if len(irMod.Decls) != 1 {
		t.Fatalf("decls = %d, want 1", len(irMod.Decls))
	}

	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}

	if td.Kind != ir.TypeDeclEnum {
		t.Errorf("kind = %q, want %q", td.Kind, ir.TypeDeclEnum)
	}

	if len(td.Values) != 3 {
		t.Fatalf("values = %d, want 3", len(td.Values))
	}

	if td.Values[0].Name != "ColorRED" {
		t.Errorf("values[0].name = %q, want ColorRED", td.Values[0].Name)
	}
}

func TestLowerABCInterface(t *testing.T) {
	mod := &pymodel.Module{
		FileName: "base.py",
		Body: []*pymodel.Node{
			{
				Type:     pymodel.NodeClass,
				Name:     "Repository",
				Metadata: map[string]string{"bases": "ABC"},
				Children: []*pymodel.Node{
					{
						Type:     pymodel.NodeFunction,
						Name:     "get",
						Params:   []*pymodel.Param{{Name: "self"}, {Name: "id", TypeHint: "str"}},
						Metadata: map[string]string{"return_type": "Optional[User]"},
					},
					{
						Type:     pymodel.NodeFunction,
						Name:     "save",
						Params:   []*pymodel.Param{{Name: "self"}, {Name: "entity", TypeHint: "User"}},
						Metadata: map[string]string{"return_type": "None"},
					},
				},
			},
		},
	}

	l := NewLowerer()
	irMod, err := l.Lower(mod)
	if err != nil {
		t.Fatal(err)
	}

	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}

	if td.Kind != ir.TypeDeclInterface {
		t.Errorf("kind = %q, want %q", td.Kind, ir.TypeDeclInterface)
	}

	if len(td.Methods) != 2 {
		t.Fatalf("methods = %d, want 2", len(td.Methods))
	}

	// get method should have Optional[User] return → pointer
	if len(td.Methods[0].Returns) == 0 {
		t.Fatal("get method has no returns")
	}
	if td.Methods[0].Returns[0].Type.Kind != ir.KindPointer {
		t.Errorf("get return type kind = %q, want pointer", td.Methods[0].Returns[0].Type.Kind)
	}

	// save method should have no returns (None)
	if len(td.Methods[1].Returns) != 0 {
		t.Errorf("save method has %d returns, want 0", len(td.Methods[1].Returns))
	}
}

func TestLowerFunction(t *testing.T) {
	mod := &pymodel.Module{
		FileName: "utils.py",
		Body: []*pymodel.Node{
			{
				Type: pymodel.NodeFunction,
				Name: "add",
				Params: []*pymodel.Param{
					{Name: "a", TypeHint: "int"},
					{Name: "b", TypeHint: "int"},
				},
				Metadata: map[string]string{"return_type": "int"},
				Children: []*pymodel.Node{
					{Type: pymodel.NodeReturn, Value: "a + b"},
				},
			},
		},
	}

	l := NewLowerer()
	irMod, err := l.Lower(mod)
	if err != nil {
		t.Fatal(err)
	}

	fn, ok := irMod.Decls[0].(*ir.FuncDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.FuncDecl", irMod.Decls[0])
	}

	if fn.Name != "Add" {
		t.Errorf("name = %q, want Add", fn.Name)
	}

	if fn.Receiver != nil {
		t.Error("free function should have nil receiver")
	}

	if len(fn.Params) != 2 {
		t.Fatalf("params = %d, want 2", len(fn.Params))
	}

	if fn.Params[0].Type.Name != "int" {
		t.Errorf("param[0].type = %q, want int", fn.Params[0].Type.Name)
	}

	if len(fn.Returns) != 1 || fn.Returns[0].Type.Name != "int" {
		t.Error("expected 1 return of type int")
	}

	if len(fn.Body) != 1 {
		t.Fatalf("body = %d, want 1", len(fn.Body))
	}
}

func TestLowerImports(t *testing.T) {
	mod := &pymodel.Module{
		FileName: "app.py",
		Imports: []*pymodel.Node{
			{Type: pymodel.NodeImport, Name: "json"},
			{Type: pymodel.NodeImport, Name: "os"},
			{Type: pymodel.NodeImport, Name: "datetime"},
		},
		Body: nil,
	}

	l := NewLowerer()
	irMod, err := l.Lower(mod)
	if err != nil {
		t.Fatal(err)
	}

	if len(irMod.Imports) != 3 {
		t.Fatalf("imports = %d, want 3", len(irMod.Imports))
	}

	// Should be sorted alphabetically
	paths := make([]string, len(irMod.Imports))
	for i, imp := range irMod.Imports {
		paths[i] = imp.Path
	}

	expected := []string{"encoding/json", "os", "time"}
	for i, want := range expected {
		if paths[i] != want {
			t.Errorf("import[%d] = %q, want %q", i, paths[i], want)
		}
	}
}

func TestLowerTypeMapping(t *testing.T) {
	tests := []struct {
		hint string
		kind ir.TypeKind
		name string
	}{
		{"str", ir.KindPrimitive, "string"},
		{"int", ir.KindPrimitive, "int"},
		{"float", ir.KindPrimitive, "float64"},
		{"bool", ir.KindPrimitive, "bool"},
		{"list[str]", ir.KindSlice, ""},
		{"dict[str, int]", ir.KindMap, ""},
		{"Optional[str]", ir.KindPointer, ""},
		{"set[int]", ir.KindMap, ""},
		{"bytes", ir.KindSlice, ""},
		{"MyClass", ir.KindStruct, "MyClass"},
		{"", ir.KindInterface, "any"},
	}

	for _, tt := range tests {
		t.Run(tt.hint, func(t *testing.T) {
			ref := mapTypeHint(tt.hint)
			if ref == nil {
				t.Fatal("got nil TypeRef")
			}
			if ref.Kind != tt.kind {
				t.Errorf("kind = %q, want %q", ref.Kind, tt.kind)
			}
			if tt.name != "" && ref.Name != tt.name {
				t.Errorf("name = %q, want %q", ref.Name, tt.name)
			}
		})
	}
}

func TestLowerEcommerce(t *testing.T) {
	// Build a simplified version of the ecommerce models.py
	mod := &pymodel.Module{
		FileName: "models.py",
		Imports: []*pymodel.Node{
			{Type: pymodel.NodeImport, Name: "dataclasses"},
			{Type: pymodel.NodeImport, Name: "enum"},
			{Type: pymodel.NodeImport, Name: "typing"},
			{Type: pymodel.NodeImport, Name: "uuid"},
		},
		Body: []*pymodel.Node{
			// Currency enum
			{
				Type:     pymodel.NodeClass,
				Name:     "Currency",
				Metadata: map[string]string{"bases": "Enum"},
				Children: []*pymodel.Node{
					{Type: pymodel.NodeAssign, Name: "USD", Value: `"USD"`},
					{Type: pymodel.NodeAssign, Name: "EUR", Value: `"EUR"`},
				},
			},
			// Money dataclass
			{
				Type:       pymodel.NodeClass,
				Name:       "Money",
				Decorators: []string{"dataclass"},
				Metadata:   map[string]string{"bases": ""},
				Children: []*pymodel.Node{
					{Type: pymodel.NodeAssign, Name: "amount", Metadata: map[string]string{"type_hint": "int"}},
					{Type: pymodel.NodeAssign, Name: "currency", Metadata: map[string]string{"type_hint": "Currency"}},
					{
						Type:     pymodel.NodeFunction,
						Name:     "display",
						Params:   []*pymodel.Param{{Name: "self"}},
						Metadata: map[string]string{"return_type": "str"},
						Value:    "whole = self.amount // 100\ncents = self.amount % 100\nreturn f\"{self.currency.value} {whole}.{cents:02d}\"",
					},
				},
			},
			// Product dataclass
			{
				Type:       pymodel.NodeClass,
				Name:       "Product",
				Decorators: []string{"dataclass"},
				Metadata:   map[string]string{"bases": ""},
				Children: []*pymodel.Node{
					{Type: pymodel.NodeAssign, Name: "id", Metadata: map[string]string{"type_hint": "str"}},
					{Type: pymodel.NodeAssign, Name: "name", Metadata: map[string]string{"type_hint": "str"}},
					{Type: pymodel.NodeAssign, Name: "price", Metadata: map[string]string{"type_hint": "Money"}},
					{Type: pymodel.NodeAssign, Name: "stock", Metadata: map[string]string{"type_hint": "int"}},
					{Type: pymodel.NodeAssign, Name: "tags", Metadata: map[string]string{"type_hint": "list[str]"}},
				},
			},
		},
	}

	l := NewLowerer()
	irMod, err := l.Lower(mod)
	if err != nil {
		t.Fatal(err)
	}

	if irMod.PackageName != "models" {
		t.Errorf("package = %q, want models", irMod.PackageName)
	}

	// Should have: Currency enum, Money struct + Display method, Product struct
	var (
		enumCount   int
		structCount int
		funcCount   int
	)
	for _, d := range irMod.Decls {
		switch n := d.(type) {
		case *ir.TypeDecl:
			switch n.Kind {
			case ir.TypeDeclEnum:
				enumCount++
				if n.Name != "Currency" {
					t.Errorf("enum name = %q, want Currency", n.Name)
				}
				if len(n.Values) != 2 {
					t.Errorf("enum values = %d, want 2", len(n.Values))
				}
			case ir.TypeDeclStruct:
				structCount++
			}
		case *ir.FuncDecl:
			funcCount++
		}
	}

	if enumCount != 1 {
		t.Errorf("enums = %d, want 1", enumCount)
	}
	if structCount != 2 {
		t.Errorf("structs = %d, want 2", structCount)
	}
	if funcCount < 1 {
		t.Errorf("funcs = %d, want >= 1", funcCount)
	}
}

func TestExportName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"hello", "Hello"},
		{"hello_world", "HelloWorld"},
		{"_private", "Private"},
		{"__dunder__", "Dunder"},
		{"already_Good", "AlreadyGood"},
	}
	for _, tt := range tests {
		got := exportName(tt.in)
		if got != tt.want {
			t.Errorf("exportName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPackageName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"models.py", "models"},
		{"__init__.py", "main"},
		{"__main__.py", "main"},
		{"my-app.py", "my_app"},
		{"path/to/utils.py", "utils"},
	}
	for _, tt := range tests {
		got := packageName(tt.in)
		if got != tt.want {
			t.Errorf("packageName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
