package codegen

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

func TestGenerate_EmptyModule(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "package main") {
		t.Error("expected 'package main' in output")
	}
}

func TestGenerate_WithImports(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Imports: []*ir.Import{
			{Path: "fmt"},
			{Path: "os"},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// goimports might remove unused imports, but the format should work
	if result == "" {
		t.Error("expected non-empty output")
	}
}

func TestGenerate_Struct(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclStruct,
				Name: "Point",
				Fields: []*ir.FieldDecl{
					{Name: "X", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "float64"}},
					{Name: "Y", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "float64"}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "type Point struct") {
		t.Error("expected 'type Point struct' in output")
	}

	if !strings.Contains(result, "X float64") {
		t.Error("expected 'X float64' field in output")
	}
}

func TestGenerate_Interface(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclInterface,
				Name: "Reader",
				Methods: []*ir.FuncDecl{
					{
						Name: "Read",
						Params: []*ir.ParamDecl{
							{Name: "p", Type: &ir.TypeRef{Kind: ir.KindSlice, Name: "[]byte", ElemType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "byte"}}},
						},
						Returns: []*ir.ParamDecl{
							{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
							{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "error"}},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "type Reader interface") {
		t.Error("expected 'type Reader interface' in output")
	}
}

func TestGenerate_Enum(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclEnum,
				Name: "Color",
				Values: []*ir.EnumVal{
					{Name: "ColorRed"},
					{Name: "ColorGreen"},
					{Name: "ColorBlue"},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "type Color int") {
		t.Error("expected 'type Color int' in output")
	}

	if !strings.Contains(result, "iota") {
		t.Error("expected 'iota' in output")
	}

	if !strings.Contains(result, "ColorRed") {
		t.Error("expected 'ColorRed' in output")
	}
}

func TestGenerate_Function(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Imports:     []*ir.Import{{Path: "fmt"}},
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Hello",
				Params: []*ir.ParamDecl{
					{Name: "name", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}},
				},
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.CallExpr{
						Func: "fmt.Println",
						Args: []ir.Expr{&ir.IdentExpr{Name: "name"}},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "func Hello") {
		t.Error("expected 'func Hello' in output")
	}

	if !strings.Contains(result, "fmt.Println") {
		t.Error("expected 'fmt.Println' in output")
	}
}

func TestGenerate_Method(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclStruct,
				Name: "Point",
				Fields: []*ir.FieldDecl{
					{Name: "X", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "float64"}},
				},
			},
			&ir.FuncDecl{
				Name: "GetX",
				Receiver: &ir.ParamDecl{
					Name: "p",
					Type: &ir.TypeRef{Kind: ir.KindPointer, Name: "*Point"},
				},
				Returns: []*ir.ParamDecl{
					{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "float64"}},
				},
				Body: []ir.Node{
					&ir.ReturnStmt{Values: []ir.Expr{
						&ir.SelectorExpr{X: &ir.IdentExpr{Name: "p"}, Sel: "X"},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "(p *Point)") {
		t.Error("expected method receiver '(p *Point)' in output")
	}

	if !strings.Contains(result, "return p.X") {
		t.Error("expected 'return p.X' in output")
	}
}

func TestGenerate_IfElse(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Check",
				Params: []*ir.ParamDecl{
					{Name: "x", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
				},
				Body: []ir.Node{
					&ir.IfStmt{
						Cond: &ir.BinaryExpr{
							Left:  &ir.IdentExpr{Name: "x"},
							Op:    ">",
							Right: &ir.LiteralExpr{Kind: "int", Value: "0"},
						},
						Then: []ir.Node{
							&ir.ReturnStmt{Values: []ir.Expr{&ir.LiteralExpr{Kind: "string", Value: `"positive"`}}},
						},
						Else: []ir.Node{
							&ir.ReturnStmt{Values: []ir.Expr{&ir.LiteralExpr{Kind: "string", Value: `"non-positive"`}}},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "if x > 0") {
		t.Error("expected 'if x > 0' in output")
	}

	if !strings.Contains(result, "} else {") {
		t.Error("expected else clause in output")
	}
}

func TestGenerate_ForLoop(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  "test.cpp",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Loop",
				Body: []ir.Node{
					&ir.ForStmt{
						Cond: &ir.BinaryExpr{
							Left:  &ir.IdentExpr{Name: "i"},
							Op:    "<",
							Right: &ir.LiteralExpr{Kind: "int", Value: "10"},
						},
						Body: []ir.Node{
							&ir.ExprStmt{Expr: &ir.IdentExpr{Name: "/* body */"}},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "for i < 10") {
		t.Error("expected 'for i < 10' in output")
	}
}

func TestTypeString(t *testing.T) {
	gen := New()

	tests := []struct {
		name string
		typ  *ir.TypeRef
		want string
	}{
		{"nil", nil, "any"},
		{"primitive", &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}, "int"},
		{"slice", &ir.TypeRef{Kind: ir.KindSlice, ElemType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}}, "[]int"},
		{"slice nil elem", &ir.TypeRef{Kind: ir.KindSlice}, "[]any"},
		{"map", &ir.TypeRef{Kind: ir.KindMap, KeyType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}, ValType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}}, "map[string]int"},
		{"map nil keys", &ir.TypeRef{Kind: ir.KindMap}, "map[string]any"},
		{"pointer", &ir.TypeRef{Kind: ir.KindPointer, ElemType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}}, "*int"},
		{"pointer no elem", &ir.TypeRef{Kind: ir.KindPointer, Name: "*MyType"}, "*MyType"},
		{"channel", &ir.TypeRef{Kind: ir.KindChannel, ElemType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}}, "chan int"},
		{"channel nil elem", &ir.TypeRef{Kind: ir.KindChannel}, "chan any"},
		{"generic", &ir.TypeRef{Kind: ir.KindGeneric, Name: "Container", TypeParams: []*ir.TypeRef{
			{Kind: ir.KindPrimitive, Name: "int"},
		}}, "Container[int]"},
		{"generic no params", &ir.TypeRef{Kind: ir.KindGeneric, Name: "Thing"}, "Thing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gen.typeString(tt.typ)
			if got != tt.want {
				t.Errorf("typeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerate_VarDecl_Const(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.VarDecl{
				Name:  "MaxSize",
				Type:  &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"},
				Const: true,
				Value: &ir.LiteralExpr{Kind: "int", Value: "100"},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "const MaxSize") {
		t.Error("expected 'const MaxSize' in output")
	}
}

func TestGenerate_VarDecl_WithValue(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Foo",
				Body: []ir.Node{
					&ir.VarDecl{
						Name:  "x",
						Value: &ir.LiteralExpr{Kind: "int", Value: "42"},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "x := 42") {
		t.Error("expected 'x := 42' in output")
	}
}

func TestGenerate_VarDecl_NoValue(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Foo",
				Body: []ir.Node{
					&ir.VarDecl{
						Name: "x",
						Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "var x int") {
		t.Error("expected 'var x int' in output")
	}
}

func TestGenerate_RangeLoop(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Iterate",
				Body: []ir.Node{
					&ir.RangeStmt{
						Key:   "i",
						Value: "v",
						Range: &ir.IdentExpr{Name: "items"},
						Body:  []ir.Node{},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "for i, v := range items") {
		t.Error("expected 'for i, v := range items' in output")
	}
}

func TestGenerate_RangeLoop_NoKeyValue(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Iterate",
				Body: []ir.Node{
					&ir.RangeStmt{
						Range: &ir.IdentExpr{Name: "items"},
						Body:  []ir.Node{},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "for _, _ := range items") {
		t.Error("expected 'for _, _ := range items' in output")
	}
}

func TestGenerate_SwitchStmt(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Classify",
				Body: []ir.Node{
					&ir.SwitchStmt{
						Tag: &ir.IdentExpr{Name: "x"},
						Cases: []*ir.CaseClause{
							{
								Values: []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "1"}},
								Body:   []ir.Node{&ir.ReturnStmt{}},
							},
							{
								Default: true,
								Body:    []ir.Node{&ir.ReturnStmt{}},
							},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "switch x") {
		t.Error("expected 'switch x' in output")
	}

	if !strings.Contains(result, "case 1") {
		t.Error("expected 'case 1' in output")
	}

	if !strings.Contains(result, "default:") {
		t.Error("expected 'default:' in output")
	}
}

func TestGenerate_SwitchNoTag(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Check",
				Body: []ir.Node{
					&ir.SwitchStmt{
						Cases: []*ir.CaseClause{
							{Default: true, Body: []ir.Node{&ir.ReturnStmt{}}},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "switch {") {
		t.Error("expected 'switch {' in output")
	}
}

func TestGenerate_AssignStmt(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Assign",
				Body: []ir.Node{
					&ir.AssignStmt{
						LHS: []ir.Expr{&ir.IdentExpr{Name: "x"}},
						Op:  "=",
						RHS: []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "5"}},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "x = 5") {
		t.Error("expected 'x = 5' in output")
	}
}

func TestGenerate_MultiAssign(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "MultiAssign",
				Body: []ir.Node{
					&ir.AssignStmt{
						LHS: []ir.Expr{&ir.IdentExpr{Name: "a"}, &ir.IdentExpr{Name: "b"}},
						Op:  ":=",
						RHS: []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "1"}, &ir.LiteralExpr{Kind: "int", Value: "2"}},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "a, b := 1, 2") {
		t.Error("expected 'a, b := 1, 2' in output")
	}
}

func TestGenerate_DeferStmt(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "WithDefer",
				Body: []ir.Node{
					&ir.DeferStmt{
						Call: &ir.MethodCallExpr{
							Receiver: &ir.IdentExpr{Name: "f"},
							Method:   "Close",
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "defer f.Close()") {
		t.Error("expected 'defer f.Close()' in output")
	}
}

func TestGenerate_BranchStmt(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "WithBreak",
				Body: []ir.Node{
					&ir.BranchStmt{Kind: "break"},
					&ir.BranchStmt{Kind: "continue"},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "break") {
		t.Error("expected 'break' in output")
	}

	if !strings.Contains(result, "continue") {
		t.Error("expected 'continue' in output")
	}
}

func TestGenerate_ErrorHandling(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "HandleErr",
				Body: []ir.Node{
					&ir.ErrorHandling{
						ErrVar: "err",
						Call:   &ir.CallExpr{Func: "doSomething"},
						Body: []ir.Node{
							&ir.ReturnStmt{Values: []ir.Expr{&ir.IdentExpr{Name: "err"}}},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "err := doSomething()") {
		t.Error("expected 'err := doSomething()' in output")
	}

	if !strings.Contains(result, "if err != nil") {
		t.Error("expected 'if err != nil' in output")
	}
}

func TestGenerate_RawStmt(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.RawStmt{Comment: "from namespace mylib"},
			&ir.RawStmt{Text: "// custom raw text"},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "// from namespace mylib") {
		t.Error("expected comment in output")
	}

	if !strings.Contains(result, "// custom raw text") {
		t.Error("expected raw text in output")
	}
}

func TestGenerate_Expressions(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Exprs",
				Body: []ir.Node{
					// Unary prefix
					&ir.ExprStmt{Expr: &ir.UnaryExpr{Op: "!", Operand: &ir.IdentExpr{Name: "flag"}, Prefix: true}},
					// Unary postfix
					&ir.ExprStmt{Expr: &ir.UnaryExpr{Op: "++", Operand: &ir.IdentExpr{Name: "i"}, Prefix: false}},
					// Method call
					&ir.ExprStmt{Expr: &ir.MethodCallExpr{
						Receiver: &ir.IdentExpr{Name: "obj"},
						Method:   "DoIt",
						Args:     []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "1"}, &ir.LiteralExpr{Kind: "int", Value: "2"}},
					}},
					// Selector
					&ir.ExprStmt{Expr: &ir.SelectorExpr{X: &ir.IdentExpr{Name: "p"}, Sel: "X"}},
					// Index
					&ir.ExprStmt{Expr: &ir.IndexExpr{X: &ir.IdentExpr{Name: "arr"}, Index: &ir.LiteralExpr{Kind: "int", Value: "0"}}},
					// Address
					&ir.ExprStmt{Expr: &ir.AddressExpr{X: &ir.IdentExpr{Name: "val"}}},
					// Deref
					&ir.ExprStmt{Expr: &ir.DerefExpr{X: &ir.IdentExpr{Name: "ptr"}}},
					// Raw
					&ir.ExprStmt{Expr: &ir.RawExpr{Text: "/* raw */"}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	checks := []string{
		"!flag",
		"i++",
		"obj.DoIt(1, 2)",
		"p.X",
		"arr[0]",
		"&val",
		"*ptr",
		"/* raw */",
	}

	for _, check := range checks {
		if !strings.Contains(result, check) {
			t.Errorf("expected %q in output", check)
		}
	}
}

func TestGenerate_CompositeLit(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "MakePoint",
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.CompositeLitExpr{
						Type: &ir.TypeRef{Kind: ir.KindStruct, Name: "Point"},
						Fields: []*ir.KeyValue{
							{Key: &ir.IdentExpr{Name: "X"}, Value: &ir.LiteralExpr{Kind: "int", Value: "1"}},
							{Value: &ir.LiteralExpr{Kind: "int", Value: "2"}},
						},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "Point{X: 1, 2}") {
		t.Errorf("expected 'Point{X: 1, 2}' in output, got:\n%s", result)
	}
}

func TestGenerate_FuncLit(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "WithCallback",
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.FuncLitExpr{
						Params: []*ir.ParamDecl{
							{Name: "x", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
						},
						Returns: []*ir.ParamDecl{
							{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
						},
						Body: []ir.Node{
							&ir.ReturnStmt{Values: []ir.Expr{&ir.IdentExpr{Name: "x"}}},
						},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "func(x int) int") {
		t.Error("expected 'func(x int) int' in output")
	}
}

func TestGenerate_MakeExpr(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "MakeSlice",
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.MakeExpr{
						Type: &ir.TypeRef{Kind: ir.KindSlice, ElemType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
						Len:  &ir.LiteralExpr{Kind: "int", Value: "10"},
						Cap:  &ir.LiteralExpr{Kind: "int", Value: "20"},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "make([]int, 10, 20)") {
		t.Error("expected 'make([]int, 10, 20)' in output")
	}
}

func TestGenerate_MakeExprNoLenCap(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "MakeMap",
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.MakeExpr{
						Type: &ir.TypeRef{Kind: ir.KindMap, KeyType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}, ValType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "make(map[string]int)") {
		t.Error("expected 'make(map[string]int)' in output")
	}
}

func TestGenerate_InfiniteFor(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Forever",
				Body: []ir.Node{
					&ir.ForStmt{
						Body: []ir.Node{
							&ir.BranchStmt{Kind: "break"},
						},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "for {") {
		t.Error("expected 'for {' in output")
	}
}

func TestGenerate_ForWithInit(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Classic",
				Body: []ir.Node{
					&ir.ForStmt{
						Init: &ir.VarDecl{Name: "i", Value: &ir.LiteralExpr{Kind: "int", Value: "0"}},
						Cond: &ir.BinaryExpr{Left: &ir.IdentExpr{Name: "i"}, Op: "<", Right: &ir.LiteralExpr{Kind: "int", Value: "10"}},
						Post: &ir.UnaryExpr{Op: "++", Operand: &ir.IdentExpr{Name: "i"}, Prefix: false},
						Body: []ir.Node{},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "for i := 0; i < 10; i++") {
		t.Errorf("expected 'for i := 0; i < 10; i++' in output, got:\n%s", result)
	}
}

func TestGenerate_ForInitAssign(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "AssignInit",
				Body: []ir.Node{
					&ir.ForStmt{
						Init: &ir.AssignStmt{
							LHS: []ir.Expr{&ir.IdentExpr{Name: "i"}},
							Op:  "=",
							RHS: []ir.Expr{&ir.LiteralExpr{Kind: "int", Value: "0"}},
						},
						Cond: &ir.BinaryExpr{Left: &ir.IdentExpr{Name: "i"}, Op: "<", Right: &ir.LiteralExpr{Kind: "int", Value: "5"}},
						Body: []ir.Node{},
					},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "i = 0; i < 5;") {
		t.Errorf("expected assignment init in for loop, got:\n%s", result)
	}
}

func TestGenerate_StructWithEmbedded(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind:     ir.TypeDeclStruct,
				Name:     "Derived",
				Embedded: []string{"Base"},
				Fields: []*ir.FieldDecl{
					{Name: "Extra", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "Base") {
		t.Error("expected embedded 'Base' in output")
	}
}

func TestGenerate_StructWithTypeParams(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind:       ir.TypeDeclStruct,
				Name:       "Container",
				TypeParams: []string{"T"},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "type Container[T any] struct") {
		t.Errorf("expected generic struct, got:\n%s", result)
	}
}

func TestGenerate_FuncWithTypeParams(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name:       "Identity",
				TypeParams: []string{"T"},
				Params: []*ir.ParamDecl{
					{Name: "v", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "T"}},
				},
				Returns: []*ir.ParamDecl{
					{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "T"}},
				},
				Body: []ir.Node{
					&ir.ReturnStmt{Values: []ir.Expr{&ir.IdentExpr{Name: "v"}}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "Identity[T any]") {
		t.Errorf("expected generic function, got:\n%s", result)
	}
}

func TestGenerate_FuncWithComment(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name:    "Documented",
				Comment: "Documented does something",
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "// Documented does something") {
		t.Error("expected function comment in output")
	}
}

func TestGenerate_EmptyFuncBody(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Empty",
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "func Empty() {}") {
		t.Errorf("expected 'func Empty() {}' in output, got:\n%s", result)
	}
}

func TestGenerate_ImportAlias(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Imports: []*ir.Import{
			{Path: "math/rand", Alias: "mrand"},
		},
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Rand",
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.CallExpr{Func: "mrand.Int"}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "mrand") {
		t.Error("expected import alias 'mrand' in output")
	}
}

func TestGenerate_ReturnMultipleValues(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Divide",
				Returns: []*ir.ParamDecl{
					{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
					{Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "error"}},
				},
				Body: []ir.Node{
					&ir.ReturnStmt{Values: []ir.Expr{
						&ir.LiteralExpr{Kind: "int", Value: "0"},
						&ir.IdentExpr{Name: "nil"},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "return 0, nil") {
		t.Error("expected 'return 0, nil' in output")
	}
}

func TestGenerate_NamedReturns(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Named",
				Returns: []*ir.ParamDecl{
					{Name: "result", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}},
					{Name: "err", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "error"}},
				},
				Body: []ir.Node{
					&ir.ReturnStmt{},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "(result int, err error)") {
		t.Errorf("expected named returns, got:\n%s", result)
	}
}

func TestGenerate_EnumWithExplicitValues(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclEnum,
				Name: "Priority",
				Values: []*ir.EnumVal{
					{Name: "PriorityLow", Value: "1"},
					{Name: "PriorityMedium", Value: "5"},
					{Name: "PriorityHigh", Value: "10"},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "PriorityLow") || !strings.Contains(result, "= 1") {
		t.Errorf("expected explicit enum value for PriorityLow, got:\n%s", result)
	}

	if strings.Contains(result, "iota") {
		t.Error("should not use iota when explicit values present")
	}
}

func TestGenerate_FieldWithTag(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclStruct,
				Name: "Config",
				Fields: []*ir.FieldDecl{
					{Name: "Name", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}, Tag: `json:"name"`},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "`json:\"name\"`") {
		t.Errorf("expected field tag in output, got:\n%s", result)
	}
}

func TestGenerate_FieldWithComment(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind: ir.TypeDeclStruct,
				Name: "Annotated",
				Fields: []*ir.FieldDecl{
					{Name: "ID", Type: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}, Comment: "unique identifier"},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "// unique identifier") {
		t.Errorf("expected field comment in output, got:\n%s", result)
	}
}

func TestGenerate_TypeDeclWithComment(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.TypeDecl{
				Kind:    ir.TypeDeclStruct,
				Name:    "Commented",
				Comment: "A commented type",
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "// A commented type") {
		t.Error("expected type comment in output")
	}
}

func TestGenerate_CallWithMultipleArgs(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Imports:     []*ir.Import{{Path: "fmt"}},
		Decls: []ir.Node{
			&ir.FuncDecl{
				Name: "Multi",
				Body: []ir.Node{
					&ir.ExprStmt{Expr: &ir.CallExpr{
						Func: "fmt.Printf",
						Args: []ir.Expr{
							&ir.LiteralExpr{Kind: "string", Value: `"%d %d"`},
							&ir.LiteralExpr{Kind: "int", Value: "1"},
							&ir.LiteralExpr{Kind: "int", Value: "2"},
						},
					}},
				},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, `fmt.Printf("%d %d", 1, 2)`) {
		t.Errorf("expected multi-arg call, got:\n%s", result)
	}
}

func TestGenerate_VarDeclConstNoType(t *testing.T) {
	gen := New()
	mod := &ir.Module{
		PackageName: "main",
		Decls: []ir.Node{
			&ir.VarDecl{
				Name:  "Pi",
				Const: true,
				Value: &ir.LiteralExpr{Kind: "float", Value: "3.14"},
			},
		},
	}

	result, err := gen.Generate(mod)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "const Pi") {
		t.Error("expected 'const Pi' in output")
	}

	if !strings.Contains(result, "3.14") {
		t.Error("expected value in output")
	}
}
