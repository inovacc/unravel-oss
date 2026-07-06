package lower

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/javamodel"
)

// countRaw walks IR nodes recursively counting *ir.RawStmt / *ir.RawExpr.
func countRaw(nodes []ir.Node) int {
	n := 0
	for _, nd := range nodes {
		switch v := nd.(type) {
		case *ir.RawStmt:
			n++
		case *ir.RawExpr:
			n++
		case *ir.ExprStmt:
			if _, ok := v.Expr.(*ir.RawExpr); ok {
				n++
			}
		case *ir.FuncDecl:
			n += countRaw(v.Body)
		case *ir.TypeDecl:
			for _, m := range v.Methods {
				n += countRaw(m.Body)
			}
		case *ir.ErrorHandling:
			n += countRaw(v.Body)
		case *ir.Block:
			n += countRaw(v.Stmts)
		}
	}
	return n
}

func TestLowerClass(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "User.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "User",
				Children: []*javamodel.Node{
					{Type: javamodel.NodeField, Name: "name", Metadata: map[string]string{"field_type": "String"}},
					{Type: javamodel.NodeMethod, Name: "getName", Metadata: map[string]string{"return_type": "String"}},
				},
			},
		},
	}

	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	if irMod.PackageName != "user" {
		t.Errorf("package = %q, want %q", irMod.PackageName, "user")
	}
	if len(irMod.Decls) < 1 {
		t.Fatal("expected at least 1 declaration")
	}
	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}
	if td.Kind != ir.TypeDeclStruct {
		t.Errorf("kind = %q, want struct", td.Kind)
	}
	if td.Name != "User" {
		t.Errorf("name = %q, want User", td.Name)
	}
}

func TestLowerInterface(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Repo.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeInterface,
				Name: "Repo",
				Children: []*javamodel.Node{
					{Type: javamodel.NodeMethod, Name: "save", Metadata: map[string]string{"return_type": "void"}},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}
	if td.Kind != ir.TypeDeclInterface {
		t.Errorf("kind = %q, want interface", td.Kind)
	}
}

func TestLowerAbstractClass(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Shape.java",
		Types: []*javamodel.Node{
			{
				Type:      javamodel.NodeClass,
				Name:      "Shape",
				Modifiers: []string{"abstract"},
				Children: []*javamodel.Node{
					{Type: javamodel.NodeMethod, Name: "area", Metadata: map[string]string{"return_type": "double"}},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	var hasIface, hasStruct bool
	for _, d := range irMod.Decls {
		if td, ok := d.(*ir.TypeDecl); ok {
			if td.Kind == ir.TypeDeclInterface {
				hasIface = true
			}
			if td.Kind == ir.TypeDeclStruct {
				hasStruct = true
			}
		}
	}
	if !hasIface || !hasStruct {
		t.Errorf("abstract class want interface+struct, got iface=%v struct=%v", hasIface, hasStruct)
	}
}

func TestLowerEnum(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Color.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeEnum,
				Name: "Color",
				Children: []*javamodel.Node{
					{Type: javamodel.NodeField, Name: "RED"},
					{Type: javamodel.NodeField, Name: "GREEN"},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}
	if td.Kind != ir.TypeDeclEnum {
		t.Errorf("kind = %q, want enum", td.Kind)
	}
	if len(td.Values) < 2 {
		t.Errorf("enum values = %d, want >= 2", len(td.Values))
	}
}

func TestLowerConstructor(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "User.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "User",
				Children: []*javamodel.Node{
					{Type: javamodel.NodeConstructor, Name: "User", Params: []*javamodel.Param{{Name: "name", Type: "String"}}},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range irMod.Decls {
		if fn, ok := d.(*ir.FuncDecl); ok && fn.Name == "NewUser" {
			found = true
		}
	}
	if !found {
		t.Error("expected a *ir.FuncDecl named NewUser")
	}
}

func TestLowerGenerics(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Box.java",
		Types: []*javamodel.Node{
			{
				Type:       javamodel.NodeClass,
				Name:       "Box",
				TypeParams: []string{"T"},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td, ok := irMod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("decl[0] is %T, want *ir.TypeDecl", irMod.Decls[0])
	}
	if len(td.TypeParams) != 1 || td.TypeParams[0] != "T" {
		t.Errorf("type params = %v, want [T]", td.TypeParams)
	}
}

func TestLowerThrows(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Io.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "Io",
				Children: []*javamodel.Node{
					{Type: javamodel.NodeMethod, Name: "read", Metadata: map[string]string{"throws": "IOException", "return_type": "void"}},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td := irMod.Decls[0].(*ir.TypeDecl)
	if len(td.Methods) < 1 {
		t.Fatal("expected a method")
	}
	m := td.Methods[0]
	var hasErr bool
	for _, r := range m.Returns {
		if r.Type != nil && r.Type.Name == "error" {
			hasErr = true
		}
	}
	if !hasErr {
		t.Error("method with throws should have trailing error return")
	}
}

func TestLowerTryCatch(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "T.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "T",
				Children: []*javamodel.Node{
					{
						Type: javamodel.NodeMethod, Name: "run",
						Children: []*javamodel.Node{
							{Type: javamodel.NodeTry, Value: "try { x(); } catch (Exception e) {}"},
						},
					},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td := irMod.Decls[0].(*ir.TypeDecl)
	if countRaw(td.Methods[0].Body) < 1 {
		t.Error("try/catch should lower to error-handling / raw IR")
	}
}

func TestLowerTryWithResources(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "T.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "T",
				Children: []*javamodel.Node{
					{
						Type: javamodel.NodeMethod, Name: "run",
						Children: []*javamodel.Node{
							{Type: javamodel.NodeTry, Value: "try (Reader r = open()) { r.read(); }", Metadata: map[string]string{"resources": "Reader r = open()"}},
						},
					},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td := irMod.Decls[0].(*ir.TypeDecl)
	var hasDefer bool
	for _, n := range td.Methods[0].Body {
		if _, ok := n.(*ir.DeferStmt); ok {
			hasDefer = true
		}
	}
	if !hasDefer {
		t.Error("try-with-resources should produce an ir.DeferStmt")
	}
}

func TestLowerStaticMethod(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Util.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "Util",
				Children: []*javamodel.Node{
					{Type: javamodel.NodeMethod, Name: "now", Modifiers: []string{"static"}, Metadata: map[string]string{"return_type": "long"}},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, d := range irMod.Decls {
		if fn, ok := d.(*ir.FuncDecl); ok && fn.Name == "Now" && fn.Receiver == nil {
			found = true
		}
	}
	if !found {
		t.Error("static method should be a package-level *ir.FuncDecl with no receiver")
	}
}

func TestLowerAdvancedFallback(t *testing.T) {
	mod := &javamodel.Module{
		FileName: "Stream.java",
		Types: []*javamodel.Node{
			{
				Type: javamodel.NodeClass,
				Name: "Stream",
				Children: []*javamodel.Node{
					{
						Type: javamodel.NodeMethod, Name: "go",
						Children: []*javamodel.Node{
							{Type: javamodel.NodeLambda, Value: "list.stream().map(x -> x*2).collect(toList())"},
						},
					},
				},
			},
		},
	}
	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatal(err)
	}
	td := irMod.Decls[0].(*ir.TypeDecl)
	if countRaw(td.Methods[0].Body) < 1 {
		t.Error("stream/lambda-heavy construct should emit at least one ir.RawStmt/RawExpr")
	}
}

func TestLowerDeterministic(t *testing.T) {
	build := func() *javamodel.Module {
		return &javamodel.Module{
			FileName: "App.java",
			Imports: []*javamodel.Node{
				{Type: javamodel.NodeImport, Name: "java.util.List"},
				{Type: javamodel.NodeImport, Name: "java.io.IOException"},
				{Type: javamodel.NodeImport, Name: "java.util.Map"},
				{Type: javamodel.NodeImport, Name: "java.time.Instant"},
			},
			Types: []*javamodel.Node{{Type: javamodel.NodeClass, Name: "App"}},
		}
	}

	a, err := NewLowerer().Lower(build())
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewLowerer().Lower(build())
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Imports) != len(b.Imports) {
		t.Fatalf("import count differs: %d vs %d", len(a.Imports), len(b.Imports))
	}
	for i := range a.Imports {
		if a.Imports[i].Path != b.Imports[i].Path {
			t.Errorf("import[%d] order differs: %q vs %q", i, a.Imports[i].Path, b.Imports[i].Path)
		}
	}
}
