package lower

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/ast"
)

func TestLower_CHeaderMapping(t *testing.T) {
	l := NewLowerer()

	tests := []struct {
		header  string
		wantPkg string
		system  bool
	}{
		// C standard library
		{"stdio.h", "fmt", true},
		{"stdio.h", "os", true},
		{"stdlib.h", "os", true},
		{"stdlib.h", "strconv", true},
		{"string.h", "strings", true},
		{"string.h", "bytes", true},
		{"ctype.h", "unicode", true},
		{"time.h", "time", true},
		{"errno.h", "errors", true},
		{"errno.h", "syscall", true},
		{"signal.h", "os/signal", true},
		{"signal.h", "os", true},

		// POSIX
		{"unistd.h", "os", true},
		{"unistd.h", "syscall", true},
		{"pthread.h", "sync", true},
		{"dirent.h", "os", true},
		{"fcntl.h", "os", true},
		{"sys/socket.h", "net", true},
		{"arpa/inet.h", "net", true},
		{"netinet/in.h", "net", true},
		{"sys/mman.h", "syscall", true},
		{"dlfcn.h", "plugin", true},
		{"sys/stat.h", "os", true},
		{"sys/types.h", "os", true},
	}

	for _, tt := range tests {
		t.Run(tt.header+"→"+tt.wantPkg, func(t *testing.T) {
			tu := &ast.TranslationUnit{
				FileName: "test.c",
				Includes: []*ast.Include{
					{Path: tt.header, System: tt.system},
				},
			}
			mod := l.Lower(tu)

			found := false

			for _, imp := range mod.Imports {
				if imp.Path == tt.wantPkg {
					found = true
				}
			}

			if !found {
				t.Errorf("expected import %q for header %q, got imports: %v",
					tt.wantPkg, tt.header, importPaths(mod.Imports))
			}
		})
	}
}

func TestLower_CHeaderNoImport(t *testing.T) {
	l := NewLowerer()

	// Headers that map to built-in types should not add imports
	headers := []string{"stdint.h", "stdbool.h", "stddef.h", "stdarg.h", "limits.h", "float.h"}

	for _, h := range headers {
		t.Run(h, func(t *testing.T) {
			tu := &ast.TranslationUnit{
				FileName: "test.c",
				Includes: []*ast.Include{
					{Path: h, System: true},
				},
			}
			mod := l.Lower(tu)

			if len(mod.Imports) != 0 {
				t.Errorf("expected 0 imports for %s, got %d: %v",
					h, len(mod.Imports), importPaths(mod.Imports))
			}
		})
	}
}

func TestLower_GotoStmt(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.c",
		Decls: []ast.Node{
			&ast.GotoStmt{Label: "cleanup"},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	gs, ok := mod.Decls[0].(*ir.GotoStmt)
	if !ok {
		t.Fatalf("expected *GotoStmt, got %T", mod.Decls[0])
	}

	if gs.Label != "cleanup" {
		t.Errorf("Label = %q, want %q", gs.Label, "cleanup")
	}
}

func TestLower_LabelStmt(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.c",
		Decls: []ast.Node{
			&ast.LabelStmt{Label: "cleanup"},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	ls, ok := mod.Decls[0].(*ir.LabelStmt)
	if !ok {
		t.Fatalf("expected *LabelStmt, got %T", mod.Decls[0])
	}

	if ls.Label != "cleanup" {
		t.Errorf("Label = %q, want %q", ls.Label, "cleanup")
	}
}

func TestLowerStmt_GotoStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.GotoStmt{Label: "error"})

	if len(stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(stmts))
	}

	gs, ok := stmts[0].(*ir.GotoStmt)
	if !ok {
		t.Fatalf("expected *GotoStmt, got %T", stmts[0])
	}

	if gs.Label != "error" {
		t.Errorf("Label = %q, want %q", gs.Label, "error")
	}
}

func TestLowerStmt_LabelStmt(t *testing.T) {
	l := NewLowerer()
	stmts := l.lowerStmt(&ast.LabelStmt{
		Label: "done",
		Stmt:  &ast.ReturnStmt{Value: &ast.Literal{Kind: "int", Value: "0"}},
	})

	if len(stmts) != 1 {
		t.Fatalf("expected 1 stmt, got %d", len(stmts))
	}

	ls, ok := stmts[0].(*ir.LabelStmt)
	if !ok {
		t.Fatalf("expected *LabelStmt, got %T", stmts[0])
	}

	if ls.Label != "done" {
		t.Errorf("Label = %q, want %q", ls.Label, "done")
	}

	if ls.Stmt == nil {
		t.Error("expected non-nil Stmt")
	}
}

func TestLower_ExternDecl(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.c",
		Decls: []ast.Node{
			&ast.ExternDecl{
				Var: &ast.Variable{
					Name: "global_count",
					Type: &ast.TypeRef{Name: "int"},
				},
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	vd, ok := mod.Decls[0].(*ir.VarDecl)
	if !ok {
		t.Fatalf("expected *VarDecl, got %T", mod.Decls[0])
	}

	if vd.Name != "global_count" {
		t.Errorf("Name = %q, want %q", vd.Name, "global_count")
	}
}

func TestLower_ExternCBlock(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.c",
		Decls: []ast.Node{
			&ast.ExternDecl{
				Linkage: "C",
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	raw, ok := mod.Decls[0].(*ir.RawStmt)
	if !ok {
		t.Fatalf("expected *RawStmt, got %T", mod.Decls[0])
	}

	if raw.Comment == "" {
		t.Error("expected comment about extern \"C\"")
	}
}

func TestLower_FuncPtrDecl(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.c",
		Decls: []ast.Node{
			&ast.FuncPtrDecl{
				Name:       "callback_t",
				ReturnType: &ast.TypeRef{Name: "int"},
				Params: []*ast.Parameter{
					{Name: "data", Type: &ast.TypeRef{Name: "void", Pointer: true}},
					{Name: "len", Type: &ast.TypeRef{Name: "int"}},
				},
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	td, ok := mod.Decls[0].(*ir.TypeDecl)
	if !ok {
		t.Fatalf("expected *TypeDecl, got %T", mod.Decls[0])
	}

	if td.Name != "callback_t" {
		t.Errorf("Name = %q, want %q", td.Name, "callback_t")
	}

	if td.Comment == "" {
		t.Error("expected comment about func type")
	}

	if len(td.Methods) != 1 {
		t.Fatalf("expected 1 method (signature), got %d", len(td.Methods))
	}

	fn := td.Methods[0]
	if len(fn.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(fn.Params))
	}

	if len(fn.Returns) != 1 {
		t.Errorf("expected 1 return, got %d", len(fn.Returns))
	}
}

func TestLower_BitField(t *testing.T) {
	l := NewLowerer()
	tu := &ast.TranslationUnit{
		FileName: "test.c",
		Decls: []ast.Node{
			&ast.BitField{
				Name:  "flags",
				Type:  &ast.TypeRef{Name: "unsigned int"},
				Width: 3,
			},
		},
	}

	mod := l.Lower(tu)

	if len(mod.Decls) != 1 {
		t.Fatalf("expected 1 decl, got %d", len(mod.Decls))
	}

	fd, ok := mod.Decls[0].(*ir.FieldDecl)
	if !ok {
		t.Fatalf("expected *FieldDecl, got %T", mod.Decls[0])
	}

	if fd.Name != "Flags" {
		t.Errorf("Name = %q, want %q", fd.Name, "Flags")
	}

	if fd.Comment == "" {
		t.Error("expected comment about bitfield width")
	}
}

func TestMapPrimitiveType_CTypes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ptrdiff_t", "int"},
		{"ssize_t", "int"},
		{"intptr_t", "int"},
		{"uintptr_t", "uintptr"},
		{"FILE", "*os.File"},
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

func TestKindUnion(t *testing.T) {
	if ir.KindUnion != "union" {
		t.Errorf("KindUnion = %q, want %q", ir.KindUnion, "union")
	}
}

func TestIRNodeTypes_CSpecific(t *testing.T) {
	// Verify C-specific IR node types satisfy ir.Node interface
	var (
		_ ir.Node = &ir.GotoStmt{Label: "cleanup"}
		_ ir.Node = &ir.LabelStmt{Label: "cleanup"}
	)
}

// importPaths returns the import paths from a slice of imports for error messages.
func importPaths(imports []*ir.Import) []string {
	var paths []string
	for _, imp := range imports {
		paths = append(paths, imp.Path)
	}

	return paths
}
