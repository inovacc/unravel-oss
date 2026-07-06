package writer

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// TestWriteBody_HoistsUndeclaredLocals pins the decompiler-parity fix for the
// undeclared-local defect: a method body that assigns a local (`var2 = 0;`) with
// no matching declaration produces uncompilable output. WriteBody hoists a
// `Type name;` declaration for every assigned local that is neither a parameter
// (already declared in the signature) nor declared inline (foreach/catch var).
func TestWriteBody_HoistsUndeclaredLocals(t *testing.T) {
	// int var2 = 0;  (slot 2 — a genuine local, must be hoisted)
	v2 := ast.NewLocalVariable(2, types.TypeInt)
	assignLocal := stmt.NewAssignment(v2, ast.NewIntLiteral(0))
	// var2 = 5;  (same local again — dedup: still one declaration)
	assignLocalAgain := stmt.NewAssignment(ast.NewLocalVariable(2, types.TypeInt), ast.NewIntLiteral(5))
	// var1 = 5;  (slot 1 is a parameter — must NOT be re-declared)
	assignParam := stmt.NewAssignment(ast.NewLocalVariable(1, types.TypeInt), ast.NewIntLiteral(5))
	// for (int var3 : ...) { }  (foreach var is inline-declared — must NOT be hoisted)
	foreach := stmt.NewStructuredForEach(ast.NewLocalVariable(3, types.TypeInt), ast.NewIntLiteral(0), stmt.NewNop())

	stmts := []stmt.Statement{assignLocal, assignLocalAgain, assignParam, foreach}
	paramSlots := map[int]bool{0: true, 1: true} // this + one param

	w := New()
	w.WriteBody(stmts, paramSlots)
	out := w.String()

	if !strings.Contains(out, "int var2;") {
		t.Errorf("expected hoisted declaration `int var2;`:\n%s", out)
	}
	if got := strings.Count(out, "int var2;"); got != 1 {
		t.Errorf("expected exactly one `int var2;` declaration (dedup), got %d:\n%s", got, out)
	}
	if strings.Contains(out, "int var1;") {
		t.Errorf("parameter var1 must not be re-declared:\n%s", out)
	}
	if strings.Contains(out, "int var3;") {
		t.Errorf("foreach variable var3 is inline-declared, must not be hoisted:\n%s", out)
	}
}

// TestCollectHoistedLocals_ObjectFallback verifies that a local with no inferred
// type is declared as Object rather than being skipped (which would leave it
// undeclared and uncompilable).
func TestCollectHoistedLocals_ObjectFallback(t *testing.T) {
	untyped := ast.NewLocalVariable(4, nil)
	stmts := []stmt.Statement{stmt.NewAssignment(untyped, ast.NewIntLiteral(1))}

	got := collectHoistedLocals(stmts, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 hoisted local, got %d", len(got))
	}
	if got[0].typeName != "Object" {
		t.Errorf("untyped local: got type %q, want Object", got[0].typeName)
	}
}
