package patterns

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ---------------------------------------------------------------------------
// Test: simplifyAutobox — boxing (Integer.valueOf)
// ---------------------------------------------------------------------------

func TestSimplifyAutobox_IntegerValueOf(t *testing.T) {
	// Build: Integer.valueOf(42) — static invocation with one arg.
	innerLit := ast.NewIntLiteral(42)
	method := &ast.MethodRef{
		ClassName:  "java.lang.Integer",
		MethodName: "valueOf",
		Descriptor: "(I)Ljava/lang/Integer;",
		ReturnType: types.NewRefType("java.lang.Integer"),
	}

	inv := ast.NewStaticInvocation(method, []ast.Expression{innerLit})

	result, ok := simplifyAutobox(inv)
	if !ok {
		t.Fatal("expected simplifyAutobox to match Integer.valueOf")
	}

	// The result should be the inner literal, not the method call.
	lit, isLit := result.(*ast.Literal)
	if !isLit {
		t.Fatalf("expected *ast.Literal, got %T", result)
	}

	if lit.IntVal != 42 {
		t.Errorf("IntVal = %d, want 42", lit.IntVal)
	}
}

// ---------------------------------------------------------------------------
// Test: simplifyAutobox — boxing with internal class name (slash form)
// ---------------------------------------------------------------------------

func TestSimplifyAutobox_InternalName(t *testing.T) {
	innerLit := ast.NewIntLiteral(7)
	method := &ast.MethodRef{
		ClassName:  "java/lang/Integer",
		MethodName: "valueOf",
		Descriptor: "(I)Ljava/lang/Integer;",
		ReturnType: types.NewRefType("java.lang.Integer"),
	}

	inv := ast.NewStaticInvocation(method, []ast.Expression{innerLit})

	result, ok := simplifyAutobox(inv)
	if !ok {
		t.Fatal("expected simplifyAutobox to match java/lang/Integer.valueOf")
	}

	if result != innerLit {
		t.Error("expected the inner literal to be returned directly")
	}
}

// ---------------------------------------------------------------------------
// Test: simplifyAutobox — unboxing (x.intValue())
// ---------------------------------------------------------------------------

func TestSimplifyAutobox_IntValue(t *testing.T) {
	// Build: x.intValue() — virtual invocation on some object.
	xVar := ast.NewLocalVariable(1, types.NewRefType("java.lang.Integer"))
	method := &ast.MethodRef{
		ClassName:  "java.lang.Integer",
		MethodName: "intValue",
		Descriptor: "()I",
		ReturnType: types.TypeInt,
	}

	inv := ast.NewMethodInvocation(ast.InvokeVirtual, xVar, method, nil)

	result, ok := simplifyAutobox(inv)
	if !ok {
		t.Fatal("expected simplifyAutobox to match intValue()")
	}

	// Result should be the receiver object.
	if result != xVar {
		t.Errorf("expected receiver variable, got %T: %s", result, result)
	}
}

// ---------------------------------------------------------------------------
// Test: simplifyAutobox — unboxing booleanValue()
// ---------------------------------------------------------------------------

func TestSimplifyAutobox_BooleanValue(t *testing.T) {
	xVar := ast.NewLocalVariable(1, types.NewRefType("java.lang.Boolean"))
	method := &ast.MethodRef{
		ClassName:  "java.lang.Boolean",
		MethodName: "booleanValue",
		Descriptor: "()Z",
		ReturnType: types.TypeBoolean,
	}

	inv := ast.NewMethodInvocation(ast.InvokeVirtual, xVar, method, nil)

	result, ok := simplifyAutobox(inv)
	if !ok {
		t.Fatal("expected simplifyAutobox to match booleanValue()")
	}

	if result != xVar {
		t.Errorf("expected receiver variable, got %T", result)
	}
}

// ---------------------------------------------------------------------------
// Test: simplifyAutobox — non-matching call returns false
// ---------------------------------------------------------------------------

func TestSimplifyAutobox_NonMatch(t *testing.T) {
	// Regular method call should not match.
	method := &ast.MethodRef{
		ClassName:  "com.example.Foo",
		MethodName: "doStuff",
		Descriptor: "(I)V",
		ReturnType: types.TypeVoid,
	}

	inv := ast.NewStaticInvocation(method, []ast.Expression{ast.NewIntLiteral(1)})

	_, ok := simplifyAutobox(inv)
	if ok {
		t.Error("expected simplifyAutobox to NOT match doStuff()")
	}
}

// ---------------------------------------------------------------------------
// Test: simplifyAutobox — non-MethodInvocation returns false
// ---------------------------------------------------------------------------

func TestSimplifyAutobox_NonInvocation(t *testing.T) {
	lit := ast.NewIntLiteral(42)

	_, ok := simplifyAutobox(lit)
	if ok {
		t.Error("expected simplifyAutobox to NOT match a literal")
	}
}

// ---------------------------------------------------------------------------
// Test: collapseTernary — assignment pattern
// ---------------------------------------------------------------------------

func TestCollapseTernary_Assignment(t *testing.T) {
	// Build: if (cond) { x = 1; } else { x = 2; }
	xVar := ast.NewLocalVariable(1, types.TypeInt)
	cond := ast.NewBoolLiteral(true)
	thenVal := ast.NewIntLiteral(1)
	elseVal := ast.NewIntLiteral(2)

	thenStmt := stmt.NewBlock(stmt.NewAssignment(xVar, thenVal))
	elseStmt := stmt.NewBlock(stmt.NewAssignment(xVar, elseVal))

	ifStmt := stmt.NewStructuredIf(cond, thenStmt, elseStmt)

	result, count := collapseTernary([]stmt.Statement{ifStmt})

	if count != 1 {
		t.Fatalf("expected 1 ternary collapse, got %d", count)
	}

	if len(result) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result))
	}

	assign, ok := result[0].(*stmt.AssignmentStatement)
	if !ok {
		t.Fatalf("expected AssignmentStatement, got %T", result[0])
	}

	ternary, ok := assign.Value.(*ast.TernaryExpression)
	if !ok {
		t.Fatalf("expected TernaryExpression, got %T", assign.Value)
	}

	if ternary.TrueExpr.String() != "1" || ternary.FalseExpr.String() != "2" {
		t.Errorf("ternary = %s, want (true ? 1 : 2)", ternary)
	}
}

// ---------------------------------------------------------------------------
// Test: collapseTernary — return pattern
// ---------------------------------------------------------------------------

func TestCollapseTernary_Return(t *testing.T) {
	cond := ast.NewBoolLiteral(false)
	thenVal := ast.NewStringLiteral("yes")
	elseVal := ast.NewStringLiteral("no")

	thenStmt := stmt.NewReturn(thenVal)
	elseStmt := stmt.NewReturn(elseVal)

	ifStmt := stmt.NewStructuredIf(cond, thenStmt, elseStmt)

	result, count := collapseTernary([]stmt.Statement{ifStmt})

	if count != 1 {
		t.Fatalf("expected 1 collapse, got %d", count)
	}

	ret, ok := result[0].(*stmt.ReturnStatement)
	if !ok {
		t.Fatalf("expected ReturnStatement, got %T", result[0])
	}

	if _, ok := ret.Value.(*ast.TernaryExpression); !ok {
		t.Fatalf("expected TernaryExpression in return, got %T", ret.Value)
	}
}

// ---------------------------------------------------------------------------
// Test: collapseTernary — no match (no else branch)
// ---------------------------------------------------------------------------

func TestCollapseTernary_NoElse(t *testing.T) {
	cond := ast.NewBoolLiteral(true)
	thenStmt := stmt.NewBlock(stmt.NewReturn(ast.NewIntLiteral(1)))
	ifStmt := stmt.NewStructuredIf(cond, thenStmt, nil)

	result, count := collapseTernary([]stmt.Statement{ifStmt})

	if count != 0 {
		t.Errorf("expected 0 collapses for if-without-else, got %d", count)
	}

	if len(result) != 1 {
		t.Errorf("expected 1 statement passthrough, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// Test: collapseTernary — mixed targets (should NOT collapse)
// ---------------------------------------------------------------------------

func TestCollapseTernary_DifferentTargets(t *testing.T) {
	xVar := ast.NewLocalVariable(1, types.TypeInt)
	yVar := ast.NewLocalVariable(2, types.TypeInt)
	cond := ast.NewBoolLiteral(true)

	thenStmt := stmt.NewBlock(stmt.NewAssignment(xVar, ast.NewIntLiteral(1)))
	elseStmt := stmt.NewBlock(stmt.NewAssignment(yVar, ast.NewIntLiteral(2)))

	ifStmt := stmt.NewStructuredIf(cond, thenStmt, elseStmt)

	_, count := collapseTernary([]stmt.Statement{ifStmt})

	if count != 0 {
		t.Errorf("expected 0 collapses for different targets, got %d", count)
	}
}

// ---------------------------------------------------------------------------
// Test: Apply on empty statement list
// ---------------------------------------------------------------------------

func TestApply_NoOp(t *testing.T) {
	result, stats := Apply(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil input, got %d statements", len(result))
	}

	if stats.Total != 0 {
		t.Errorf("expected 0 total transforms, got %d", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// Test: Apply on empty slice
// ---------------------------------------------------------------------------

func TestApply_EmptySlice(t *testing.T) {
	result, stats := Apply([]stmt.Statement{})
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d statements", len(result))
	}

	if stats.Total != 0 {
		t.Errorf("expected 0 total transforms, got %d", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// Test: Apply preserves non-matching statements
// ---------------------------------------------------------------------------

func TestApply_Passthrough(t *testing.T) {
	s := stmt.NewReturn(ast.NewIntLiteral(42))
	result, stats := Apply([]stmt.Statement{s})

	if len(result) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(result))
	}

	if stats.Total != 0 {
		t.Errorf("expected 0 transforms for simple return, got %d", stats.Total)
	}
}

// ---------------------------------------------------------------------------
// Test: Apply with autobox inside a return statement
// ---------------------------------------------------------------------------

func TestApply_AutoboxInReturn(t *testing.T) {
	innerLit := ast.NewIntLiteral(99)
	method := &ast.MethodRef{
		ClassName:  "java.lang.Integer",
		MethodName: "valueOf",
		Descriptor: "(I)Ljava/lang/Integer;",
		ReturnType: types.NewRefType("java.lang.Integer"),
	}

	inv := ast.NewStaticInvocation(method, []ast.Expression{innerLit})
	s := stmt.NewReturn(inv)

	result, stats := Apply([]stmt.Statement{s})

	if stats.Autobox != 1 {
		t.Errorf("expected 1 autobox transform, got %d", stats.Autobox)
	}

	ret, ok := result[0].(*stmt.ReturnStatement)
	if !ok {
		t.Fatalf("expected ReturnStatement, got %T", result[0])
	}

	// The Integer.valueOf(99) should have been simplified to just 99.
	lit, ok := ret.Value.(*ast.Literal)
	if !ok {
		t.Fatalf("expected simplified Literal, got %T: %s", ret.Value, ret.Value)
	}

	if lit.IntVal != 99 {
		t.Errorf("IntVal = %d, want 99", lit.IntVal)
	}
}
