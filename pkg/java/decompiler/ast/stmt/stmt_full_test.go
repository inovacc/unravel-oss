package stmt

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// helpers — minimal concrete implementations of ast.Expression / ast.LValue

type mockExpr struct {
	s  string
	jt types.JavaType
}

func (m *mockExpr) Type() types.JavaType       { return m.jt }
func (m *mockExpr) Precedence() ast.Precedence { return ast.PrecHighest }
func (m *mockExpr) IsSimple() bool             { return true }
func (m *mockExpr) Children() []ast.Expression { return nil }
func (m *mockExpr) String() string             { return m.s }

type mockLValue struct {
	mockExpr
}

func (m *mockLValue) LValueName() string { return m.s }

func expr(s string) ast.Expression { return &mockExpr{s: s, jt: types.TypeInt} }
func lval(s string) ast.LValue     { return &mockLValue{mockExpr{s: s, jt: types.TypeInt}} }

// lvalWithType creates an LValue whose Type() returns the given JavaType (needed by StructuredForEach).
func lvalWithType(s string, jt types.JavaType) ast.LValue {
	return &mockLValue{mockExpr{s: s, jt: jt}}
}

// ---------------------------------------------------------------------------
// basic.go
// ---------------------------------------------------------------------------

func TestNop(t *testing.T) {
	n := NewNop()
	if n.Kind() != KindNop {
		t.Errorf("kind: got %d want %d", n.Kind(), KindNop)
	}
	if len(n.Children()) != 0 {
		t.Error("expected nil children")
	}
	if len(n.Expressions()) != 0 {
		t.Error("expected nil expressions")
	}
	if n.String() != "nop" {
		t.Errorf("string: %q", n.String())
	}
}

func TestAssignmentStatement(t *testing.T) {
	t.Run("kind", func(t *testing.T) {
		a := NewAssignment(lval("x"), expr("1"))
		if a.Kind() != KindAssignment {
			t.Errorf("kind %d", a.Kind())
		}
	})
	t.Run("children_nil", func(t *testing.T) {
		a := NewAssignment(lval("x"), expr("1"))
		if len(a.Children()) != 0 {
			t.Error("expected no children")
		}
	})
	t.Run("expressions", func(t *testing.T) {
		a := NewAssignment(lval("x"), expr("42"))
		exprs := a.Expressions()
		if len(exprs) != 2 {
			t.Fatalf("expected 2 expressions, got %d", len(exprs))
		}
	})
	t.Run("string", func(t *testing.T) {
		a := NewAssignment(lval("x"), expr("42"))
		got := a.String()
		if got != "x = 42;" {
			t.Errorf("string: %q", got)
		}
	})
}

func TestExpressionStatement(t *testing.T) {
	e := NewExpressionStatement(expr("foo()"))
	if e.Kind() != KindExpression {
		t.Errorf("kind %d", e.Kind())
	}
	if len(e.Children()) != 0 {
		t.Error("expected no children")
	}
	exprs := e.Expressions()
	if len(exprs) != 1 {
		t.Fatalf("expected 1 expression, got %d", len(exprs))
	}
	if e.String() != "foo();" {
		t.Errorf("string: %q", e.String())
	}
}

func TestReturnStatement(t *testing.T) {
	r := NewReturn(expr("x"))
	if r.Kind() != KindReturn {
		t.Errorf("kind %d", r.Kind())
	}
	if len(r.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(r.Expressions()) != 1 {
		t.Error("expected 1 expression")
	}
	if r.String() != "return x;" {
		t.Errorf("string: %q", r.String())
	}
}

func TestReturnVoidStatement(t *testing.T) {
	r := NewReturnVoid()
	if r.Kind() != KindReturnVoid {
		t.Errorf("kind %d", r.Kind())
	}
	if len(r.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(r.Expressions()) != 0 {
		t.Error("expected no expressions")
	}
	if r.String() != "return;" {
		t.Errorf("string: %q", r.String())
	}
}

func TestThrowStatement(t *testing.T) {
	th := NewThrow(expr("ex"))
	if th.Kind() != KindThrow {
		t.Errorf("kind %d", th.Kind())
	}
	if len(th.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(th.Expressions()) != 1 {
		t.Error("expected 1 expression")
	}
	if th.String() != "throw ex;" {
		t.Errorf("string: %q", th.String())
	}
}

// ---------------------------------------------------------------------------
// control.go
// ---------------------------------------------------------------------------

func TestGotoStatement(t *testing.T) {
	g := NewGoto(42)
	if g.Kind() != KindGoto {
		t.Errorf("kind %d", g.Kind())
	}
	if len(g.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(g.Expressions()) != 0 {
		t.Error("expected no expressions")
	}
	if g.String() != "goto 42;" {
		t.Errorf("string: %q", g.String())
	}
}

func TestIfStatement(t *testing.T) {
	i := NewIf(expr("x > 0"), 100)
	if i.Kind() != KindIf {
		t.Errorf("kind %d", i.Kind())
	}
	if len(i.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(i.Expressions()) != 1 {
		t.Error("expected 1 expression")
	}
	if i.String() != "if (x > 0) goto 100;" {
		t.Errorf("string: %q", i.String())
	}
}

func TestSwitchStatement(t *testing.T) {
	t.Run("no_cases", func(t *testing.T) {
		s := NewSwitch(expr("x"), nil)
		if s.Kind() != KindSwitch {
			t.Errorf("kind %d", s.Kind())
		}
		if len(s.Children()) != 0 {
			t.Error("expected no children")
		}
		if len(s.Expressions()) != 1 {
			t.Error("expected 1 expression")
		}
		got := s.String()
		if !strings.Contains(got, "switch (x)") {
			t.Errorf("string missing switch: %q", got)
		}
	})
	t.Run("with_default", func(t *testing.T) {
		cases := []SwitchCase{
			{Values: nil, TargetOffset: 10, IsDefault: true},
		}
		s := NewSwitch(expr("y"), cases)
		got := s.String()
		if !strings.Contains(got, "default: goto 10;") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_values", func(t *testing.T) {
		cases := []SwitchCase{
			{Values: []int32{1, 2}, TargetOffset: 20, IsDefault: false},
		}
		s := NewSwitch(expr("z"), cases)
		got := s.String()
		if !strings.Contains(got, "case 1: goto 20;") {
			t.Errorf("string missing case 1: %q", got)
		}
		if !strings.Contains(got, "case 2: goto 20;") {
			t.Errorf("string missing case 2: %q", got)
		}
	})
}

func TestTryStatement(t *testing.T) {
	tr := NewTry(7)
	if tr.Kind() != KindTry {
		t.Errorf("kind %d", tr.Kind())
	}
	if len(tr.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(tr.Expressions()) != 0 {
		t.Error("expected no expressions")
	}
	if tr.String() != "try_7 {" {
		t.Errorf("string: %q", tr.String())
	}
}

func TestCatchStatement(t *testing.T) {
	t.Run("with_type", func(t *testing.T) {
		exType := types.NewRefType("java.lang.Exception")
		c := NewCatch(3, exType, lval("e"))
		if c.Kind() != KindCatch {
			t.Errorf("kind %d", c.Kind())
		}
		if len(c.Children()) != 0 {
			t.Error("expected no children")
		}
		exprs := c.Expressions()
		if len(exprs) != 1 {
			t.Fatalf("expected 1 expression, got %d", len(exprs))
		}
		got := c.String()
		if !strings.Contains(got, "catch") || !strings.Contains(got, "Exception") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("finally_no_type", func(t *testing.T) {
		c := NewCatch(3, nil, nil)
		if c.Kind() != KindCatch {
			t.Errorf("kind %d", c.Kind())
		}
		exprs := c.Expressions()
		if len(exprs) != 0 {
			t.Error("expected no expressions for nil ExceptionVar")
		}
		got := c.String()
		if !strings.Contains(got, "finally") {
			t.Errorf("string: %q", got)
		}
	})
}

func TestMonitorEnterStatement(t *testing.T) {
	m := NewMonitorEnter(expr("lock"))
	if m.Kind() != KindMonitorEnter {
		t.Errorf("kind %d", m.Kind())
	}
	if len(m.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(m.Expressions()) != 1 {
		t.Error("expected 1 expression")
	}
	if m.String() != "monitorenter(lock);" {
		t.Errorf("string: %q", m.String())
	}
}

func TestMonitorExitStatement(t *testing.T) {
	m := NewMonitorExit(expr("lock"))
	if m.Kind() != KindMonitorExit {
		t.Errorf("kind %d", m.Kind())
	}
	if len(m.Children()) != 0 {
		t.Error("expected no children")
	}
	if len(m.Expressions()) != 1 {
		t.Error("expected 1 expression")
	}
	if m.String() != "monitorexit(lock);" {
		t.Errorf("string: %q", m.String())
	}
}

func TestCompoundStatement(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		c := NewCompound()
		if c.Kind() != KindCompound {
			t.Errorf("kind %d", c.Kind())
		}
		if len(c.Children()) != 0 {
			t.Error("expected no children")
		}
		if len(c.Expressions()) != 0 {
			t.Error("expected no expressions")
		}
		if c.String() != "" {
			t.Errorf("string: %q", c.String())
		}
	})
	t.Run("two_stmts", func(t *testing.T) {
		c := NewCompound(NewNop(), NewReturnVoid())
		if len(c.Children()) != 2 {
			t.Errorf("expected 2 children, got %d", len(c.Children()))
		}
		got := c.String()
		if !strings.Contains(got, "nop") || !strings.Contains(got, "return;") {
			t.Errorf("string: %q", got)
		}
	})
}

func TestBlock(t *testing.T) {
	t.Run("no_label", func(t *testing.T) {
		b := NewBlock(NewNop())
		if b.Kind() != KindBlock {
			t.Errorf("kind %d", b.Kind())
		}
		if len(b.Children()) != 1 {
			t.Errorf("expected 1 child, got %d", len(b.Children()))
		}
		if len(b.Expressions()) != 0 {
			t.Error("expected no expressions")
		}
		got := b.String()
		if !strings.Contains(got, "nop") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_label", func(t *testing.T) {
		b := NewBlock(NewReturnVoid())
		b.Label = "outer"
		got := b.String()
		if !strings.HasPrefix(got, "outer: ") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("empty_block", func(t *testing.T) {
		b := NewBlock()
		got := b.String()
		if got != "{ }" {
			t.Errorf("string: %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// structured.go
// ---------------------------------------------------------------------------

func TestStructuredIf(t *testing.T) {
	t.Run("no_else", func(t *testing.T) {
		s := NewStructuredIf(expr("x > 0"), NewNop(), nil)
		if s.Kind() != KindStructuredIf {
			t.Errorf("kind %d", s.Kind())
		}
		ch := s.Children()
		if len(ch) != 1 {
			t.Errorf("expected 1 child, got %d", len(ch))
		}
		if len(s.Expressions()) != 1 {
			t.Error("expected 1 expression")
		}
		got := s.String()
		if !strings.Contains(got, "if (x > 0)") {
			t.Errorf("string: %q", got)
		}
		if strings.Contains(got, "else") {
			t.Errorf("should not contain else: %q", got)
		}
	})
	t.Run("with_else", func(t *testing.T) {
		s := NewStructuredIf(expr("flag"), NewNop(), NewReturnVoid())
		ch := s.Children()
		if len(ch) != 2 {
			t.Errorf("expected 2 children, got %d", len(ch))
		}
		got := s.String()
		if !strings.Contains(got, "else") {
			t.Errorf("string missing else: %q", got)
		}
	})
}

func TestStructuredWhile(t *testing.T) {
	t.Run("no_label", func(t *testing.T) {
		s := NewStructuredWhile(expr("i < 10"), NewNop())
		if s.Kind() != KindStructuredWhile {
			t.Errorf("kind %d", s.Kind())
		}
		if len(s.Children()) != 1 {
			t.Error("expected 1 child")
		}
		if len(s.Expressions()) != 1 {
			t.Error("expected 1 expression")
		}
		got := s.String()
		if !strings.Contains(got, "while (i < 10)") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_label", func(t *testing.T) {
		s := NewStructuredWhile(expr("true"), NewNop())
		s.Label = "loop1"
		got := s.String()
		if !strings.HasPrefix(got, "loop1: ") {
			t.Errorf("string: %q", got)
		}
	})
}

func TestStructuredDoWhile(t *testing.T) {
	t.Run("no_label", func(t *testing.T) {
		s := NewStructuredDoWhile(expr("i > 0"), NewNop())
		if s.Kind() != KindStructuredDoWhile {
			t.Errorf("kind %d", s.Kind())
		}
		if len(s.Children()) != 1 {
			t.Error("expected 1 child")
		}
		if len(s.Expressions()) != 1 {
			t.Error("expected 1 expression")
		}
		got := s.String()
		if !strings.Contains(got, "do") || !strings.Contains(got, "while (i > 0)") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_label", func(t *testing.T) {
		s := NewStructuredDoWhile(expr("true"), NewNop())
		s.Label = "myloop"
		got := s.String()
		if !strings.HasPrefix(got, "myloop: ") {
			t.Errorf("string: %q", got)
		}
	})
}

func TestStructuredFor(t *testing.T) {
	t.Run("all_nil", func(t *testing.T) {
		s := NewStructuredFor(nil, nil, nil, NewNop())
		if s.Kind() != KindStructuredFor {
			t.Errorf("kind %d", s.Kind())
		}
		ch := s.Children()
		// only body
		if len(ch) != 1 {
			t.Errorf("expected 1 child, got %d", len(ch))
		}
		exprs := s.Expressions()
		if len(exprs) != 0 {
			t.Error("expected 0 expressions when cond is nil")
		}
		got := s.String()
		if !strings.Contains(got, "for (") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("full", func(t *testing.T) {
		init_ := NewExpressionStatement(expr("i=0"))
		update := NewExpressionStatement(expr("i++"))
		s := NewStructuredFor(init_, expr("i<10"), update, NewNop())
		ch := s.Children()
		// init + body + update
		if len(ch) != 3 {
			t.Errorf("expected 3 children, got %d", len(ch))
		}
		exprs := s.Expressions()
		if len(exprs) != 1 {
			t.Error("expected 1 expression")
		}
		got := s.String()
		if !strings.Contains(got, "i=0") {
			t.Errorf("string missing init: %q", got)
		}
		if !strings.Contains(got, "i<10") {
			t.Errorf("string missing cond: %q", got)
		}
		if !strings.Contains(got, "i++") {
			t.Errorf("string missing update: %q", got)
		}
	})
	t.Run("with_label", func(t *testing.T) {
		s := NewStructuredFor(nil, nil, nil, NewNop())
		s.Label = "outer"
		got := s.String()
		if !strings.HasPrefix(got, "outer: ") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("init_only", func(t *testing.T) {
		init_ := NewExpressionStatement(expr("i=0"))
		s := NewStructuredFor(init_, nil, nil, NewNop())
		ch := s.Children()
		// init + body
		if len(ch) != 2 {
			t.Errorf("expected 2 children (init+body), got %d", len(ch))
		}
	})
	t.Run("update_only", func(t *testing.T) {
		update := NewExpressionStatement(expr("i++"))
		s := NewStructuredFor(nil, nil, update, NewNop())
		ch := s.Children()
		// body + update
		if len(ch) != 2 {
			t.Errorf("expected 2 children (body+update), got %d", len(ch))
		}
	})
}

func TestStructuredForEach(t *testing.T) {
	elemType := types.NewRefType("java.lang.String")
	v := lvalWithType("s", elemType)
	s := NewStructuredForEach(v, expr("list"), NewNop())
	if s.Kind() != KindStructuredForEach {
		t.Errorf("kind %d", s.Kind())
	}
	if len(s.Children()) != 1 {
		t.Error("expected 1 child")
	}
	exprs := s.Expressions()
	if len(exprs) != 2 {
		t.Fatalf("expected 2 expressions, got %d", len(exprs))
	}
	got := s.String()
	if !strings.Contains(got, "for (") || !strings.Contains(got, "list") {
		t.Errorf("string: %q", got)
	}
	t.Run("with_label", func(t *testing.T) {
		s2 := NewStructuredForEach(v, expr("col"), NewNop())
		s2.Label = "each"
		got2 := s2.String()
		if !strings.HasPrefix(got2, "each: ") {
			t.Errorf("string: %q", got2)
		}
	})
}

func TestStructuredSwitch(t *testing.T) {
	t.Run("empty_cases", func(t *testing.T) {
		s := NewStructuredSwitch(expr("x"), nil)
		if s.Kind() != KindStructuredSwitch {
			t.Errorf("kind %d", s.Kind())
		}
		if len(s.Children()) != 0 {
			t.Error("expected no children")
		}
		if len(s.Expressions()) != 1 {
			t.Error("expected 1 expression")
		}
		got := s.String()
		if !strings.Contains(got, "switch (x)") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("default_case_nil_body", func(t *testing.T) {
		cases := []StructuredCase{
			{IsDefault: true, Body: nil},
		}
		s := NewStructuredSwitch(expr("y"), cases)
		// body is nil — Children must skip it
		if len(s.Children()) != 0 {
			t.Error("expected no children for nil body")
		}
		got := s.String()
		if !strings.Contains(got, "default:") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("value_case_with_body", func(t *testing.T) {
		cases := []StructuredCase{
			{Values: []int32{1, 2}, IsDefault: false, Body: NewNop()},
		}
		s := NewStructuredSwitch(expr("z"), cases)
		if len(s.Children()) != 1 {
			t.Errorf("expected 1 child, got %d", len(s.Children()))
		}
		got := s.String()
		if !strings.Contains(got, "case 1:") || !strings.Contains(got, "case 2:") {
			t.Errorf("string: %q", got)
		}
	})
}

func TestStructuredTry(t *testing.T) {
	t.Run("body_only", func(t *testing.T) {
		s := NewStructuredTry(NewNop(), nil, nil)
		if s.Kind() != KindStructuredTry {
			t.Errorf("kind %d", s.Kind())
		}
		if len(s.Expressions()) != 0 {
			t.Error("expected no expressions")
		}
		ch := s.Children()
		if len(ch) != 1 {
			t.Errorf("expected 1 child, got %d", len(ch))
		}
		got := s.String()
		if !strings.HasPrefix(got, "try") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_catch_typed", func(t *testing.T) {
		exType := types.NewRefType("java.io.IOException")
		catches := []CatchClause{
			{ExceptionType: exType, ExceptionVar: lval("ex"), Body: NewNop()},
		}
		s := NewStructuredTry(NewNop(), catches, nil)
		ch := s.Children()
		// body + catch body
		if len(ch) != 2 {
			t.Errorf("expected 2 children, got %d", len(ch))
		}
		got := s.String()
		if !strings.Contains(got, "catch") || !strings.Contains(got, "IOException") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_catch_untyped", func(t *testing.T) {
		catches := []CatchClause{
			{ExceptionType: nil, ExceptionVar: lval("ex"), Body: NewNop()},
		}
		s := NewStructuredTry(NewNop(), catches, nil)
		got := s.String()
		if !strings.Contains(got, "catch") {
			t.Errorf("string: %q", got)
		}
	})
	t.Run("with_finally", func(t *testing.T) {
		s := NewStructuredTry(NewNop(), nil, NewReturnVoid())
		ch := s.Children()
		// body + finally
		if len(ch) != 2 {
			t.Errorf("expected 2 children, got %d", len(ch))
		}
		got := s.String()
		if !strings.Contains(got, "finally") {
			t.Errorf("string: %q", got)
		}
	})
}

func TestStructuredSynchronized(t *testing.T) {
	s := NewStructuredSynchronized(expr("lock"), NewNop())
	if s.Kind() != KindStructuredSynchronized {
		t.Errorf("kind %d", s.Kind())
	}
	if len(s.Children()) != 1 {
		t.Error("expected 1 child")
	}
	if len(s.Expressions()) != 1 {
		t.Error("expected 1 expression")
	}
	got := s.String()
	if !strings.Contains(got, "synchronized (lock)") {
		t.Errorf("string: %q", got)
	}
}

func TestBreakStatement(t *testing.T) {
	t.Run("unlabeled", func(t *testing.T) {
		b := NewBreak("")
		if b.Kind() != KindBreak {
			t.Errorf("kind %d", b.Kind())
		}
		if len(b.Children()) != 0 {
			t.Error("expected no children")
		}
		if len(b.Expressions()) != 0 {
			t.Error("expected no expressions")
		}
		if b.String() != "break;" {
			t.Errorf("string: %q", b.String())
		}
	})
	t.Run("labeled", func(t *testing.T) {
		b := NewBreak("outer")
		if b.String() != "break outer;" {
			t.Errorf("string: %q", b.String())
		}
	})
}

func TestContinueStatement(t *testing.T) {
	t.Run("unlabeled", func(t *testing.T) {
		c := NewContinue("")
		if c.Kind() != KindContinue {
			t.Errorf("kind %d", c.Kind())
		}
		if len(c.Children()) != 0 {
			t.Error("expected no children")
		}
		if len(c.Expressions()) != 0 {
			t.Error("expected no expressions")
		}
		if c.String() != "continue;" {
			t.Errorf("string: %q", c.String())
		}
	})
	t.Run("labeled", func(t *testing.T) {
		c := NewContinue("loop")
		if c.String() != "continue loop;" {
			t.Errorf("string: %q", c.String())
		}
	})
}

// ---------------------------------------------------------------------------
// statement.go — StmtKind constants
// ---------------------------------------------------------------------------

func TestStmtKindValues(t *testing.T) {
	// Ensure all constants are distinct and in expected order.
	kinds := []struct {
		name string
		val  StmtKind
	}{
		{"KindNop", KindNop},
		{"KindAssignment", KindAssignment},
		{"KindExpression", KindExpression},
		{"KindReturn", KindReturn},
		{"KindReturnVoid", KindReturnVoid},
		{"KindThrow", KindThrow},
		{"KindIf", KindIf},
		{"KindGoto", KindGoto},
		{"KindSwitch", KindSwitch},
		{"KindTry", KindTry},
		{"KindCatch", KindCatch},
		{"KindBlock", KindBlock},
		{"KindMonitorEnter", KindMonitorEnter},
		{"KindMonitorExit", KindMonitorExit},
		{"KindCompound", KindCompound},
		{"KindLabeled", KindLabeled},
		{"KindStructuredIf", KindStructuredIf},
		{"KindStructuredWhile", KindStructuredWhile},
		{"KindStructuredDoWhile", KindStructuredDoWhile},
		{"KindStructuredFor", KindStructuredFor},
		{"KindStructuredForEach", KindStructuredForEach},
		{"KindStructuredSwitch", KindStructuredSwitch},
		{"KindStructuredTry", KindStructuredTry},
		{"KindStructuredSynchronized", KindStructuredSynchronized},
		{"KindBreak", KindBreak},
		{"KindContinue", KindContinue},
	}
	seen := make(map[StmtKind]string)
	for _, k := range kinds {
		if prev, dup := seen[k.val]; dup {
			t.Errorf("duplicate StmtKind value %d: %s and %s", k.val, prev, k.name)
		}
		seen[k.val] = k.name
	}
	if len(seen) != len(kinds) {
		t.Errorf("expected %d unique kinds, got %d", len(kinds), len(seen))
	}
}

// ---------------------------------------------------------------------------
// Interface conformance — every Statement implements the Statement interface.
// ---------------------------------------------------------------------------

func TestStatementInterfaceConformance(t *testing.T) {
	exType := types.NewRefType("java.lang.Exception")
	body := NewNop()
	stmts := []Statement{
		NewNop(),
		NewAssignment(lval("x"), expr("1")),
		NewExpressionStatement(expr("f()")),
		NewReturn(expr("v")),
		NewReturnVoid(),
		NewThrow(expr("ex")),
		NewGoto(0),
		NewIf(expr("c"), 0),
		NewSwitch(expr("s"), nil),
		NewTry(0),
		NewCatch(0, exType, lval("e")),
		NewCatch(0, nil, nil),
		NewMonitorEnter(expr("o")),
		NewMonitorExit(expr("o")),
		NewCompound(NewNop()),
		NewBlock(NewNop()),
		NewStructuredIf(expr("c"), body, nil),
		NewStructuredIf(expr("c"), body, NewNop()),
		NewStructuredWhile(expr("c"), body),
		NewStructuredDoWhile(expr("c"), body),
		NewStructuredFor(nil, nil, nil, body),
		NewStructuredForEach(lvalWithType("x", types.TypeInt), expr("arr"), body),
		NewStructuredSwitch(expr("x"), nil),
		NewStructuredTry(body, nil, nil),
		NewStructuredSynchronized(expr("l"), body),
		NewBreak(""),
		NewBreak("L"),
		NewContinue(""),
		NewContinue("L"),
	}
	for _, s := range stmts {
		_ = s.Kind()
		_ = s.Children()
		_ = s.Expressions()
		_ = s.String()
	}
}
