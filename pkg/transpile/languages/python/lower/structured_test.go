package lower

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	pyparser "github.com/inovacc/unravel-oss/pkg/transpile/languages/python/parser"
)

// findFunc returns the first FuncDecl with the given name in the module.
func findFunc(t *testing.T, m *ir.Module, name string) *ir.FuncDecl {
	t.Helper()

	for _, d := range m.Decls {
		if fn, ok := d.(*ir.FuncDecl); ok && fn.Name == name {
			return fn
		}
	}

	t.Fatalf("func %q not found in module (decls=%d)", name, len(m.Decls))

	return nil
}

func lowerSrc(t *testing.T, src string) *ir.Module {
	t.Helper()

	mod, err := pyparser.New().ParseFile("sample.py", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	return irMod
}

func TestStructuredIf(t *testing.T) {
	src := `
def check(x):
    if x is None:
        return "none"
    else:
        return "some"
`
	m := lowerSrc(t, src)
	fn := findFunc(t, m, "Check")

	if len(fn.Body) == 0 {
		t.Fatalf("function body empty")
	}

	ifs, ok := fn.Body[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected *ir.IfStmt, got %T (%+v)", fn.Body[0], fn.Body[0])
	}

	if len(ifs.Then) == 0 {
		t.Fatalf("if Then branch is empty (not recursed)")
	}

	if _, ok := ifs.Then[0].(*ir.ReturnStmt); !ok {
		t.Fatalf("expected ReturnStmt in Then, got %T", ifs.Then[0])
	}

	if len(ifs.Else) == 0 {
		t.Fatalf("else branch not captured")
	}

	if re, ok := ifs.Cond.(*ir.RawExpr); !ok || re.Text == "" {
		t.Fatalf("if condition not captured: %+v", ifs.Cond)
	} else if re.Text == "xisNone" {
		t.Fatalf("condition lost whitespace/normalization: %q", re.Text)
	}
}

func TestStructuredForRange(t *testing.T) {
	src := `
def total(items):
    s = 0
    for it in items:
        s = s + it
    return s
`
	fn := findFunc(t, lowerSrc(t, src), "Total")

	var found bool

	for _, n := range fn.Body {
		if rng, ok := n.(*ir.RangeStmt); ok {
			found = true

			if len(rng.Body) == 0 {
				t.Fatalf("for-loop body not recursed")
			}
		}
	}

	if !found {
		t.Fatalf("for-loop did not lower to *ir.RangeStmt; body=%+v", fn.Body)
	}
}

func TestStructuredWhile(t *testing.T) {
	src := `
def countdown(n):
    while n > 0:
        n = n - 1
    return n
`
	fn := findFunc(t, lowerSrc(t, src), "Countdown")

	var found bool

	for _, n := range fn.Body {
		if f, ok := n.(*ir.ForStmt); ok {
			found = true

			if f.Cond == nil {
				t.Fatalf("while condition not captured")
			}

			if len(f.Body) == 0 {
				t.Fatalf("while body not recursed")
			}
		}
	}

	if !found {
		t.Fatalf("while did not lower to *ir.ForStmt; body=%+v", fn.Body)
	}
}

func TestConditionNormalizedToGo(t *testing.T) {
	src := `
def f(x):
    if x is not None and x or not x:
        return 1
    return 0
`
	fn := findFunc(t, lowerSrc(t, src), "F")

	ifs, ok := fn.Body[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected IfStmt, got %T", fn.Body[0])
	}

	re := ifs.Cond.(*ir.RawExpr)
	for _, banned := range []string{" is not ", " is ", " and ", " or ", "not "} {
		if containsToken(re.Text, banned) {
			t.Errorf("Python operator %q not normalized in %q", banned, re.Text)
		}
	}
}

func TestSelfRewrittenToReceiver(t *testing.T) {
	src := `
class Box:
    def total(self):
        return self.amount + self.tax
`
	fn := findFunc(t, lowerSrc(t, src), "Total")

	ret := fn.Body[0].(*ir.ReturnStmt)
	txt := ret.Values[0].(*ir.RawExpr).Text

	if containsToken(txt, "self") {
		t.Errorf("self not rewritten to receiver: %q", txt)
	}

	if fn.Receiver == nil || !containsToken(txt, fn.Receiver.Name+".amount") {
		t.Errorf("expected receiver-qualified access, got %q", txt)
	}
}

func TestRaiseLoweredToPanic(t *testing.T) {
	src := `
def boom(x):
    if x:
        raise ValueError("bad value")
    return x
`
	fn := findFunc(t, lowerSrc(t, src), "Boom")

	ifs := fn.Body[0].(*ir.IfStmt)
	rs, ok := ifs.Then[0].(*ir.RawStmt)

	if !ok {
		t.Fatalf("expected RawStmt in then, got %T", ifs.Then[0])
	}

	if rs.Text != `panic("bad value")` {
		t.Errorf("raise not lowered to panic: %q", rs.Text)
	}
}

func TestBareAssignBecomesShortDecl(t *testing.T) {
	src := `
def f():
    total = compute()
    return total
`
	fn := findFunc(t, lowerSrc(t, src), "F")

	var got string

	for _, n := range fn.Body {
		if rs, ok := n.(*ir.RawStmt); ok && containsToken(rs.Text, "total") {
			got = rs.Text
		}
	}

	if got != "" && !containsToken(got, "total := ") {
		t.Errorf("bare local assignment not converted to :=, got %q", got)
	}
}

func TestFStringToSprintf(t *testing.T) {
	src := `
def greet(name, n):
    return f"Hi {name}, you have {n} msgs and x and y"
`
	fn := findFunc(t, lowerSrc(t, src), "Greet")
	txt := fn.Body[0].(*ir.ReturnStmt).Values[0].(*ir.RawExpr).Text

	if !containsToken(txt, `fmt.Sprintf("Hi %v, you have %v msgs and x and y"`) {
		t.Errorf("f-string not converted: %q", txt)
	}

	if !containsToken(txt, "name") || !containsToken(txt, "n)") {
		t.Errorf("f-string args missing: %q", txt)
	}
}

func TestStringLiteralNotMangled(t *testing.T) {
	src := `
def f(a):
    if a is None:
        return "cats and dogs is fine"
    return "x"
`
	fn := findFunc(t, lowerSrc(t, src), "F")
	ifs := fn.Body[0].(*ir.IfStmt)
	ret := ifs.Then[0].(*ir.ReturnStmt).Values[0].(*ir.RawExpr).Text

	if ret != `"cats and dogs is fine"` {
		t.Errorf("string literal corrupted by operator normalization: %q", ret)
	}

	if c := ifs.Cond.(*ir.RawExpr).Text; !containsToken(c, "== nil") {
		t.Errorf("condition outside literal should still normalize: %q", c)
	}
}

func TestMembershipToBooleanChain(t *testing.T) {
	src := `
def f(s):
    if s in (1, 2, 3):
        return 1
    return 0
`
	fn := findFunc(t, lowerSrc(t, src), "F")
	c := fn.Body[0].(*ir.IfStmt).Cond.(*ir.RawExpr).Text

	if c != "(s == 1 || s == 2 || s == 3)" {
		t.Errorf("membership not rewritten: %q", c)
	}
}

func TestKwargsCallToCompositeLiteral(t *testing.T) {
	src := `
def make(p):
    x = Item(name=p, qty=2)
    return x
`
	fn := findFunc(t, lowerSrc(t, src), "Make")

	var got string

	for _, n := range fn.Body {
		if rs, ok := n.(*ir.RawStmt); ok && containsToken(rs.Text, "Item") {
			got = rs.Text
		}
	}

	if !containsToken(got, "Item{Name: p, Qty: 2}") {
		t.Errorf("kwargs ctor not converted to composite literal: %q", got)
	}
}

func containsToken(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}

	return -1
}
