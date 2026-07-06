package lower

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	javaparser "github.com/inovacc/unravel-oss/pkg/transpile/languages/java/parser"
)

func lowerJava(t *testing.T, src string) *ir.Module {
	t.Helper()

	mod, err := javaparser.New().ParseFile("Sample.java", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	irMod, err := NewLowerer().Lower(mod)
	if err != nil {
		t.Fatalf("lower: %v", err)
	}

	return irMod
}

func findMethod(t *testing.T, m *ir.Module, name string) *ir.FuncDecl {
	t.Helper()

	for _, d := range m.Decls {
		switch v := d.(type) {
		case *ir.FuncDecl:
			if v.Name == name {
				return v
			}
		case *ir.TypeDecl:
			for _, fn := range v.Methods {
				if fn.Name == name {
					return fn
				}
			}
		}
	}

	t.Fatalf("method %q not found (decls=%d)", name, len(m.Decls))

	return nil
}

func TestJavaStructuredIfElse(t *testing.T) {
	src := `
public class Box {
    int amount;
    public String check() {
        if (this.amount == 0) {
            return "zero";
        } else {
            return "some";
        }
    }
}`
	fn := findMethod(t, lowerJava(t, src), "Check")

	if len(fn.Body) == 0 {
		t.Fatal("empty body")
	}

	ifs, ok := fn.Body[0].(*ir.IfStmt)
	if !ok {
		t.Fatalf("expected *ir.IfStmt, got %T", fn.Body[0])
	}

	if len(ifs.Then) == 0 || len(ifs.Else) == 0 {
		t.Fatalf("then/else not recursed: then=%d else=%d", len(ifs.Then), len(ifs.Else))
	}

	cond := ifs.Cond.(*ir.RawExpr).Text
	if cond == "" || cond == "this.amount==0" {
		t.Fatalf("condition lost spacing/structure: %q", cond)
	}

	if fn.Receiver != nil && containsSub(cond, "this") {
		t.Errorf("`this` not rewritten to receiver: %q", cond)
	}
}

func TestJavaStructuredForEachAndWhile(t *testing.T) {
	src := `
public class L {
    java.util.List<Integer> items;
    public int total() {
        int s = 0;
        for (Integer it : this.items) {
            s = s + it;
        }
        while (s > 0) {
            s = s - 1;
        }
        return s;
    }
}`
	fn := findMethod(t, lowerJava(t, src), "Total")

	var sawRange, sawFor bool

	for _, n := range fn.Body {
		switch st := n.(type) {
		case *ir.RangeStmt:
			sawRange = true

			if st.Value != "it" || len(st.Body) == 0 {
				t.Errorf("for-each not structured: %+v", st)
			}
		case *ir.ForStmt:
			sawFor = true

			if st.Cond == nil || len(st.Body) == 0 {
				t.Errorf("while not structured: %+v", st)
			}
		}
	}

	if !sawRange {
		t.Errorf("for-each did not lower to *ir.RangeStmt; body=%+v", fn.Body)
	}

	if !sawFor {
		t.Errorf("while did not lower to *ir.ForStmt; body=%+v", fn.Body)
	}
}

func TestJavaNoFlattenedControlFlow(t *testing.T) {
	src := `
public class C {
    public void run(int x) {
        if (x > 0) { System.out.println(x); }
    }
}`
	fn := findMethod(t, lowerJava(t, src), "Run")
	for _, n := range fn.Body {
		if rs, ok := n.(*ir.RawStmt); ok && containsSub(rs.Comment, "Java if statement") {
			t.Fatalf("control flow still flattened to RawStmt: %q", rs.Text)
		}
	}
}

func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}

	return false
}
