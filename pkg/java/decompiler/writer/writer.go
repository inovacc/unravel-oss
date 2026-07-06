package writer

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// JavaWriter renders a statement tree as Java source code.
type JavaWriter struct {
	buf    strings.Builder
	indent int
	tab    string // indentation unit (default: "    ")
}

// New creates a new JavaWriter.
func New() *JavaWriter {
	return &JavaWriter{tab: "    "}
}

// String returns the accumulated Java source code.
func (w *JavaWriter) String() string {
	return w.buf.String()
}

// Reset clears the writer's buffer.
func (w *JavaWriter) Reset() {
	w.buf.Reset()
	w.indent = 0
}

// WriteStatements writes a list of statements as a method body.
func (w *JavaWriter) WriteStatements(stmts []stmt.Statement) {
	for _, s := range stmts {
		w.writeStatement(s)
	}
}

// hoistedLocal is a local variable that is assigned in a method body but never
// declared inline, so it needs a hoisted `Type name;` declaration.
type hoistedLocal struct {
	name     string
	typeName string
}

// WriteBody renders a method body, first emitting hoisted declarations for local
// variables that are assigned but never declared inline. Without this, the body
// emits bare `var2 = 0;` with no `int var2` in scope — output that does not
// compile (a top compile-readiness blocker vs CFR/procyon, which declare every
// local). paramSlots holds the JVM local slots occupied by `this` + the method
// parameters (already declared in the signature); those are never re-declared.
func (w *JavaWriter) WriteBody(stmts []stmt.Statement, paramSlots map[int]bool) {
	for _, d := range collectHoistedLocals(stmts, paramSlots) {
		w.writeLine(fmt.Sprintf("%s %s;", d.typeName, d.name))
	}

	w.WriteStatements(stmts)
}

// collectHoistedLocals walks the statement tree and returns, in first-assignment
// order, the local variables that are assigned but neither a parameter nor
// declared inline (foreach loop variable, catch clause variable). Each is
// returned once with its inferred type ("Object" when the type is unknown).
func collectHoistedLocals(stmts []stmt.Statement, paramSlots map[int]bool) []hoistedLocal {
	inline := map[string]bool{}  // names declared inline (foreach/catch) — skip
	types := map[string]string{} // name -> type for assigned locals
	var order []string           // first-assignment order, deduped

	record := func(lv *ast.LocalVariable) {
		if lv == nil || (paramSlots != nil && paramSlots[lv.Slot]) {
			return
		}

		name := lv.String()
		if _, seen := types[name]; seen {
			return
		}

		tn := "Object"
		if lv.JType != nil {
			if n := lv.JType.Name(); n != "" {
				tn = n
			}
		}

		types[name] = tn
		order = append(order, name)
	}

	var visit func(s stmt.Statement)
	visit = func(s stmt.Statement) {
		switch st := s.(type) {
		case *stmt.AssignmentStatement:
			if lv, ok := st.Target.(*ast.LocalVariable); ok {
				record(lv)
			}
		case *stmt.StructuredForEach:
			if lv, ok := st.Variable.(*ast.LocalVariable); ok {
				inline[lv.String()] = true
			}
		case *stmt.StructuredTry:
			for _, c := range st.Catches {
				if lv, ok := c.ExceptionVar.(*ast.LocalVariable); ok {
					inline[lv.String()] = true
				}
			}
		}

		for _, ch := range s.Children() {
			if ch != nil {
				visit(ch)
			}
		}
	}

	for _, s := range stmts {
		visit(s)
	}

	out := make([]hoistedLocal, 0, len(order))
	for _, name := range order {
		if inline[name] {
			continue
		}

		out = append(out, hoistedLocal{name: name, typeName: types[name]})
	}

	return out
}

func (w *JavaWriter) writeStatement(s stmt.Statement) {
	switch st := s.(type) {
	case *stmt.Block:
		w.writeBlock(st)
	case *stmt.AssignmentStatement:
		w.writeLine(fmt.Sprintf("%s = %s;", st.Target, w.renderExpr(st.Value)))
	case *stmt.ExpressionStatement:
		w.writeLine(fmt.Sprintf("%s;", w.renderExpr(st.Expr)))
	case *stmt.ReturnStatement:
		w.writeLine(fmt.Sprintf("return %s;", w.renderExpr(st.Value)))
	case *stmt.ReturnVoidStatement:
		w.writeLine("return;")
	case *stmt.ThrowStatement:
		w.writeLine(fmt.Sprintf("throw %s;", w.renderExpr(st.Value)))
	case *stmt.StructuredIf:
		w.writeIf(st)
	case *stmt.StructuredWhile:
		w.writeWhile(st)
	case *stmt.StructuredDoWhile:
		w.writeDoWhile(st)
	case *stmt.StructuredFor:
		w.writeFor(st)
	case *stmt.StructuredForEach:
		w.writeForEach(st)
	case *stmt.StructuredSwitch:
		w.writeSwitch(st)
	case *stmt.StructuredTry:
		w.writeTry(st)
	case *stmt.StructuredSynchronized:
		w.writeSynchronized(st)
	case *stmt.BreakStatement:
		if st.Label != "" {
			w.writeLine(fmt.Sprintf("break %s;", st.Label))
		} else {
			w.writeLine("break;")
		}
	case *stmt.ContinueStatement:
		if st.Label != "" {
			w.writeLine(fmt.Sprintf("continue %s;", st.Label))
		} else {
			w.writeLine("continue;")
		}
	case *stmt.Nop:
		// skip
	case *stmt.GotoStatement:
		w.writeLine(fmt.Sprintf("/* goto %d */", st.TargetOffset))
	default:
		w.writeLine(fmt.Sprintf("/* unknown: %s */", s))
	}
}

func (w *JavaWriter) writeBlock(b *stmt.Block) {
	for _, s := range b.Stmts {
		w.writeStatement(s)
	}
}

func (w *JavaWriter) writeIf(s *stmt.StructuredIf) {
	w.writeLine(fmt.Sprintf("if (%s) {", w.renderExpr(s.Condition)))
	w.indent++
	w.writeStatement(s.Then)
	w.indent--

	if s.Else != nil {
		// Check for else-if chain
		if elseIf, ok := s.Else.(*stmt.StructuredIf); ok {
			w.writeIndent()
			_, _ = fmt.Fprintf(&w.buf, "} else ")
			// Write the else-if inline (not indented)
			w.writeIfInline(elseIf)

			return
		}

		w.writeLine("} else {")
		w.indent++
		w.writeStatement(s.Else)
		w.indent--
	}

	w.writeLine("}")
}

func (w *JavaWriter) writeIfInline(s *stmt.StructuredIf) {
	_, _ = fmt.Fprintf(&w.buf, "if (%s) {\n", w.renderExpr(s.Condition))
	w.indent++
	w.writeStatement(s.Then)
	w.indent--

	if s.Else != nil {
		if elseIf, ok := s.Else.(*stmt.StructuredIf); ok {
			w.writeIndent()
			_, _ = fmt.Fprintf(&w.buf, "} else ")
			w.writeIfInline(elseIf)

			return
		}

		w.writeLine("} else {")
		w.indent++
		w.writeStatement(s.Else)
		w.indent--
	}

	w.writeLine("}")
}

func (w *JavaWriter) writeWhile(s *stmt.StructuredWhile) {
	if s.Label != "" {
		w.writeLine(fmt.Sprintf("%s:", s.Label))
	}

	w.writeLine(fmt.Sprintf("while (%s) {", w.renderExpr(s.Condition)))
	w.indent++
	w.writeStatement(s.Body)
	w.indent--
	w.writeLine("}")
}

func (w *JavaWriter) writeDoWhile(s *stmt.StructuredDoWhile) {
	if s.Label != "" {
		w.writeLine(fmt.Sprintf("%s:", s.Label))
	}

	w.writeLine("do {")
	w.indent++
	w.writeStatement(s.Body)
	w.indent--
	w.writeLine(fmt.Sprintf("} while (%s);", w.renderExpr(s.Condition)))
}

func (w *JavaWriter) writeFor(s *stmt.StructuredFor) {
	if s.Label != "" {
		w.writeLine(fmt.Sprintf("%s:", s.Label))
	}

	init := ""
	if s.Init != nil {
		init = strings.TrimSuffix(s.Init.String(), ";")
	}

	cond := ""
	if s.Condition != nil {
		cond = w.renderExpr(s.Condition)
	}

	update := ""
	if s.Update != nil {
		update = strings.TrimSuffix(s.Update.String(), ";")
	}

	w.writeLine(fmt.Sprintf("for (%s; %s; %s) {", init, cond, update))
	w.indent++
	w.writeStatement(s.Body)
	w.indent--
	w.writeLine("}")
}

func (w *JavaWriter) writeForEach(s *stmt.StructuredForEach) {
	if s.Label != "" {
		w.writeLine(fmt.Sprintf("%s:", s.Label))
	}

	typeName := "var"
	if s.Variable.Type() != nil {
		typeName = s.Variable.Type().Name()
	}

	w.writeLine(fmt.Sprintf("for (%s %s : %s) {",
		typeName, s.Variable, w.renderExpr(s.Iterable)))
	w.indent++
	w.writeStatement(s.Body)
	w.indent--
	w.writeLine("}")
}

func (w *JavaWriter) writeSwitch(s *stmt.StructuredSwitch) {
	w.writeLine(fmt.Sprintf("switch (%s) {", w.renderExpr(s.Value)))
	w.indent++

	for _, c := range s.Cases {
		if c.IsDefault {
			w.writeLine("default:")
		} else {
			for _, v := range c.Values {
				w.writeLine(fmt.Sprintf("case %d:", v))
			}
		}

		if c.Body != nil {
			w.indent++
			w.writeStatement(c.Body)
			w.indent--
		}
	}

	w.indent--
	w.writeLine("}")
}

func (w *JavaWriter) writeTry(s *stmt.StructuredTry) {
	w.writeLine("try {")
	w.indent++
	w.writeStatement(s.Body)
	w.indent--

	for _, c := range s.Catches {
		typeName := "Exception"
		if c.ExceptionType != nil {
			typeName = c.ExceptionType.Name()
		}

		varName := "e"
		if c.ExceptionVar != nil {
			varName = c.ExceptionVar.String()
		}

		w.writeLine(fmt.Sprintf("} catch (%s %s) {", typeName, varName))
		w.indent++
		w.writeStatement(c.Body)
		w.indent--
	}

	if s.Finally != nil {
		w.writeLine("} finally {")
		w.indent++
		w.writeStatement(s.Finally)
		w.indent--
	}

	w.writeLine("}")
}

func (w *JavaWriter) writeSynchronized(s *stmt.StructuredSynchronized) {
	w.writeLine(fmt.Sprintf("synchronized (%s) {", w.renderExpr(s.Object)))
	w.indent++
	w.writeStatement(s.Body)
	w.indent--
	w.writeLine("}")
}

// renderExpr renders an expression as a Java source string.
// It delegates to the expression's own String() method, which handles
// precedence-based parenthesization.
func (w *JavaWriter) renderExpr(e ast.Expression) string {
	if e == nil {
		return ""
	}

	return e.String()
}

func (w *JavaWriter) writeLine(s string) {
	w.writeIndent()
	w.buf.WriteString(s)
	w.buf.WriteByte('\n')
}

func (w *JavaWriter) writeIndent() {
	for range w.indent {
		w.buf.WriteString(w.tab)
	}
}

// WriteMethod writes a complete method declaration.
func (w *JavaWriter) WriteMethod(returnType, name string, params []string, stmts []stmt.Statement) {
	var paramStr string
	if len(params) > 0 {
		paramStr = strings.Join(params, ", ")
	}

	w.writeLine(fmt.Sprintf("%s %s(%s) {", returnType, name, paramStr))
	w.indent++
	w.WriteStatements(stmts)
	w.indent--
	w.writeLine("}")
}

// WriteClass writes a class wrapper around statements.
func (w *JavaWriter) WriteClass(className string, stmts []stmt.Statement) {
	w.writeLine(fmt.Sprintf("class %s {", className))
	w.indent++
	w.WriteStatements(stmts)
	w.indent--
	w.writeLine("}")
}
