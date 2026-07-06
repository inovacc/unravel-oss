package codegen

import (
	"fmt"
	"strings"

	"golang.org/x/tools/imports"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
)

// Generator produces Go source code from IR.
type Generator struct {
	buf    strings.Builder
	indent int
}

// New creates a new code generator.
func New() *Generator {
	return &Generator{}
}

// Generate produces Go source code from an IR module.
func (g *Generator) Generate(mod *ir.Module) (string, error) {
	g.buf.Reset()
	g.indent = 0

	// Package declaration
	g.writef("package %s\n", mod.PackageName)

	// Imports
	if len(mod.Imports) > 0 {
		g.writef("\nimport (\n")
		g.indent++

		for _, imp := range mod.Imports {
			if imp.Alias != "" {
				g.writef("%s %q\n", imp.Alias, imp.Path)
			} else {
				g.writef("%q\n", imp.Path)
			}
		}

		g.indent--
		g.writef(")\n")
	}

	// Declarations
	for _, decl := range mod.Decls {
		g.writef("\n")
		g.genDecl(decl)
	}

	// Format with goimports
	return g.format()
}

// format runs goimports on the generated code.
func (g *Generator) format() (string, error) {
	src := g.buf.String()

	out, err := imports.Process("output.go", []byte(src), nil)
	if err != nil {
		// Return unformatted code on error
		return src, nil
	}

	return string(out), nil
}

// genDecl generates code for a declaration node.
func (g *Generator) genDecl(node ir.Node) {
	switch n := node.(type) {
	case *ir.TypeDecl:
		g.genTypeDecl(n)
	case *ir.FuncDecl:
		g.genFuncDecl(n)
	case *ir.VarDecl:
		g.genVarDecl(n)
	case *ir.RawStmt:
		g.genRawStmt(n)
	default:
		g.writef("// unsupported declaration: %T\n", node)
	}
}

// genTypeDecl generates a type declaration.
func (g *Generator) genTypeDecl(td *ir.TypeDecl) {
	if td.Comment != "" {
		g.writef("// %s\n", td.Comment)
	}

	switch td.Kind {
	case ir.TypeDeclStruct:
		g.genStruct(td)
	case ir.TypeDeclInterface:
		g.genInterface(td)
	case ir.TypeDeclEnum:
		g.genEnum(td)
	}
}

// genStruct generates a struct type declaration.
func (g *Generator) genStruct(td *ir.TypeDecl) {
	typeParams := ""

	if len(td.TypeParams) > 0 {
		var params []string
		for _, tp := range td.TypeParams {
			params = append(params, tp+" any")
		}

		typeParams = "[" + strings.Join(params, ", ") + "]"
	}

	g.writef("type %s%s struct {\n", td.Name, typeParams)
	g.indent++

	// Embedded types (from inheritance)
	for _, emb := range td.Embedded {
		g.writef("%s\n", emb)
	}

	// Fields
	for _, f := range td.Fields {
		g.genFieldDecl(f)
	}

	g.indent--
	g.writef("}\n")
}

// genInterface generates an interface type declaration.
func (g *Generator) genInterface(td *ir.TypeDecl) {
	g.writef("type %s interface {\n", td.Name)
	g.indent++

	for _, m := range td.Methods {
		g.writef("%s(%s)", m.Name, g.paramList(m.Params))

		if len(m.Returns) > 0 {
			g.buf.WriteString(" " + g.returnList(m.Returns))
		}

		g.buf.WriteString("\n")
	}

	g.indent--
	g.writef("}\n")
}

// genEnum generates Go const declarations from an enum.
func (g *Generator) genEnum(td *ir.TypeDecl) {
	g.writef("type %s int\n\n", td.Name)
	g.writef("const (\n")
	g.indent++

	for i, v := range td.Values {
		if i == 0 && v.Value == "" {
			g.writef("%s %s = iota\n", v.Name, td.Name)
		} else if v.Value != "" {
			g.writef("%s %s = %s\n", v.Name, td.Name, v.Value)
		} else {
			g.writef("%s\n", v.Name)
		}
	}

	g.indent--
	g.writef(")\n")
}

// genFieldDecl generates a struct field declaration.
func (g *Generator) genFieldDecl(f *ir.FieldDecl) {
	tag := ""
	if f.Tag != "" {
		tag = " `" + f.Tag + "`"
	}

	comment := ""
	if f.Comment != "" {
		comment = " // " + f.Comment
	}

	g.writef("%s %s%s%s\n", f.Name, g.typeString(f.Type), tag, comment)
}

// genFuncDecl generates a function or method declaration.
func (g *Generator) genFuncDecl(fn *ir.FuncDecl) {
	if fn.Comment != "" {
		g.writef("// %s\n", fn.Comment)
	}

	g.buf.WriteString(g.indentStr())
	g.buf.WriteString("func ")

	// Receiver
	if fn.Receiver != nil {
		g.buf.WriteString("(")
		g.buf.WriteString(fn.Receiver.Name)
		g.buf.WriteString(" ")
		g.buf.WriteString(g.typeString(fn.Receiver.Type))
		g.buf.WriteString(") ")
	}

	// Type params
	typeParams := ""

	if len(fn.TypeParams) > 0 {
		var params []string
		for _, tp := range fn.TypeParams {
			params = append(params, tp+" any")
		}

		typeParams = "[" + strings.Join(params, ", ") + "]"
	}

	g.buf.WriteString(fn.Name)
	g.buf.WriteString(typeParams)
	g.buf.WriteString("(")
	g.buf.WriteString(g.paramList(fn.Params))
	g.buf.WriteString(")")

	if len(fn.Returns) > 0 {
		g.buf.WriteString(" ")
		g.buf.WriteString(g.returnList(fn.Returns))
	}

	if len(fn.Body) == 0 {
		g.buf.WriteString(" {}\n")

		return
	}

	g.buf.WriteString(" {\n")
	g.indent++
	g.genBody(fn.Body)
	g.indent--
	g.writef("}\n")
}

// genVarDecl generates a variable declaration.
func (g *Generator) genVarDecl(v *ir.VarDecl) {
	if v.Const {
		g.buf.WriteString(g.indentStr())
		g.buf.WriteString("const ")
		g.buf.WriteString(v.Name)

		if v.Type != nil {
			g.buf.WriteString(" " + g.typeString(v.Type))
		}

		if v.Value != nil {
			g.buf.WriteString(" = ")
			g.genExpr(v.Value)
		}

		g.buf.WriteString("\n")

		return
	}

	if v.Value != nil {
		g.buf.WriteString(g.indentStr())
		g.buf.WriteString(v.Name)
		g.buf.WriteString(" := ")
		g.genExpr(v.Value)
		g.buf.WriteString("\n")
	} else {
		g.buf.WriteString(g.indentStr())
		g.buf.WriteString("var " + v.Name)

		if v.Type != nil {
			g.buf.WriteString(" " + g.typeString(v.Type))
		}

		g.buf.WriteString("\n")
	}
}

// genBody generates a list of statements.
func (g *Generator) genBody(stmts []ir.Node) {
	for _, stmt := range stmts {
		g.genStmt(stmt)
	}
}

// genStmt generates a single statement.
func (g *Generator) genStmt(node ir.Node) {
	switch n := node.(type) {
	case *ir.ReturnStmt:
		g.genReturn(n)
	case *ir.IfStmt:
		g.genIf(n)
	case *ir.ForStmt:
		g.genFor(n)
	case *ir.RangeStmt:
		g.genRange(n)
	case *ir.SwitchStmt:
		g.genSwitch(n)
	case *ir.AssignStmt:
		g.genAssign(n)
	case *ir.ExprStmt:
		g.buf.WriteString(g.indentStr())
		g.genExpr(n.Expr)
		g.buf.WriteString("\n")
	case *ir.DeferStmt:
		g.buf.WriteString(g.indentStr())
		g.buf.WriteString("defer ")
		g.genExpr(n.Call)
		g.buf.WriteString("\n")
	case *ir.BranchStmt:
		g.writef("%s\n", n.Kind)
	case *ir.VarDecl:
		g.genVarDecl(n)
	case *ir.ErrorHandling:
		g.genErrorHandling(n)
	case *ir.RawStmt:
		g.genRawStmt(n)
	case *ir.FuncDecl:
		g.genFuncDecl(n)
	case *ir.TypeDecl:
		g.genTypeDecl(n)
	default:
		g.writef("// unsupported statement: %T\n", node)
	}
}

// genReturn generates a return statement.
func (g *Generator) genReturn(r *ir.ReturnStmt) {
	g.buf.WriteString(g.indentStr())
	g.buf.WriteString("return")

	if len(r.Values) > 0 {
		g.buf.WriteString(" ")

		for i, v := range r.Values {
			if i > 0 {
				g.buf.WriteString(", ")
			}

			g.genExpr(v)
		}
	}

	g.buf.WriteString("\n")
}

// genIf generates an if/else statement.
func (g *Generator) genIf(n *ir.IfStmt) {
	g.buf.WriteString(g.indentStr())
	g.buf.WriteString("if ")
	g.genExpr(n.Cond)
	g.buf.WriteString(" {\n")
	g.indent++
	g.genBody(n.Then)
	g.indent--

	if len(n.Else) > 0 {
		g.writef("} else {\n")
		g.indent++
		g.genBody(n.Else)
		g.indent--
	}

	g.writef("}\n")
}

// genFor generates a for loop.
func (g *Generator) genFor(n *ir.ForStmt) {
	g.buf.WriteString(g.indentStr())

	if n.Init == nil && n.Cond == nil && n.Post == nil {
		// Infinite loop
		g.buf.WriteString("for {\n")
	} else if n.Init == nil && n.Post == nil {
		// While-style loop
		g.buf.WriteString("for ")
		g.genExpr(n.Cond)
		g.buf.WriteString(" {\n")
	} else {
		g.buf.WriteString("for ")

		if n.Init != nil {
			g.genStmtInline(n.Init)
		}

		g.buf.WriteString("; ")

		if n.Cond != nil {
			g.genExpr(n.Cond)
		}

		g.buf.WriteString("; ")

		if n.Post != nil {
			g.genExpr(n.Post)
		}

		g.buf.WriteString(" {\n")
	}

	g.indent++
	g.genBody(n.Body)
	g.indent--
	g.writef("}\n")
}

// genRange generates a for-range loop.
func (g *Generator) genRange(n *ir.RangeStmt) {
	g.buf.WriteString(g.indentStr())
	g.buf.WriteString("for ")

	if n.Key != "" {
		g.buf.WriteString(n.Key)
	} else {
		g.buf.WriteString("_")
	}

	g.buf.WriteString(", ")

	if n.Value != "" {
		g.buf.WriteString(n.Value)
	} else {
		g.buf.WriteString("_")
	}

	g.buf.WriteString(" := range ")
	g.genExpr(n.Range)
	g.buf.WriteString(" {\n")

	g.indent++
	g.genBody(n.Body)
	g.indent--
	g.writef("}\n")
}

// genSwitch generates a switch statement.
func (g *Generator) genSwitch(n *ir.SwitchStmt) {
	g.buf.WriteString(g.indentStr())
	g.buf.WriteString("switch ")

	if n.Tag != nil {
		g.genExpr(n.Tag)
		g.buf.WriteString(" ")
	}

	g.buf.WriteString("{\n")

	for _, c := range n.Cases {
		if c.Default {
			g.writef("default:\n")
		} else {
			g.buf.WriteString(g.indentStr())
			g.buf.WriteString("case ")

			for i, v := range c.Values {
				if i > 0 {
					g.buf.WriteString(", ")
				}

				g.genExpr(v)
			}

			g.buf.WriteString(":\n")
		}

		g.indent++
		g.genBody(c.Body)
		g.indent--
	}

	g.writef("}\n")
}

// genAssign generates an assignment statement.
func (g *Generator) genAssign(n *ir.AssignStmt) {
	g.buf.WriteString(g.indentStr())

	for i, lhs := range n.LHS {
		if i > 0 {
			g.buf.WriteString(", ")
		}

		g.genExpr(lhs)
	}

	g.buf.WriteString(" ")
	g.buf.WriteString(n.Op)
	g.buf.WriteString(" ")

	for i, rhs := range n.RHS {
		if i > 0 {
			g.buf.WriteString(", ")
		}

		g.genExpr(rhs)
	}

	g.buf.WriteString("\n")
}

// genErrorHandling generates Go error handling pattern.
func (g *Generator) genErrorHandling(n *ir.ErrorHandling) {
	g.buf.WriteString(g.indentStr())
	g.buf.WriteString(n.ErrVar)
	g.buf.WriteString(" := ")
	g.genExpr(n.Call)
	g.buf.WriteString("\n")

	g.buf.WriteString(g.indentStr())
	g.buf.WriteString("if ")
	g.buf.WriteString(n.ErrVar)
	g.buf.WriteString(" != nil {\n")

	g.indent++
	g.genBody(n.Body)
	g.indent--

	g.writef("}\n")
}

// genRawStmt generates a raw (unprocessed) statement.
func (g *Generator) genRawStmt(n *ir.RawStmt) {
	if n.Comment != "" {
		g.writef("// %s\n", n.Comment)
	}

	if n.Text != "" {
		g.writef("%s\n", n.Text)
	}
}

// genExpr generates an expression.
func (g *Generator) genExpr(expr ir.Expr) {
	switch e := expr.(type) {
	case *ir.LiteralExpr:
		if e.Kind == "string" {
			g.buf.WriteString(e.Value)
		} else {
			g.buf.WriteString(e.Value)
		}
	case *ir.IdentExpr:
		g.buf.WriteString(e.Name)
	case *ir.BinaryExpr:
		g.genExpr(e.Left)
		g.buf.WriteString(" ")
		g.buf.WriteString(e.Op)
		g.buf.WriteString(" ")
		g.genExpr(e.Right)
	case *ir.UnaryExpr:
		if e.Prefix {
			g.buf.WriteString(e.Op)
			g.genExpr(e.Operand)
		} else {
			g.genExpr(e.Operand)
			g.buf.WriteString(e.Op)
		}
	case *ir.CallExpr:
		g.buf.WriteString(e.Func)
		g.buf.WriteString("(")

		for i, arg := range e.Args {
			if i > 0 {
				g.buf.WriteString(", ")
			}

			g.genExpr(arg)
		}

		g.buf.WriteString(")")
	case *ir.MethodCallExpr:
		g.genExpr(e.Receiver)
		g.buf.WriteString(".")
		g.buf.WriteString(e.Method)
		g.buf.WriteString("(")

		for i, arg := range e.Args {
			if i > 0 {
				g.buf.WriteString(", ")
			}

			g.genExpr(arg)
		}

		g.buf.WriteString(")")
	case *ir.SelectorExpr:
		g.genExpr(e.X)
		g.buf.WriteString(".")
		g.buf.WriteString(e.Sel)
	case *ir.IndexExpr:
		g.genExpr(e.X)
		g.buf.WriteString("[")
		g.genExpr(e.Index)
		g.buf.WriteString("]")
	case *ir.AddressExpr:
		g.buf.WriteString("&")
		g.genExpr(e.X)
	case *ir.DerefExpr:
		g.buf.WriteString("*")
		g.genExpr(e.X)
	case *ir.CompositeLitExpr:
		if e.Type != nil {
			g.buf.WriteString(g.typeString(e.Type))
		}

		g.buf.WriteString("{")

		for i, kv := range e.Fields {
			if i > 0 {
				g.buf.WriteString(", ")
			}

			if kv.Key != nil {
				g.genExpr(kv.Key)
				g.buf.WriteString(": ")
			}

			g.genExpr(kv.Value)
		}

		g.buf.WriteString("}")
	case *ir.FuncLitExpr:
		g.buf.WriteString("func(")
		g.buf.WriteString(g.paramList(e.Params))
		g.buf.WriteString(")")

		if len(e.Returns) > 0 {
			g.buf.WriteString(" ")
			g.buf.WriteString(g.returnList(e.Returns))
		}

		g.buf.WriteString(" {\n")
		g.indent++
		g.genBody(e.Body)
		g.indent--
		g.buf.WriteString(g.indentStr())
		g.buf.WriteString("}")
	case *ir.RawExpr:
		g.buf.WriteString(e.Text)
	case *ir.MakeExpr:
		g.buf.WriteString("make(")
		g.buf.WriteString(g.typeString(e.Type))

		if e.Len != nil {
			g.buf.WriteString(", ")
			g.genExpr(e.Len)
		}

		if e.Cap != nil {
			g.buf.WriteString(", ")
			g.genExpr(e.Cap)
		}

		g.buf.WriteString(")")
	default:
		g.buf.WriteString(fmt.Sprintf("/* unsupported expr: %T */", expr))
	}
}

// genStmtInline generates a statement without newline (for for-init).
func (g *Generator) genStmtInline(node ir.Node) {
	switch n := node.(type) {
	case *ir.VarDecl:
		g.buf.WriteString(n.Name + " := ")

		if n.Value != nil {
			g.genExpr(n.Value)
		} else {
			g.buf.WriteString("0")
		}
	case *ir.AssignStmt:
		for i, lhs := range n.LHS {
			if i > 0 {
				g.buf.WriteString(", ")
			}

			g.genExpr(lhs)
		}

		g.buf.WriteString(" " + n.Op + " ")

		for i, rhs := range n.RHS {
			if i > 0 {
				g.buf.WriteString(", ")
			}

			g.genExpr(rhs)
		}
	default:
		g.buf.WriteString("/* inline stmt */")
	}
}

// typeString returns the Go type string for an IR type reference.
func (g *Generator) typeString(t *ir.TypeRef) string {
	if t == nil {
		return "any"
	}

	switch t.Kind {
	case ir.KindSlice:
		elem := "any"
		if t.ElemType != nil {
			elem = g.typeString(t.ElemType)
		}

		return "[]" + elem

	case ir.KindMap:
		key := "string"
		val := "any"

		if t.KeyType != nil {
			key = g.typeString(t.KeyType)
		}

		if t.ValType != nil {
			val = g.typeString(t.ValType)
		}

		return "map[" + key + "]" + val

	case ir.KindPointer:
		if t.ElemType != nil {
			return "*" + g.typeString(t.ElemType)
		}

		return t.Name

	case ir.KindChannel:
		elem := "any"
		if t.ElemType != nil {
			elem = g.typeString(t.ElemType)
		}

		return "chan " + elem

	case ir.KindGeneric:
		if len(t.TypeParams) > 0 {
			var params []string
			for _, p := range t.TypeParams {
				params = append(params, g.typeString(p))
			}

			return t.Name + "[" + strings.Join(params, ", ") + "]"
		}

		return t.Name

	default:
		return t.Name
	}
}

// paramList generates a parameter list string.
func (g *Generator) paramList(params []*ir.ParamDecl) string {
	var parts []string

	for _, p := range params {
		if p.Name != "" {
			parts = append(parts, p.Name+" "+g.typeString(p.Type))
		} else {
			parts = append(parts, g.typeString(p.Type))
		}
	}

	return strings.Join(parts, ", ")
}

// returnList generates a return type list string.
func (g *Generator) returnList(returns []*ir.ParamDecl) string {
	if len(returns) == 1 && returns[0].Name == "" {
		return g.typeString(returns[0].Type)
	}

	var parts []string

	for _, r := range returns {
		if r.Name != "" {
			parts = append(parts, r.Name+" "+g.typeString(r.Type))
		} else {
			parts = append(parts, g.typeString(r.Type))
		}
	}

	return "(" + strings.Join(parts, ", ") + ")"
}

// writef writes a formatted string with proper indentation.
func (g *Generator) writef(format string, args ...any) {
	g.buf.WriteString(g.indentStr())

	_, _ = fmt.Fprintf(&g.buf, format, args...)
}

// indentStr returns the current indentation string.
func (g *Generator) indentStr() string {
	return strings.Repeat("\t", g.indent)
}
