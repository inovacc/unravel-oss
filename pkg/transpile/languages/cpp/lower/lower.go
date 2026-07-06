package lower

import (
	"fmt"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/ast"
)

// Lowerer transforms a C++ AST into language-agnostic IR.
type Lowerer struct{}

// NewLowerer creates a new AST-to-IR lowerer.
func NewLowerer() *Lowerer {
	return &Lowerer{}
}

// Lower transforms a TranslationUnit into an IR Module.
func (l *Lowerer) Lower(tu *ast.TranslationUnit) *ir.Module {
	mod := &ir.Module{
		PackageName: "main",
		SourceFile:  tu.FileName,
	}

	// Collect imports from #include directives
	imports := make(map[string]*ir.Import)
	for _, inc := range tu.Includes {
		l.mapIncludeToImport(inc, imports)
	}

	keys := make([]string, 0, len(imports))
	for k := range imports {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		mod.Imports = append(mod.Imports, imports[k])
	}

	// Lower all declarations
	for _, decl := range tu.Decls {
		lowered := l.lowerDecl(decl)
		mod.Decls = append(mod.Decls, lowered...)
	}

	return mod
}

// mapIncludeToImport maps a C++ #include to Go imports.
func (l *Lowerer) mapIncludeToImport(inc *ast.Include, imports map[string]*ir.Import) {
	if !inc.System {
		return
	}

	// Map standard C++ headers to Go packages
	switch inc.Path {
	case "iostream", "cstdio":
		imports["fmt"] = &ir.Import{Path: "fmt"}
	case "fstream", "cstdlib":
		imports["os"] = &ir.Import{Path: "os"}
	case "string", "cstring":
		imports["strings"] = &ir.Import{Path: "strings"}
	case "vector", "array", "list", "deque", "forward_list":
		// Slices are built-in, but might need "slices" for helpers
	case "map", "unordered_map", "set", "unordered_set":
		// Maps are built-in
	case "algorithm":
		imports["sort"] = &ir.Import{Path: "sort"}
		imports["slices"] = &ir.Import{Path: "slices"}
	case "cmath":
		imports["math"] = &ir.Import{Path: "math"}
	case "thread":
		imports["sync"] = &ir.Import{Path: "sync"}
	case "mutex":
		imports["sync"] = &ir.Import{Path: "sync"}
	case "atomic":
		imports["sync/atomic"] = &ir.Import{Path: "sync/atomic"}
	case "chrono", "ctime":
		imports["time"] = &ir.Import{Path: "time"}
	case "regex":
		imports["regexp"] = &ir.Import{Path: "regexp"}
	case "filesystem":
		imports["os"] = &ir.Import{Path: "os"}
		imports["path/filepath"] = &ir.Import{Path: "path/filepath"}
	case "memory":
		// smart pointers → regular pointers in Go
	case "functional":
		// function objects → closures in Go
	case "sstream", "iomanip":
		imports["fmt"] = &ir.Import{Path: "fmt"}
		imports["strings"] = &ir.Import{Path: "strings"}
	case "exception", "stdexcept":
		imports["errors"] = &ir.Import{Path: "errors"}
		imports["fmt"] = &ir.Import{Path: "fmt"}
	case "cassert":
		// Go doesn't have assert, use testing or panic
	case "numeric":
		// numeric algorithms
	case "random":
		imports["math/rand"] = &ir.Import{Path: "math/rand"}
	case "json/json.h", "nlohmann/json.hpp":
		imports["encoding/json"] = &ir.Import{Path: "encoding/json"}

	// C standard library headers
	case "stdio.h":
		imports["fmt"] = &ir.Import{Path: "fmt"}
		imports["os"] = &ir.Import{Path: "os"}
	case "math.h":
		imports["math"] = &ir.Import{Path: "math"}
	case "assert.h":
		// Go doesn't have assert, use testing or panic
	case "stdlib.h":
		imports["os"] = &ir.Import{Path: "os"}
		imports["strconv"] = &ir.Import{Path: "strconv"}
	case "string.h":
		imports["strings"] = &ir.Import{Path: "strings"}
		imports["bytes"] = &ir.Import{Path: "bytes"}
	case "ctype.h":
		imports["unicode"] = &ir.Import{Path: "unicode"}
	case "time.h":
		imports["time"] = &ir.Import{Path: "time"}
	case "errno.h":
		imports["errors"] = &ir.Import{Path: "errors"}
		imports["syscall"] = &ir.Import{Path: "syscall"}
	case "signal.h":
		imports["os/signal"] = &ir.Import{Path: "os/signal"}
		imports["os"] = &ir.Import{Path: "os"}

	// POSIX headers
	case "unistd.h":
		imports["os"] = &ir.Import{Path: "os"}
		imports["syscall"] = &ir.Import{Path: "syscall"}
	case "pthread.h":
		imports["sync"] = &ir.Import{Path: "sync"}
	case "dirent.h":
		imports["os"] = &ir.Import{Path: "os"}
	case "fcntl.h":
		imports["os"] = &ir.Import{Path: "os"}
	case "sys/socket.h", "arpa/inet.h", "netinet/in.h":
		imports["net"] = &ir.Import{Path: "net"}
	case "sys/mman.h":
		imports["syscall"] = &ir.Import{Path: "syscall"}
	case "dlfcn.h":
		imports["plugin"] = &ir.Import{Path: "plugin"}
	case "sys/stat.h", "sys/types.h":
		imports["os"] = &ir.Import{Path: "os"}

	// stdint.h / stdbool.h / stddef.h / stdarg.h / limits.h / float.h
	// These map to built-in Go types, no import needed.
	case "stdint.h", "stdbool.h", "stddef.h", "stdarg.h", "limits.h", "float.h", "locale.h", "setjmp.h":
		// built-in types or no direct mapping needed
	}
}

// lowerDecl transforms a single AST declaration into IR node(s).
func (l *Lowerer) lowerDecl(node ast.Node) []ir.Node {
	switch n := node.(type) {
	case *ast.Class:
		return l.lowerClass(n)
	case *ast.Enum:
		return l.lowerEnum(n)
	case *ast.Function:
		return l.lowerFunction(n)
	case *ast.Namespace:
		return l.lowerNamespace(n)
	case *ast.Variable:
		return []ir.Node{l.lowerVariable(n)}
	case *ast.UsingDecl:
		return l.lowerUsing(n)
	case *ast.TypedefDecl:
		return l.lowerTypedef(n)
	case *ast.GotoStmt:
		return []ir.Node{&ir.GotoStmt{Label: n.Label}}
	case *ast.LabelStmt:
		ls := &ir.LabelStmt{Label: n.Label}
		if n.Stmt != nil {
			stmts := l.lowerDecl(n.Stmt)
			if len(stmts) > 0 {
				ls.Stmt = stmts[0]
			}
		}

		return []ir.Node{ls}
	case *ast.ExternDecl:
		return l.lowerExternDecl(n)
	case *ast.FuncPtrDecl:
		return l.lowerFuncPtrDecl(n)
	case *ast.BitField:
		return []ir.Node{&ir.FieldDecl{
			Name:    exportName(n.Name),
			Type:    l.lowerType(n.Type),
			Comment: fmt.Sprintf("bitfield: %d bits", n.Width),
		}}
	default:
		return []ir.Node{&ir.RawStmt{Text: fmt.Sprintf("// unsupported declaration: %T", node)}}
	}
}

// lowerClass transforms a C++ class/struct into IR types and functions.
func (l *Lowerer) lowerClass(cls *ast.Class) []ir.Node {
	var nodes []ir.Node

	// Create the struct type
	td := &ir.TypeDecl{
		Kind: ir.TypeDeclStruct,
		Name: cls.Name,
	}

	// Add type params for templates
	for _, tp := range cls.TemplateParams {
		td.TypeParams = append(td.TypeParams, tp.Name)
	}

	// Inheritance → embedded types (composition)
	for _, base := range cls.BaseClasses {
		td.Embedded = append(td.Embedded, base.Name)
	}

	// Fields
	for _, field := range cls.Fields {
		fd := &ir.FieldDecl{
			Name: exportName(field.Name),
			Type: l.lowerType(field.Type),
		}
		td.Fields = append(td.Fields, fd)
	}

	nodes = append(nodes, td)

	// Constructors → NewX() functions
	for _, ctor := range cls.Constructors {
		fn := l.lowerConstructor(cls.Name, ctor)
		nodes = append(nodes, fn)
	}

	// Destructor → Close() method with defer hint
	if cls.Destructor != nil {
		fn := l.lowerDestructor(cls.Name, cls.Destructor)
		nodes = append(nodes, fn)
	}

	// Methods → method declarations with receiver
	for _, method := range cls.Methods {
		fn := l.lowerMethod(cls.Name, method)
		nodes = append(nodes, fn)
	}

	// Operator overloads → named methods
	for _, op := range cls.Operators {
		fn := l.lowerOperator(cls.Name, op)
		nodes = append(nodes, fn)
	}

	// If class has pure virtual methods, also generate an interface
	if iface := l.extractInterface(cls); iface != nil {
		nodes = append(nodes, iface)
	}

	return nodes
}

// extractInterface creates an interface TypeDecl if the class has pure virtual methods.
func (l *Lowerer) extractInterface(cls *ast.Class) *ir.TypeDecl {
	var methods []*ir.FuncDecl

	for _, m := range cls.Methods {
		if m.Pure {
			fn := &ir.FuncDecl{
				Name: exportName(m.Name),
			}
			for _, p := range m.Params {
				fn.Params = append(fn.Params, &ir.ParamDecl{
					Name: p.Name,
					Type: l.lowerType(p.Type),
				})
			}

			if m.ReturnType != nil && m.ReturnType.Name != "void" {
				fn.Returns = append(fn.Returns, &ir.ParamDecl{
					Type: l.lowerType(m.ReturnType),
				})
			}

			methods = append(methods, fn)
		}
	}

	if len(methods) == 0 {
		return nil
	}

	return &ir.TypeDecl{
		Kind:    ir.TypeDeclInterface,
		Name:    cls.Name + "er",
		Methods: methods,
		Comment: fmt.Sprintf("Interface extracted from abstract class %s", cls.Name),
	}
}

// lowerEnum transforms a C++ enum into an IR type declaration with const values.
func (l *Lowerer) lowerEnum(e *ast.Enum) []ir.Node {
	td := &ir.TypeDecl{
		Kind: ir.TypeDeclEnum,
		Name: e.Name,
	}

	for _, v := range e.Values {
		td.Values = append(td.Values, &ir.EnumVal{
			Name:  e.Name + v.Name, // Go convention: TypeName + ValueName
			Value: v.Value,
		})
	}

	return []ir.Node{td}
}

// lowerFunction transforms a C++ function into an IR function declaration.
func (l *Lowerer) lowerFunction(fn *ast.Function) []ir.Node {
	fd := &ir.FuncDecl{
		Name: exportName(fn.Name),
	}

	// Template params
	for _, tp := range fn.TemplateParams {
		fd.TypeParams = append(fd.TypeParams, tp.Name)
	}

	// Parameters
	for _, p := range fn.Params {
		fd.Params = append(fd.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: l.lowerType(p.Type),
		})
	}

	// Return type
	if fn.ReturnType != nil && fn.ReturnType.Name != "void" {
		fd.Returns = append(fd.Returns, &ir.ParamDecl{
			Type: l.lowerType(fn.ReturnType),
		})
	}

	// Body
	fd.Body = l.lowerBody(fn.Body)

	return []ir.Node{fd}
}

// lowerConstructor transforms a C++ constructor into a NewX() factory function.
func (l *Lowerer) lowerConstructor(className string, ctor *ast.Constructor) *ir.FuncDecl {
	fn := &ir.FuncDecl{
		Name: "New" + className,
	}

	for _, p := range ctor.Params {
		fn.Params = append(fn.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: l.lowerType(p.Type),
		})
	}

	fn.Returns = []*ir.ParamDecl{
		{Type: &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + className, ElemType: &ir.TypeRef{Kind: ir.KindStruct, Name: className}}},
	}

	fn.Body = l.lowerBody(ctor.Body)

	return fn
}

// lowerDestructor transforms a C++ destructor into a Close() method.
func (l *Lowerer) lowerDestructor(className string, dtor *ast.Destructor) *ir.FuncDecl {
	return &ir.FuncDecl{
		Name: "Close",
		Receiver: &ir.ParamDecl{
			Name: strings.ToLower(className[:1]),
			Type: &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + className},
		},
		Body:    l.lowerBody(dtor.Body),
		Comment: "Close cleans up resources (from C++ destructor). Use with defer.",
	}
}

// lowerMethod transforms a C++ method into an IR method with a receiver.
func (l *Lowerer) lowerMethod(className string, m *ast.Method) *ir.FuncDecl {
	receiverType := &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + className}
	if m.Const {
		// const methods could use value receiver, but pointer is safer
		receiverType = &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + className}
	}

	fn := &ir.FuncDecl{
		Name: exportName(m.Name),
		Receiver: &ir.ParamDecl{
			Name: strings.ToLower(className[:1]),
			Type: receiverType,
		},
	}

	for _, p := range m.Params {
		fn.Params = append(fn.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: l.lowerType(p.Type),
		})
	}

	if m.ReturnType != nil && m.ReturnType.Name != "void" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{
			Type: l.lowerType(m.ReturnType),
		})
	}

	fn.Body = l.lowerBody(m.Body)

	return fn
}

// lowerOperator transforms an operator overload into a named method.
func (l *Lowerer) lowerOperator(className string, op *ast.OperatorOverload) *ir.FuncDecl {
	methodName := operatorMethodName(op.Operator)

	fn := &ir.FuncDecl{
		Name: methodName,
		Receiver: &ir.ParamDecl{
			Name: strings.ToLower(className[:1]),
			Type: &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + className},
		},
		Comment: fmt.Sprintf("From C++ operator%s", op.Operator),
	}

	for _, p := range op.Params {
		fn.Params = append(fn.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: l.lowerType(p.Type),
		})
	}

	if op.ReturnType != nil && op.ReturnType.Name != "void" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{
			Type: l.lowerType(op.ReturnType),
		})
	}

	fn.Body = l.lowerBody(op.Body)

	return fn
}

// lowerNamespace flattens namespace declarations into top-level decls.
func (l *Lowerer) lowerNamespace(ns *ast.Namespace) []ir.Node {
	var nodes []ir.Node

	nodes = append(nodes, &ir.RawStmt{
		Comment: fmt.Sprintf("From C++ namespace %s", ns.Name),
	})

	for _, decl := range ns.Decls {
		nodes = append(nodes, l.lowerDecl(decl)...)
	}

	return nodes
}

// lowerVariable transforms a C++ variable into an IR variable declaration.
func (l *Lowerer) lowerVariable(v *ast.Variable) ir.Node {
	vd := &ir.VarDecl{
		Name:  v.Name,
		Type:  l.lowerType(v.Type),
		Const: v.Const,
	}

	if v.Init != nil {
		vd.Value = l.lowerExpr(v.Init)
	}

	return vd
}

// lowerUsing handles using declarations.
func (l *Lowerer) lowerUsing(u *ast.UsingDecl) []ir.Node {
	return []ir.Node{&ir.RawStmt{
		Comment: fmt.Sprintf("using %s (resolved at import level)", u.Name),
	}}
}

// lowerTypedef handles typedef/using alias declarations.
func (l *Lowerer) lowerTypedef(td *ast.TypedefDecl) []ir.Node {
	return []ir.Node{&ir.TypeDecl{
		Kind:    ir.TypeDeclStruct,
		Name:    td.Name,
		Comment: fmt.Sprintf("Type alias from C++ typedef/using (underlying: %s)", td.Underlying.Name),
	}}
}

// lowerExternDecl flattens extern declarations into top-level decls.
func (l *Lowerer) lowerExternDecl(ed *ast.ExternDecl) []ir.Node {
	var nodes []ir.Node

	if ed.Var != nil {
		nodes = append(nodes, l.lowerVariable(ed.Var))
	}

	for _, decl := range ed.Decls {
		nodes = append(nodes, l.lowerDecl(decl)...)
	}

	if len(nodes) == 0 {
		return []ir.Node{&ir.RawStmt{Comment: "extern \"C\" block"}}
	}

	return nodes
}

// lowerFuncPtrDecl transforms a C function pointer typedef into a Go func type.
func (l *Lowerer) lowerFuncPtrDecl(fpd *ast.FuncPtrDecl) []ir.Node {
	td := &ir.TypeDecl{
		Kind:    ir.TypeDeclStruct, // reuse struct kind for type alias
		Name:    fpd.Name,
		Comment: "func type from C function pointer typedef",
	}

	// Build a representative method signature to capture the func type info
	fn := &ir.FuncDecl{
		Name: fpd.Name,
	}
	for _, p := range fpd.Params {
		fn.Params = append(fn.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: l.lowerType(p.Type),
		})
	}

	if fpd.ReturnType != nil && fpd.ReturnType.Name != "void" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{
			Type: l.lowerType(fpd.ReturnType),
		})
	}

	td.Methods = []*ir.FuncDecl{fn}

	return []ir.Node{td}
}

// lowerBody transforms a slice of AST statements into IR nodes.
func (l *Lowerer) lowerBody(stmts []ast.Node) []ir.Node {
	var nodes []ir.Node
	for _, stmt := range stmts {
		nodes = append(nodes, l.lowerStmt(stmt)...)
	}

	return nodes
}

// lowerStmt transforms a single AST statement into IR node(s).
func (l *Lowerer) lowerStmt(stmt ast.Node) []ir.Node {
	switch s := stmt.(type) {
	case *ast.ReturnStmt:
		ret := &ir.ReturnStmt{}
		if s.Value != nil {
			ret.Values = []ir.Expr{l.lowerExpr(s.Value)}
		}

		return []ir.Node{ret}

	case *ast.IfStmt:
		ifNode := &ir.IfStmt{
			Cond: l.lowerExpr(s.Condition),
			Then: l.lowerBody(s.Then),
			Else: l.lowerBody(s.Else),
		}

		return []ir.Node{ifNode}

	case *ast.ForStmt:
		forNode := &ir.ForStmt{
			Body: l.lowerBody(s.Body),
		}
		if s.Condition != nil {
			forNode.Cond = l.lowerExpr(s.Condition)
		}

		if s.Post != nil {
			forNode.Post = l.lowerExpr(s.Post)
		}

		return []ir.Node{forNode}

	case *ast.RangeForStmt:
		return []ir.Node{&ir.RangeStmt{
			Value: s.VarName,
			Range: l.lowerExpr(s.Range),
			Body:  l.lowerBody(s.Body),
		}}

	case *ast.WhileStmt:
		return []ir.Node{&ir.ForStmt{
			Cond: l.lowerExpr(s.Condition),
			Body: l.lowerBody(s.Body),
		}}

	case *ast.DoWhileStmt:
		// do-while → for { ... if !cond { break } }
		body := l.lowerBody(s.Body)
		body = append(body, &ir.IfStmt{
			Cond: &ir.UnaryExpr{Op: "!", Operand: l.lowerExpr(s.Condition), Prefix: true},
			Then: []ir.Node{&ir.BranchStmt{Kind: "break"}},
		})

		return []ir.Node{&ir.ForStmt{Body: body}}

	case *ast.SwitchStmt:
		switchNode := &ir.SwitchStmt{
			Tag: l.lowerExpr(s.Condition),
		}
		for _, c := range s.Cases {
			cc := &ir.CaseClause{
				Default: c.Default,
				Body:    l.lowerBody(c.Body),
			}
			if c.Value != nil {
				cc.Values = []ir.Expr{l.lowerExpr(c.Value)}
			}

			switchNode.Cases = append(switchNode.Cases, cc)
		}

		return []ir.Node{switchNode}

	case *ast.TryBlock:
		return l.lowerTryCatch(s)

	case *ast.ThrowExpr:
		// throw → return error
		if s.Value != nil {
			return []ir.Node{&ir.ReturnStmt{
				Values: []ir.Expr{
					&ir.CallExpr{Func: "fmt.Errorf", Args: []ir.Expr{
						&ir.LiteralExpr{Kind: "string", Value: `"%v"`},
						l.lowerExpr(s.Value),
					}},
				},
			}}
		}

		return []ir.Node{&ir.ReturnStmt{
			Values: []ir.Expr{&ir.IdentExpr{Name: "err"}},
		}}

	case *ast.Variable:
		return []ir.Node{l.lowerVariable(s)}

	case *ast.BreakStmt:
		return []ir.Node{&ir.BranchStmt{Kind: "break"}}

	case *ast.ContinueStmt:
		return []ir.Node{&ir.BranchStmt{Kind: "continue"}}

	case *ast.ExprStmt:
		return []ir.Node{&ir.ExprStmt{Expr: l.lowerExpr(s.Expr)}}

	case *ast.RawStmt:
		return []ir.Node{&ir.RawStmt{Text: s.Text}}

	case *ast.GotoStmt:
		return []ir.Node{&ir.GotoStmt{Label: s.Label}}

	case *ast.LabelStmt:
		ls := &ir.LabelStmt{Label: s.Label}
		if s.Stmt != nil {
			stmts := l.lowerStmt(s.Stmt)
			if len(stmts) > 0 {
				ls.Stmt = stmts[0]
			}
		}

		return []ir.Node{ls}

	default:
		return []ir.Node{&ir.RawStmt{Text: fmt.Sprintf("// unsupported statement: %T", stmt)}}
	}
}

// lowerTryCatch transforms try/catch into Go error handling patterns.
func (l *Lowerer) lowerTryCatch(tb *ast.TryBlock) []ir.Node {
	var nodes []ir.Node

	// Each statement in the try body becomes a potential error check
	for _, stmt := range tb.Body {
		lowered := l.lowerStmt(stmt)
		nodes = append(nodes, lowered...)
	}

	// Add a comment about the original catch blocks
	for _, catch := range tb.Catches {
		comment := "// catch"
		if catch.ParamType != nil {
			comment += " (" + catch.ParamType.Name + ")"
		} else {
			comment += " (...)"
		}

		nodes = append(nodes, &ir.RawStmt{Text: comment})
	}

	return nodes
}

// lowerExpr transforms a C++ AST expression into an IR expression.
func (l *Lowerer) lowerExpr(expr ast.Expr) ir.Expr {
	if expr == nil {
		return &ir.IdentExpr{Name: "nil"}
	}

	switch e := expr.(type) {
	case *ast.Literal:
		return l.lowerLiteral(e)

	case *ast.Identifier:
		return &ir.IdentExpr{Name: e.Name}

	case *ast.BinaryExpr:
		return &ir.BinaryExpr{
			Left:  l.lowerExpr(e.Left),
			Op:    e.Operator,
			Right: l.lowerExpr(e.Right),
		}

	case *ast.UnaryExpr:
		return &ir.UnaryExpr{
			Op:      e.Operator,
			Operand: l.lowerExpr(e.Operand),
			Prefix:  e.Prefix,
		}

	case *ast.CallExpr:
		return l.lowerCallExpr(e)

	case *ast.MemberExpr:
		return &ir.SelectorExpr{
			X:   l.lowerExpr(e.Object),
			Sel: e.Member,
		}

	case *ast.ScopeExpr:
		return l.lowerScopeExpr(e)

	case *ast.IndexExpr:
		return &ir.IndexExpr{
			X:     l.lowerExpr(e.Object),
			Index: l.lowerExpr(e.Index),
		}

	case *ast.Assignment:
		// Assignment expressions become statements upstream
		return &ir.RawExpr{Text: "/* assignment */"}

	case *ast.NewExpr:
		// new T(args) → &T{} or constructor call
		return &ir.AddressExpr{X: &ir.CompositeLitExpr{
			Type: l.lowerType(e.Type),
		}}

	case *ast.DeleteExpr:
		// delete → no-op in Go (GC handles it)
		return &ir.RawExpr{Text: "/* delete (GC-managed) */"}

	case *ast.CastExpr:
		return l.lowerCast(e)

	case *ast.LambdaExpr:
		return l.lowerLambda(e)

	case *ast.RawExpr:
		return &ir.RawExpr{Text: e.Text}

	default:
		return &ir.RawExpr{Text: fmt.Sprintf("/* unsupported expr: %T */", expr)}
	}
}

// lowerLiteral transforms a C++ literal into an IR literal.
func (l *Lowerer) lowerLiteral(lit *ast.Literal) ir.Expr {
	kind := lit.Kind
	value := lit.Value

	switch kind {
	case "nullptr":
		return &ir.IdentExpr{Name: "nil"}
	case "char":
		kind = "string" // Go uses rune/byte, simplified to string
	}

	return &ir.LiteralExpr{Kind: kind, Value: value}
}

// lowerCallExpr transforms a function call, handling std:: patterns.
func (l *Lowerer) lowerCallExpr(call *ast.CallExpr) ir.Expr {
	var args []ir.Expr
	for _, a := range call.Args {
		args = append(args, l.lowerExpr(a))
	}

	// Handle member function calls (method calls)
	if member, ok := call.Func.(*ast.MemberExpr); ok {
		return &ir.MethodCallExpr{
			Receiver: l.lowerExpr(member.Object),
			Method:   member.Member,
			Args:     args,
		}
	}

	// Handle scope resolution (std::cout, std::sort, etc.)
	if scope, ok := call.Func.(*ast.ScopeExpr); ok {
		mapped := l.mapStdFunction(scope.Scope, scope.Name)
		return &ir.CallExpr{Func: mapped, Args: args}
	}

	funcName := ""
	if ident, ok := call.Func.(*ast.Identifier); ok {
		funcName = ident.Name
	}

	return &ir.CallExpr{Func: funcName, Args: args}
}

// lowerScopeExpr maps C++ scope resolution to Go equivalents.
func (l *Lowerer) lowerScopeExpr(se *ast.ScopeExpr) ir.Expr {
	mapped := l.mapStdFunction(se.Scope, se.Name)
	return &ir.IdentExpr{Name: mapped}
}

// mapStdFunction maps std:: functions/objects to Go equivalents.
func (l *Lowerer) mapStdFunction(scope, name string) string {
	if scope == "std" {
		switch name {
		case "cout":
			return "fmt.Print"
		case "cerr":
			return "fmt.Fprint(os.Stderr, "
		case "endl":
			return `"\n"`
		case "sort":
			return "sort.Slice"
		case "make_unique", "make_shared":
			return "new"
		case "move":
			return "" // no-op in Go
		case "to_string":
			return "fmt.Sprint"
		case "stoi":
			return "strconv.Atoi"
		case "stof", "stod":
			return "strconv.ParseFloat"
		case "min":
			return "min"
		case "max":
			return "max"
		case "abs":
			return "math.Abs"
		case "swap":
			return "/* swap */"
		case "find":
			return "slices.Index"
		case "begin", "end":
			return "" // iterators don't exist in Go
		case "lock_guard", "unique_lock":
			return "sync.Mutex"
		case "thread":
			return "go"
		case "async":
			return "go"
		case "this_thread::sleep_for":
			return "time.Sleep"
		default:
			return "std." + name
		}
	}

	return scope + "." + name
}

// lowerCast transforms C++ casts into Go type conversions.
func (l *Lowerer) lowerCast(cast *ast.CastExpr) ir.Expr {
	target := l.lowerType(cast.Type)

	return &ir.CallExpr{
		Func: target.Name,
		Args: []ir.Expr{l.lowerExpr(cast.Operand)},
	}
}

// lowerLambda transforms a C++ lambda into a Go function literal.
func (l *Lowerer) lowerLambda(lambda *ast.LambdaExpr) ir.Expr {
	fn := &ir.FuncLitExpr{}

	for _, p := range lambda.Params {
		fn.Params = append(fn.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: l.lowerType(p.Type),
		})
	}

	if lambda.ReturnType != nil && lambda.ReturnType.Name != "void" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{
			Type: l.lowerType(lambda.ReturnType),
		})
	}

	fn.Body = l.lowerBody(lambda.Body)

	return fn
}

// lowerType transforms a C++ TypeRef into an IR TypeRef.
func (l *Lowerer) lowerType(t *ast.TypeRef) *ir.TypeRef {
	if t == nil {
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "any"}
	}

	// Map std:: container types
	fullName := t.Name
	switch fullName {
	case "std::vector", "vector":
		elem := &ir.TypeRef{Kind: ir.KindPrimitive, Name: "any"}
		if len(t.TemplateArgs) > 0 {
			elem = l.lowerType(t.TemplateArgs[0])
		}

		return &ir.TypeRef{Kind: ir.KindSlice, Name: "[]" + elem.Name, ElemType: elem}

	case "std::map", "std::unordered_map", "map", "unordered_map":
		key := &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}
		val := &ir.TypeRef{Kind: ir.KindPrimitive, Name: "any"}

		if len(t.TemplateArgs) > 0 {
			key = l.lowerType(t.TemplateArgs[0])
		}

		if len(t.TemplateArgs) > 1 {
			val = l.lowerType(t.TemplateArgs[1])
		}

		return &ir.TypeRef{Kind: ir.KindMap, Name: "map[" + key.Name + "]" + val.Name, KeyType: key, ValType: val}

	case "std::set", "std::unordered_set", "set", "unordered_set":
		elem := &ir.TypeRef{Kind: ir.KindPrimitive, Name: "any"}
		if len(t.TemplateArgs) > 0 {
			elem = l.lowerType(t.TemplateArgs[0])
		}

		return &ir.TypeRef{Kind: ir.KindMap, Name: "map[" + elem.Name + "]struct{}", KeyType: elem}

	case "std::string", "string":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}

	case "std::unique_ptr", "std::shared_ptr", "unique_ptr", "shared_ptr":
		elem := &ir.TypeRef{Kind: ir.KindPrimitive, Name: "any"}
		if len(t.TemplateArgs) > 0 {
			elem = l.lowerType(t.TemplateArgs[0])
		}

		return &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + elem.Name, ElemType: elem}

	case "std::optional", "optional":
		elem := &ir.TypeRef{Kind: ir.KindPrimitive, Name: "any"}
		if len(t.TemplateArgs) > 0 {
			elem = l.lowerType(t.TemplateArgs[0])
		}

		return &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + elem.Name, ElemType: elem}

	case "std::pair", "pair":
		return &ir.TypeRef{Kind: ir.KindStruct, Name: "struct{ First, Second any }"}

	case "std::tuple", "tuple":
		return &ir.TypeRef{Kind: ir.KindStruct, Name: "struct{ /* tuple fields */ }"}

	case "std::function", "function":
		return &ir.TypeRef{Kind: ir.KindFunc, Name: "func()"}

	case "std::mutex", "mutex":
		return &ir.TypeRef{Kind: ir.KindStruct, Name: "sync.Mutex"}

	case "std::atomic", "atomic":
		return &ir.TypeRef{Kind: ir.KindStruct, Name: "atomic.Value"}

	case "std::thread", "thread":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "/* goroutine */"}
	}

	// Map C++ primitive types
	mapped := mapPrimitiveType(fullName)
	if mapped != fullName {
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: mapped}
	}

	// Pointer
	if t.Pointer {
		inner := &ir.TypeRef{Kind: ir.KindPrimitive, Name: fullName}
		return &ir.TypeRef{Kind: ir.KindPointer, Name: "*" + fullName, ElemType: inner}
	}

	// Reference (treated as value in Go)
	if t.Reference || t.RValueRef {
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: mapPrimitiveType(fullName)}
	}

	return &ir.TypeRef{Kind: ir.KindPrimitive, Name: fullName}
}

// mapPrimitiveType maps C++ primitive types to Go types.
func mapPrimitiveType(name string) string {
	switch name {
	case "int", "int32_t":
		return "int"
	case "long", "int64_t", "long int":
		return "int64"
	case "short", "int16_t":
		return "int16"
	case "unsigned int", "uint32_t", "size_t":
		return "uint"
	case "unsigned long", "uint64_t":
		return "uint64"
	case "unsigned short", "uint16_t":
		return "uint16"
	case "char", "int8_t":
		return "byte"
	case "unsigned char", "uint8_t":
		return "byte"
	case "wchar_t", "char16_t", "char32_t":
		return "rune"
	case "float":
		return "float32"
	case "double", "long double":
		return "float64"
	case "bool":
		return "bool"
	case "void":
		return ""
	case "auto":
		return "any"
	case "nullptr_t":
		return "any"
	case "ptrdiff_t":
		return "int"
	case "ssize_t":
		return "int"
	case "intptr_t":
		return "int"
	case "uintptr_t":
		return "uintptr"
	case "FILE":
		return "*os.File"
	default:
		return name
	}
}

// operatorMethodName maps C++ operator symbols to Go method names.
func operatorMethodName(op string) string {
	switch op {
	case "+":
		return "Add"
	case "-":
		return "Sub"
	case "*":
		return "Mul"
	case "/":
		return "Div"
	case "%":
		return "Mod"
	case "==":
		return "Equal"
	case "!=":
		return "NotEqual"
	case "<":
		return "Less"
	case "<=":
		return "LessEqual"
	case ">":
		return "Greater"
	case ">=":
		return "GreaterEqual"
	case "<<":
		return "String" // common for ostream operator<<
	case ">>":
		return "Read"
	case "[]":
		return "At"
	case "()":
		return "Call"
	case "++":
		return "Inc"
	case "--":
		return "Dec"
	case "!":
		return "Not"
	case "~":
		return "Complement"
	case "&":
		return "BitAnd"
	case "|":
		return "BitOr"
	case "^":
		return "BitXor"
	case "=":
		return "Set"
	case "+=":
		return "AddAssign"
	case "-=":
		return "SubAssign"
	default:
		return "Op" + strings.ReplaceAll(op, " ", "")
	}
}

// exportName converts a C++ name to Go exported (PascalCase) convention.
func exportName(name string) string {
	if name == "" {
		return name
	}

	// Handle snake_case
	parts := strings.Split(name, "_")

	var result strings.Builder

	for _, part := range parts {
		if part == "" {
			continue
		}

		result.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}

	if result.Len() == 0 {
		return name
	}

	return result.String()
}
