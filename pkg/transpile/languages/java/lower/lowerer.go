// Package lower transforms Java javamodel AST into language-agnostic IR.
//
// Structure mirrors internal/languages/python/lower/lowerer.go byte-for-byte:
// a stateless Lowerer with a deterministic (sorted-key) import pass and a
// node dispatch. The D-01 core construct set (class, interface, abstract,
// enum, constructor, generics, throws, try/catch, try-with-resources, static)
// lowers to structured IR; the D-02/D-08 advanced set degrades to
// ir.RawStmt/ir.RawExpr (never a silent Raw for a DEGRADED D-01 core
// construct — see 06-01-FIDELITY.md; all three core constructs verified
// PRESERVED, so no escalation applies).
package lower

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/javamodel"
)

// Lowerer transforms a Java javamodel.Module into an ir.Module.
type Lowerer struct{}

// NewLowerer creates a new Java AST-to-IR lowerer.
func NewLowerer() *Lowerer {
	return &Lowerer{}
}

// Lower transforms a javamodel.Module into an IR Module.
func (l *Lowerer) Lower(mod *javamodel.Module) (*ir.Module, error) {
	if mod == nil {
		return nil, fmt.Errorf("lower: nil javamodel.Module")
	}

	irMod := &ir.Module{
		PackageName: packageName(mod.FileName),
		SourceFile:  mod.FileName,
	}

	// Map Java imports to Go imports, then emit in sorted-key order
	// (Pitfall 1 / D-07 / SC2 — load-bearing determinism guard).
	imports := make(map[string]*ir.Import)
	for _, imp := range mod.Imports {
		l.mapImport(imp, imports)
	}

	keys := make([]string, 0, len(imports))
	for k := range imports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		irMod.Imports = append(irMod.Imports, imports[k])
	}

	for _, node := range mod.Types {
		irMod.Decls = append(irMod.Decls, l.lowerNode(node, "")...)
	}

	return irMod, nil
}

// packageName derives a Go package name from a Java filename.
func packageName(filename string) string {
	name := filename
	if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
		name = name[idx+1:]
	}
	name = strings.TrimSuffix(name, ".java")
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ToLower(name)
	if name == "" {
		return "main"
	}
	return name
}

// mapImport maps a Java import node to Go imports. Java FQN top-segment
// drives a small, deterministic standard-library mapping (CLAUDE.md
// Java->Go table); unknown packages are intentionally dropped (the host
// LLM fallback resolves third-party deps — D-08).
func (l *Lowerer) mapImport(node *javamodel.Node, imports map[string]*ir.Import) {
	if node == nil {
		return
	}
	name := node.Name
	if name == "" {
		name = node.Value
	}
	name = strings.TrimPrefix(name, "static ")

	switch {
	case strings.HasPrefix(name, "java.util.concurrent"):
		imports["sync"] = &ir.Import{Path: "sync"}
	case strings.HasPrefix(name, "java.util.regex"):
		imports["regexp"] = &ir.Import{Path: "regexp"}
	case strings.HasPrefix(name, "java.util"):
		// collections map to builtin Go types; no import needed
	case strings.HasPrefix(name, "java.io"), strings.HasPrefix(name, "java.nio"):
		imports["io"] = &ir.Import{Path: "io"}
	case strings.HasPrefix(name, "java.time"):
		imports["time"] = &ir.Import{Path: "time"}
	case strings.HasPrefix(name, "java.math"):
		imports["math/big"] = &ir.Import{Path: "math/big"}
	case strings.HasPrefix(name, "java.net"):
		imports["net"] = &ir.Import{Path: "net"}
	case strings.HasPrefix(name, "java.security"), strings.HasPrefix(name, "javax.crypto"):
		imports["crypto"] = &ir.Import{Path: "crypto"}
	case strings.HasPrefix(name, "java.lang"):
		// java.lang.* is implicit; nothing to import
	}
}

// lowerNode transforms a javamodel.Node into IR nodes. typeName is
// non-empty when lowering inside a type body (drives receiver naming).
func (l *Lowerer) lowerNode(node *javamodel.Node, typeName string) []ir.Node {
	if node == nil {
		return nil
	}

	switch node.Type {
	case javamodel.NodeClass:
		if hasModifier(node, "abstract") {
			return l.lowerAbstractClass(node)
		}
		return l.lowerClass(node)
	case javamodel.NodeInterface:
		return l.lowerInterface(node)
	case javamodel.NodeEnum:
		return l.lowerEnum(node)
	case javamodel.NodeRecord:
		// Records: trivial data carriers lower like structs; complex ones
		// (compact constructors etc.) fall through to struct + Raw bodies.
		return l.lowerClass(node)
	case javamodel.NodeConstructor:
		return []ir.Node{l.lowerConstructor(node, typeName)}
	case javamodel.NodeMethod:
		return []ir.Node{l.lowerMethod(node, typeName)}
	case javamodel.NodeField:
		if fd := l.lowerFieldDecl(node); fd != nil {
			return []ir.Node{&ir.VarDecl{Name: fd.Name, Type: fd.Type}}
		}
		return nil
	case javamodel.NodeReturn:
		return l.lowerReturn(node)
	case javamodel.NodeBreak:
		return []ir.Node{&ir.BranchStmt{Kind: "break"}}
	case javamodel.NodeContinue:
		return []ir.Node{&ir.BranchStmt{Kind: "continue"}}
	case javamodel.NodeTry:
		return l.lowerTry(node)
	case javamodel.NodeCall, javamodel.NodeExpr, javamodel.NodeAssign:
		return []ir.Node{&ir.ExprStmt{Expr: &ir.RawExpr{Text: javaExprToGo(nodeText(node))}}}
	case javamodel.NodeIf:
		return []ir.Node{l.lowerIf(node)}
	case javamodel.NodeWhile, javamodel.NodeDoWhile:
		return []ir.Node{l.lowerWhile(node)}
	case javamodel.NodeForEach:
		return []ir.Node{l.lowerForEach(node)}
	case javamodel.NodeFor, javamodel.NodeSwitch,
		javamodel.NodeThrow, javamodel.NodeBlock:
		// Classic for / switch / throw not yet structured — preserved
		// verbatim (lossless) for LLM refinement.
		return []ir.Node{&ir.RawStmt{Text: nodeText(node), Comment: fmt.Sprintf("Java %s statement", node.Type)}}
	default:
		// D-02/D-08 advanced set (lambdas, annotation-as-behavior,
		// anonymous/inner classes, ...) -> Raw. NOT a silent Raw for a
		// D-01 core construct: all three core constructs are PRESERVED
		// (06-01-FIDELITY.md), so no escalation applies.
		return []ir.Node{&ir.RawStmt{Text: nodeText(node), Comment: fmt.Sprintf("unsupported (advanced): %s", node.Type)}}
	}
}

// lowerClass transforms a Java class into an IR struct + methods.
func (l *Lowerer) lowerClass(node *javamodel.Node) []ir.Node {
	name := exportName(node.Name)
	td := &ir.TypeDecl{
		Kind:       ir.TypeDeclStruct,
		Name:       name,
		TypeParams: copyStrings(node.TypeParams),
	}

	if node.Extends != "" {
		td.Embedded = append(td.Embedded, exportName(node.Extends))
	}
	for _, iface := range node.Implements {
		td.Embedded = append(td.Embedded, exportName(iface))
	}

	var methods, ctors []*javamodel.Node
	for _, child := range node.Children {
		switch child.Type {
		case javamodel.NodeField:
			if fd := l.lowerFieldDecl(child); fd != nil {
				td.Fields = append(td.Fields, fd)
			}
		case javamodel.NodeMethod:
			methods = append(methods, child)
		case javamodel.NodeConstructor:
			ctors = append(ctors, child)
		}
	}

	for _, m := range methods {
		if !hasModifier(m, "static") {
			td.Methods = append(td.Methods, l.lowerMethod(m, name))
		}
	}

	nodes := []ir.Node{td}
	for _, c := range ctors {
		nodes = append(nodes, l.lowerConstructor(c, name))
	}
	for _, m := range methods {
		if hasModifier(m, "static") {
			nodes = append(nodes, l.lowerMethod(m, ""))
		}
	}
	return nodes
}

// lowerAbstractClass transforms a Java abstract class into an interface
// (abstract API surface) plus a struct (shared state) — CLAUDE.md table.
func (l *Lowerer) lowerAbstractClass(node *javamodel.Node) []ir.Node {
	name := exportName(node.Name)

	iface := &ir.TypeDecl{
		Kind:       ir.TypeDeclInterface,
		Name:       name,
		TypeParams: copyStrings(node.TypeParams),
	}
	st := &ir.TypeDecl{
		Kind:       ir.TypeDeclStruct,
		Name:       name + "Base",
		TypeParams: copyStrings(node.TypeParams),
	}

	var methods []*javamodel.Node
	for _, child := range node.Children {
		switch child.Type {
		case javamodel.NodeField:
			if fd := l.lowerFieldDecl(child); fd != nil {
				st.Fields = append(st.Fields, fd)
			}
		case javamodel.NodeMethod:
			methods = append(methods, child)
		}
	}

	nodes := []ir.Node{iface, st}
	for _, m := range methods {
		fn := l.lowerMethod(m, name+"Base")
		fn.Receiver = nil // interface signature
		fnSig := &ir.FuncDecl{Name: fn.Name, Params: fn.Params, Returns: fn.Returns, TypeParams: fn.TypeParams}
		iface.Methods = append(iface.Methods, fnSig)
	}
	return nodes
}

// lowerInterface transforms a Java interface into an IR interface type.
func (l *Lowerer) lowerInterface(node *javamodel.Node) []ir.Node {
	td := &ir.TypeDecl{
		Kind:       ir.TypeDeclInterface,
		Name:       exportName(node.Name),
		TypeParams: copyStrings(node.TypeParams),
	}
	for _, iface := range node.Implements {
		td.Embedded = append(td.Embedded, exportName(iface))
	}
	if node.Extends != "" {
		td.Embedded = append(td.Embedded, exportName(node.Extends))
	}

	for _, child := range node.Children {
		if child.Type != javamodel.NodeMethod {
			continue
		}
		fn := l.lowerMethod(child, "")
		fn.Receiver = nil
		fn.Body = nil
		td.Methods = append(td.Methods, fn)
	}
	return []ir.Node{td}
}

// lowerEnum transforms a Java enum into an IR enum type (const + iota).
func (l *Lowerer) lowerEnum(node *javamodel.Node) []ir.Node {
	name := exportName(node.Name)
	td := &ir.TypeDecl{
		Kind: ir.TypeDeclEnum,
		Name: name,
	}
	for _, child := range node.Children {
		if child.Type == javamodel.NodeField {
			td.Values = append(td.Values, &ir.EnumVal{
				Name:  name + exportName(child.Name),
				Value: child.Value,
			})
		}
	}
	return []ir.Node{td}
}

// lowerConstructor converts a Java constructor to a NewX() factory.
func (l *Lowerer) lowerConstructor(node *javamodel.Node, typeName string) *ir.FuncDecl {
	if typeName == "" {
		typeName = exportName(node.Name)
	}
	fn := &ir.FuncDecl{
		Name:       "New" + exportName(typeName),
		TypeParams: copyStrings(node.TypeParams),
	}
	for _, p := range node.Params {
		fn.Params = append(fn.Params, &ir.ParamDecl{Name: p.Name, Type: mapJavaType(p.Type)})
	}
	fn.Returns = append(fn.Returns, &ir.ParamDecl{
		Type: &ir.TypeRef{Kind: ir.KindPointer, ElemType: &ir.TypeRef{Kind: ir.KindStruct, Name: exportName(typeName)}},
	})
	l.applyThrows(node, fn)
	fn.Body = l.lowerBody(node)

	if fn.Receiver != nil {
		rewriteThis(fn.Body, fn.Receiver.Name)
	}

	return fn
}

// lowerMethod transforms a Java method into an IR FuncDecl. An empty
// typeName produces a package-level function (static methods / interface
// signatures); a non-empty typeName attaches a pointer receiver.
func (l *Lowerer) lowerMethod(node *javamodel.Node, typeName string) *ir.FuncDecl {
	fn := &ir.FuncDecl{
		Name:       exportName(node.Name),
		TypeParams: copyStrings(node.TypeParams),
	}

	if typeName != "" {
		fn.Receiver = &ir.ParamDecl{
			Name: strings.ToLower(typeName[:1]),
			Type: &ir.TypeRef{Kind: ir.KindPointer, ElemType: &ir.TypeRef{Kind: ir.KindStruct, Name: typeName}},
		}
	}

	for _, p := range node.Params {
		pd := &ir.ParamDecl{Name: p.Name, Type: mapJavaType(p.Type)}
		if p.IsVarargs {
			pd.Type = &ir.TypeRef{Kind: ir.KindSlice, ElemType: mapJavaType(p.Type)}
		}
		fn.Params = append(fn.Params, pd)
	}

	if rt := node.Metadata["return_type"]; rt != "" && rt != "void" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{Type: mapJavaType(rt)})
	}

	l.applyThrows(node, fn)
	fn.Body = l.lowerBody(node)

	if fn.Receiver != nil {
		rewriteThis(fn.Body, fn.Receiver.Name)
	}

	return fn
}

// applyThrows appends a trailing Go error return when the Java method
// declares a throws clause (CLAUDE.md: throws -> error return). The
// throws clause is PRESERVED in Metadata["throws"] (06-01-FIDELITY.md).
func (l *Lowerer) applyThrows(node *javamodel.Node, fn *ir.FuncDecl) {
	if node.Metadata == nil {
		return
	}
	if t := node.Metadata["throws"]; t != "" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{
			Type: &ir.TypeRef{Kind: ir.KindInterface, Name: "error"},
		})
	}
}

// lowerBody lowers a method/constructor body, recursing into children.
func (l *Lowerer) lowerBody(node *javamodel.Node) []ir.Node {
	var body []ir.Node
	for _, child := range node.Children {
		body = append(body, l.lowerNode(child, "")...)
	}
	if len(body) == 0 && node.Value != "" {
		body = append(body, &ir.RawStmt{Text: node.Value})
	}
	return body
}

// lowerReturn transforms a return statement.
func (l *Lowerer) lowerReturn(node *javamodel.Node) []ir.Node {
	var values []ir.Expr
	if node.Value != "" {
		values = append(values, &ir.RawExpr{Text: javaExprToGo(node.Value)})
	}
	return []ir.Node{&ir.ReturnStmt{Values: values}}
}

// lowerStmtBody lowers a slice of structured child statements.
func (l *Lowerer) lowerStmtBody(children []*javamodel.Node) []ir.Node {
	var body []ir.Node
	for _, c := range children {
		body = append(body, l.lowerNode(c, "")...)
	}
	return body
}

// lowerIf transforms a structured Java if/else-if/else chain into ir.IfStmt.
func (l *Lowerer) lowerIf(node *javamodel.Node) ir.Node {
	stmt := &ir.IfStmt{
		Cond: &ir.RawExpr{Text: javaExprToGo(node.Cond)},
		Then: l.lowerStmtBody(node.Children),
	}

	if len(node.Orelse) == 1 && node.Orelse[0].Type == javamodel.NodeIf {
		stmt.Else = []ir.Node{l.lowerIf(node.Orelse[0])}
	} else if len(node.Orelse) > 0 {
		stmt.Else = l.lowerStmtBody(node.Orelse)
	}

	return stmt
}

// lowerWhile transforms while / do-while into a condition-only ir.ForStmt.
func (l *Lowerer) lowerWhile(node *javamodel.Node) ir.Node {
	return &ir.ForStmt{
		Cond: &ir.RawExpr{Text: javaExprToGo(node.Cond)},
		Body: l.lowerStmtBody(node.Children),
	}
}

// lowerForEach transforms `for (T x : coll)` into an ir.RangeStmt.
func (l *Lowerer) lowerForEach(node *javamodel.Node) ir.Node {
	val := node.Target
	if i := strings.LastIndexAny(val, " \t"); i >= 0 {
		val = val[i+1:] // drop the declared type, keep the var name
	}

	return &ir.RangeStmt{
		Key:   "_",
		Value: strings.TrimSpace(val),
		Range: &ir.RawExpr{Text: javaExprToGo(node.Cond)},
		Body:  l.lowerStmtBody(node.Children),
	}
}

// javaThisRe matches the Java implicit receiver `this` as a whole word.
var javaThisRe = regexp.MustCompile(`\bthis\b`)
var javaNullRe = regexp.MustCompile(`\bnull\b`)

// javaExprToGo applies conservative Java→Go expression normalization.
// Java is C-family so &&/||/!/==/!= already match Go; only `null`→`nil`
// is unconditional here (`this`→receiver is a body-scoped post-pass).
func javaExprToGo(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	return javaNullRe.ReplaceAllString(s, "nil")
}

// rewriteThis replaces `this` with the Go receiver name throughout a method
// body (mirrors the Python self→receiver pass).
func rewriteThis(nodes []ir.Node, recv string) {
	if recv == "" {
		return
	}

	for _, n := range nodes {
		switch s := n.(type) {
		case *ir.RawStmt:
			s.Text = javaThisRe.ReplaceAllString(s.Text, recv)
		case *ir.ExprStmt:
			rewriteThisExpr(s.Expr, recv)
		case *ir.ReturnStmt:
			for _, e := range s.Values {
				rewriteThisExpr(e, recv)
			}
		case *ir.IfStmt:
			rewriteThisExpr(s.Cond, recv)
			rewriteThis(s.Then, recv)
			rewriteThis(s.Else, recv)
		case *ir.ForStmt:
			rewriteThisExpr(s.Cond, recv)
			rewriteThis(s.Body, recv)
		case *ir.RangeStmt:
			rewriteThisExpr(s.Range, recv)
			rewriteThis(s.Body, recv)
		}
	}
}

func rewriteThisExpr(e ir.Expr, recv string) {
	if r, ok := e.(*ir.RawExpr); ok {
		r.Text = javaThisRe.ReplaceAllString(r.Text, recv)
	}
}

// lowerTry maps Java try forms to Go idioms:
//   - try-with-resources -> ir.DeferStmt (resource close) + raw body
//     (CLAUDE.md: try-with-resources -> defer)
//   - try/catch -> ir.ErrorHandling (CLAUDE.md: try/catch -> if err != nil)
//
// The resource / body text is PRESERVED verbatim in node.Value
// (06-01-FIDELITY.md: try-with-resources=PRESERVED), so no information is
// lost — this is NOT a silent Raw fallback for a degraded core construct.
func (l *Lowerer) lowerTry(node *javamodel.Node) []ir.Node {
	if isTryWithResources(node) {
		res := ""
		if node.Metadata != nil {
			res = node.Metadata["resources"]
		}
		return []ir.Node{
			&ir.DeferStmt{Call: &ir.RawExpr{Text: closeCallFor(res)}},
			&ir.RawStmt{Text: nodeText(node), Comment: "Java try-with-resources body"},
		}
	}
	return []ir.Node{
		&ir.ErrorHandling{
			Call:   &ir.RawExpr{Text: nodeText(node)},
			ErrVar: "err",
			Body:   []ir.Node{&ir.RawStmt{Text: "// translated from Java catch block"}},
		},
	}
}

// lowerFieldDecl creates an IR field from a javamodel field node.
func (l *Lowerer) lowerFieldDecl(node *javamodel.Node) *ir.FieldDecl {
	if node == nil || node.Name == "" {
		return nil
	}
	ft := ""
	if node.Metadata != nil {
		ft = node.Metadata["field_type"]
	}
	if ft == "" {
		ft = node.Value
	}
	return &ir.FieldDecl{
		Name: exportName(node.Name),
		Type: mapJavaType(ft),
	}
}

// --- Type mapping (CLAUDE.md "Key Type Mappings (Java -> Go)") ---

// mapJavaType converts a Java type string to an IR TypeRef.
func mapJavaType(t string) *ir.TypeRef {
	t = strings.TrimSpace(t)
	if t == "" {
		return &ir.TypeRef{Kind: ir.KindInterface, Name: "any"}
	}

	if i := strings.IndexByte(t, '<'); i >= 0 && strings.HasSuffix(t, ">") {
		outer := t[:i]
		inner := t[i+1 : len(t)-1]
		switch outer {
		case "List", "ArrayList", "LinkedList", "Collection", "Iterable":
			return &ir.TypeRef{Kind: ir.KindSlice, ElemType: mapJavaType(inner)}
		case "Set", "HashSet", "TreeSet", "LinkedHashSet":
			return &ir.TypeRef{Kind: ir.KindMap, KeyType: mapJavaType(inner), ValType: &ir.TypeRef{Kind: ir.KindStruct, Name: "struct{}"}}
		case "Map", "HashMap", "TreeMap", "LinkedHashMap":
			parts := splitGenericArgs(inner)
			if len(parts) == 2 {
				return &ir.TypeRef{Kind: ir.KindMap, KeyType: mapJavaType(parts[0]), ValType: mapJavaType(parts[1])}
			}
			return &ir.TypeRef{Kind: ir.KindMap, KeyType: mapJavaType("String"), ValType: mapJavaType("Object")}
		case "Optional":
			return &ir.TypeRef{Kind: ir.KindPointer, ElemType: mapJavaType(inner)}
		case "CompletableFuture", "Future":
			return &ir.TypeRef{Kind: ir.KindChannel, ElemType: mapJavaType(inner)}
		default:
			return &ir.TypeRef{Kind: ir.KindStruct, Name: exportName(outer)}
		}
	}

	switch t {
	case "String", "CharSequence":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}
	case "int", "Integer", "short", "Short", "byte", "Byte":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}
	case "long", "Long":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int64"}
	case "double", "Double", "float", "Float":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "float64"}
	case "boolean", "Boolean":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "bool"}
	case "char", "Character":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "rune"}
	case "void", "Void":
		return nil
	case "Object":
		return &ir.TypeRef{Kind: ir.KindInterface, Name: "any"}
	}

	if before, ok := strings.CutSuffix(t, "[]"); ok {
		return &ir.TypeRef{Kind: ir.KindSlice, ElemType: mapJavaType(before)}
	}

	return &ir.TypeRef{Kind: ir.KindStruct, Name: exportName(t)}
}

// splitGenericArgs splits "K, V" respecting nested angle brackets.
func splitGenericArgs(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(s[start:]))
	return parts
}

// --- Helpers ---

func hasModifier(node *javamodel.Node, mod string) bool {
	return slices.Contains(node.Modifiers, mod)
}

func isTryWithResources(node *javamodel.Node) bool {
	if node.Metadata != nil && node.Metadata["resources"] != "" {
		return true
	}
	v := strings.TrimSpace(node.Value)
	return strings.HasPrefix(v, "try (") || strings.HasPrefix(v, "try(")
}

func closeCallFor(resources string) string {
	resources = strings.TrimSpace(resources)
	if resources == "" {
		return "resource.Close()"
	}
	// "Reader r = open()" -> close the bound identifier.
	if i := strings.IndexByte(resources, '='); i > 0 {
		decl := strings.Fields(strings.TrimSpace(resources[:i]))
		if len(decl) > 0 {
			return decl[len(decl)-1] + ".Close()"
		}
	}
	return "resource.Close()"
}

func copyStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func exportName(name string) string {
	if name == "" {
		return ""
	}
	clean := strings.TrimLeft(name, "_")
	if clean == "" {
		return name
	}
	parts := strings.Split(clean, "_")
	var sb strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		sb.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	result := sb.String()
	if result == "" {
		return name
	}
	return result
}

func nodeText(node *javamodel.Node) string {
	if node.Value != "" {
		return node.Value
	}
	if node.Name != "" {
		return node.Name
	}
	return fmt.Sprintf("/* %s */", node.Type)
}
