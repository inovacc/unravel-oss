// Package lower transforms Python pymodel AST into language-agnostic IR.
package lower

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/ir"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/pymodel"
)

// Lowerer transforms a Python pymodel.Module into an ir.Module.
type Lowerer struct{}

// NewLowerer creates a new Python AST-to-IR lowerer.
func NewLowerer() *Lowerer {
	return &Lowerer{}
}

// Lower transforms a pymodel.Module into an IR Module.
func (l *Lowerer) Lower(mod *pymodel.Module) (*ir.Module, error) {
	pkg := packageName(mod.FileName)

	irMod := &ir.Module{
		PackageName: pkg,
		SourceFile:  mod.FileName,
	}

	// Map Python imports to Go imports
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

	// Lower body declarations
	for _, node := range mod.Body {
		lowered := l.lowerTopLevel(node)
		irMod.Decls = append(irMod.Decls, lowered...)
	}

	return irMod, nil
}

// packageName derives a Go package name from a Python filename.
func packageName(filename string) string {
	name := filename
	// Strip directory
	if idx := strings.LastIndexAny(name, "/\\"); idx >= 0 {
		name = name[idx+1:]
	}
	// Strip .py extension
	name = strings.TrimSuffix(name, ".py")
	// Sanitize
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ToLower(name)
	if name == "" || name == "__init__" || name == "__main__" {
		return "main"
	}
	return name
}

// mapImport maps a Python import node to Go imports.
func (l *Lowerer) mapImport(node *pymodel.Node, imports map[string]*ir.Import) {
	name := node.Name
	if name == "" {
		name = node.Value
	}
	// Extract top-level package
	if idx := strings.Index(name, "."); idx > 0 {
		name = name[:idx]
	}

	switch name {
	case "os", "sys", "pathlib":
		imports["os"] = &ir.Import{Path: "os"}
	case "json":
		imports["encoding/json"] = &ir.Import{Path: "encoding/json"}
	case "re":
		imports["regexp"] = &ir.Import{Path: "regexp"}
	case "math":
		imports["math"] = &ir.Import{Path: "math"}
	case "datetime":
		imports["time"] = &ir.Import{Path: "time"}
	case "time":
		imports["time"] = &ir.Import{Path: "time"}
	case "threading":
		imports["sync"] = &ir.Import{Path: "sync"}
	case "logging":
		imports["log/slog"] = &ir.Import{Path: "log/slog"}
	case "hashlib":
		imports["crypto"] = &ir.Import{Path: "crypto"}
	case "uuid":
		imports["github.com/google/uuid"] = &ir.Import{Path: "github.com/google/uuid"}
	case "collections":
		// built-in Go types
	case "dataclasses":
		// struct patterns, no import needed
	case "typing":
		// type system, no import needed
	case "enum":
		// const+iota pattern, no import needed
	case "abc":
		// interface pattern, no import needed
	case "__future__":
		// no equivalent
	case "fmt":
		imports["fmt"] = &ir.Import{Path: "fmt"}
	}
}

// lowerNode transforms a pymodel.Node into IR nodes.
// className is non-empty when lowering inside a class body.
func (l *Lowerer) lowerNode(node *pymodel.Node, className string) []ir.Node {
	switch node.Type {
	case pymodel.NodeClass:
		return l.lowerClass(node)
	case pymodel.NodeFunction:
		return []ir.Node{l.lowerFunction(node, className)}
	case pymodel.NodeAssign:
		return l.lowerAssign(node, className)
	case pymodel.NodeReturn:
		return l.lowerReturn(node)
	case pymodel.NodeExpr, pymodel.NodeCall:
		return []ir.Node{&ir.ExprStmt{Expr: &ir.RawExpr{Text: pyExprToGo(nodeText(node))}}}
	case pymodel.NodeIf:
		return []ir.Node{l.lowerIf(node, className)}
	case pymodel.NodeWhile:
		return []ir.Node{l.lowerWhile(node, className)}
	case pymodel.NodeFor:
		return []ir.Node{l.lowerFor(node, className)}
	case pymodel.NodeRaise:
		return []ir.Node{l.lowerRaise(node)}
	case pymodel.NodeTry, pymodel.NodeWith:
		return []ir.Node{&ir.RawStmt{Text: nodeText(node), Comment: fmt.Sprintf("Python %s statement", node.Type)}}
	case pymodel.NodePass:
		return []ir.Node{&ir.RawStmt{Text: "// pass"}}
	case pymodel.NodeComment:
		return []ir.Node{&ir.RawStmt{Text: "// " + node.Value}}
	default:
		return []ir.Node{&ir.RawStmt{Text: nodeText(node), Comment: fmt.Sprintf("unsupported: %s", node.Type)}}
	}
}

// lowerClass transforms a Python class into IR type declarations.
func (l *Lowerer) lowerClass(node *pymodel.Node) []ir.Node {
	var nodes []ir.Node
	name := exportName(node.Name)

	// Detect class kind from decorators and bases
	isDataclass := hasDecorator(node, "dataclass")
	isEnum := hasBase(node, "Enum")
	isABC := hasBase(node, "ABC") || hasBase(node, "ABCMeta")

	if isEnum {
		return l.lowerEnum(node, name)
	}

	if isABC {
		return l.lowerABCInterface(node, name)
	}

	td := &ir.TypeDecl{
		Kind: ir.TypeDeclStruct,
		Name: name,
	}

	// Bases → embedded types (skip common base classes)
	for _, meta := range node.Metadata {
		// bases are stored in metadata
		_ = meta
	}
	if bases := node.Metadata["bases"]; bases != "" {
		for part := range strings.SplitSeq(bases, ",") {
			base := strings.TrimSpace(part)
			if base != "" && base != "object" && base != "ABC" {
				td.Embedded = append(td.Embedded, exportName(base))
			}
		}
	}

	// Extract fields from children
	var methods []*pymodel.Node
	for _, child := range node.Children {
		switch child.Type {
		case pymodel.NodeAssign:
			if isDataclass || isFieldAssign(child) {
				fd := l.lowerFieldDecl(child)
				if fd != nil {
					td.Fields = append(td.Fields, fd)
				}
			}
		case pymodel.NodeFunction:
			methods = append(methods, child)
		}
	}

	nodes = append(nodes, td)

	// Lower methods
	for _, m := range methods {
		if m.Name == "__init__" {
			nodes = append(nodes, l.lowerInit(m, name, td.Fields))
		} else {
			fn := l.lowerFunction(m, name)
			nodes = append(nodes, fn)
		}
	}

	return nodes
}

// lowerEnum transforms a Python Enum class into IR enum type.
func (l *Lowerer) lowerEnum(node *pymodel.Node, name string) []ir.Node {
	td := &ir.TypeDecl{
		Kind: ir.TypeDeclEnum,
		Name: name,
	}

	for _, child := range node.Children {
		if child.Type == pymodel.NodeAssign && child.Name != "" {
			td.Values = append(td.Values, &ir.EnumVal{
				Name:  name + exportName(child.Name),
				Value: enumValue(child.Value),
			})
		}
	}

	return []ir.Node{td}
}

// enumValue normalizes a Python enum member RHS to a Go const value.
// `auto()` and string/auto values become "" so codegen falls back to the
// idiomatic `iota` sequence (Go enums are int); only an explicit integer
// literal is preserved. String-enum semantics are intentionally degraded to
// a deterministic, compilable int enum (LLM refinement can restore them).
func enumValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "auto()" {
		return ""
	}

	if _, err := strconv.Atoi(v); err == nil {
		return v
	}

	return ""
}

// lowerABCInterface transforms a Python ABC class into an IR interface.
func (l *Lowerer) lowerABCInterface(node *pymodel.Node, name string) []ir.Node {
	td := &ir.TypeDecl{
		Kind: ir.TypeDeclInterface,
		Name: name,
	}

	for _, child := range node.Children {
		if child.Type != pymodel.NodeFunction {
			continue
		}
		if child.Name == "__init__" {
			continue
		}

		fn := &ir.FuncDecl{
			Name: exportName(child.Name),
		}

		// Params (skip self)
		for _, p := range child.Params {
			if p.Name == "self" || p.Name == "cls" {
				continue
			}
			fn.Params = append(fn.Params, &ir.ParamDecl{
				Name: p.Name,
				Type: mapTypeHint(p.TypeHint),
			})
		}

		// Return type
		if rt := child.Metadata["return_type"]; rt != "" && rt != "None" {
			fn.Returns = append(fn.Returns, &ir.ParamDecl{
				Type: mapTypeHint(rt),
			})
		}

		td.Methods = append(td.Methods, fn)
	}

	return []ir.Node{td}
}

// lowerFunction transforms a Python function into an IR FuncDecl.
func (l *Lowerer) lowerFunction(node *pymodel.Node, className string) *ir.FuncDecl {
	goName := exportName(node.Name)

	// Dunder methods → Go-idiomatic names
	goName = mapDunderName(goName, node.Name)

	fn := &ir.FuncDecl{
		Name: goName,
	}

	// Set receiver for methods
	if className != "" {
		fn.Receiver = &ir.ParamDecl{
			Name: strings.ToLower(className[:1]),
			Type: &ir.TypeRef{Kind: ir.KindPointer, ElemType: &ir.TypeRef{Kind: ir.KindStruct, Name: className}},
		}
	}

	// Parameters (skip self/cls)
	for _, p := range node.Params {
		if p.Name == "self" || p.Name == "cls" {
			continue
		}
		pd := &ir.ParamDecl{
			Name: p.Name,
			Type: mapTypeHint(p.TypeHint),
		}
		if p.IsVariadic {
			pd.Type = &ir.TypeRef{Kind: ir.KindSlice, ElemType: mapTypeHint("")}
		}
		fn.Params = append(fn.Params, pd)
	}

	// Return type
	if rt := node.Metadata["return_type"]; rt != "" && rt != "None" {
		fn.Returns = append(fn.Returns, &ir.ParamDecl{
			Type: mapTypeHint(rt),
		})
	}

	// Body → lower each child statement
	for _, child := range node.Children {
		stmts := l.lowerNode(child, "")
		fn.Body = append(fn.Body, stmts...)
	}

	// If body is empty but node has a Value (raw body text), use RawStmt
	if len(fn.Body) == 0 && node.Value != "" {
		fn.Body = append(fn.Body, &ir.RawStmt{Text: node.Value})
	}

	// Rewrite the Python implicit receiver to the Go receiver name.
	if fn.Receiver != nil {
		rewriteSelf(fn.Body, fn.Receiver.Name)
	}

	// Resolve new-local vs rebind so the body compiles.
	declareLocals(fn.Body, map[string]bool{})

	return fn
}

// lowerInit converts __init__ to a NewX() factory function.
func (l *Lowerer) lowerInit(node *pymodel.Node, className string, fields []*ir.FieldDecl) *ir.FuncDecl {
	fn := &ir.FuncDecl{
		Name: "New" + className,
	}

	// Params (skip self)
	for _, p := range node.Params {
		if p.Name == "self" {
			continue
		}
		fn.Params = append(fn.Params, &ir.ParamDecl{
			Name: p.Name,
			Type: mapTypeHint(p.TypeHint),
		})
	}

	// Returns *ClassName
	fn.Returns = append(fn.Returns, &ir.ParamDecl{
		Type: &ir.TypeRef{Kind: ir.KindPointer, ElemType: &ir.TypeRef{Kind: ir.KindStruct, Name: className}},
	})

	// Body: raw init body (complex assignment patterns)
	if node.Value != "" {
		fn.Body = append(fn.Body, &ir.RawStmt{Text: node.Value})
	} else if len(node.Children) > 0 {
		for _, child := range node.Children {
			stmts := l.lowerNode(child, "")
			fn.Body = append(fn.Body, stmts...)
		}
	}

	return fn
}

// lowerTopLevel lowers a module-level declaration. Module-scope assignments
// become Go package vars/consts (`:=` is illegal at file scope); everything
// else defers to lowerNode.
func (l *Lowerer) lowerTopLevel(node *pymodel.Node) []ir.Node {
	if node.Type != pymodel.NodeAssign || node.Name == "" {
		return l.lowerNode(node, "")
	}

	return []ir.Node{&ir.VarDecl{
		Name:  node.Name,
		Type:  mapTypeHint(node.Metadata["type_hint"]),
		Value: &ir.RawExpr{Text: pyExprToGo(node.Value)},
		Const: isConstantName(node.Name),
	}}
}

// lowerAssign transforms an assignment used as a statement (function/loop/if
// body). It always emits a Go statement (never a VarDecl) — local
// new-vs-rebind is resolved later by declareLocals.
func (l *Lowerer) lowerAssign(node *pymodel.Node, _ string) []ir.Node {
	if node.Name != "" && node.Value != "" && node.Metadata["augmented"] == "" {
		return []ir.Node{&ir.RawStmt{Text: node.Name + " = " + pyExprToGo(node.Value)}}
	}

	return []ir.Node{&ir.RawStmt{Text: pyAssignToGo(nodeText(node))}}
}

// lowerReturn transforms a return statement.
func (l *Lowerer) lowerReturn(node *pymodel.Node) []ir.Node {
	var values []ir.Expr
	if node.Value != "" {
		values = append(values, &ir.RawExpr{Text: pyExprToGo(node.Value)})
	}
	return []ir.Node{&ir.ReturnStmt{Values: values}}
}

// lowerBody lowers a slice of structured child statements.
func (l *Lowerer) lowerBody(children []*pymodel.Node, className string) []ir.Node {
	var body []ir.Node
	for _, c := range children {
		body = append(body, l.lowerNode(c, className)...)
	}
	return body
}

// lowerIf transforms a structured if/elif/else chain into ir.IfStmt.
func (l *Lowerer) lowerIf(node *pymodel.Node, className string) ir.Node {
	stmt := &ir.IfStmt{
		Cond: &ir.RawExpr{Text: pyExprToGo(node.Cond)},
		Then: l.lowerBody(node.Children, className),
	}

	// Orelse is either a single nested NodeIf (elif) or a plain else body.
	if len(node.Orelse) == 1 && node.Orelse[0].Type == pymodel.NodeIf {
		stmt.Else = []ir.Node{l.lowerIf(node.Orelse[0], className)}
	} else if len(node.Orelse) > 0 {
		stmt.Else = l.lowerBody(node.Orelse, className)
	}

	return stmt
}

// lowerWhile transforms a Python while loop into a condition-only ir.ForStmt.
func (l *Lowerer) lowerWhile(node *pymodel.Node, className string) ir.Node {
	return &ir.ForStmt{
		Cond: &ir.RawExpr{Text: pyExprToGo(node.Cond)},
		Body: l.lowerBody(node.Children, className),
	}
}

// lowerFor transforms a Python for-each loop into an ir.RangeStmt.
// `for k, v in d:` → key/value; `for x in xs:` → value only.
func (l *Lowerer) lowerFor(node *pymodel.Node, className string) ir.Node {
	rng := &ir.RangeStmt{
		Range: &ir.RawExpr{Text: pyExprToGo(node.Cond)},
		Body:  l.lowerBody(node.Children, className),
	}

	targets := strings.Split(node.Target, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}

	switch len(targets) {
	case 1:
		rng.Key = "_"
		rng.Value = targets[0]
	case 2:
		rng.Key = targets[0]
		rng.Value = targets[1]
	default:
		if len(targets) > 0 {
			rng.Value = targets[0]
		}
	}

	return rng
}

// pyExprToGo applies conservative token-level normalization of Python
// expression syntax to Go. It is intentionally minimal: it only rewrites
// constructs that are unambiguous at the token level so that structurally
// lowered control flow compiles for the common case. Complex expressions
// still pass through as-is (RawExpr) for the host LLM to refine.
var pyExprReplacements = []struct{ old, new string }{
	{" is not ", " != "},
	{" is ", " == "},
	{" and ", " && "},
	{" or ", " || "},
}

// pyNotRe matches the Python boolean `not` operator as a whole word so it can
// become Go `!` without touching identifiers like `cannot` or `not_found`.
var pyNotRe = regexp.MustCompile(`\bnot\s+`)

// fStrRe matches a Python f-string (optionally also r/b prefixed).
var fStrRe = regexp.MustCompile(`(?i)\bf[rb]?("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')`)

// strLitRe matches a normal (non-f) Go-compatible string/char literal so its
// contents are shielded from operator normalization.
var strLitRe = regexp.MustCompile(`"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'`)

// pyExprToGo normalizes a Python expression to Go without corrupting string
// literals: f-strings become fmt.Sprintf, other literals are shielded, and
// operator/keyword rewriting only touches code segments.
func pyExprToGo(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	s = fStrRe.ReplaceAllStringFunc(s, fStringToSprintf)

	// Walk literal vs code segments; normalize only code.
	var (
		b   strings.Builder
		idx int
	)

	for _, loc := range strLitRe.FindAllStringIndex(s, -1) {
		b.WriteString(normalizeCode(s[idx:loc[0]]))
		b.WriteString(s[loc[0]:loc[1]]) // literal verbatim
		idx = loc[1]
	}

	b.WriteString(normalizeCode(s[idx:]))

	return strings.TrimSpace(b.String())
}

// normalizeCode applies operator/keyword rewriting to a code-only segment.
func normalizeCode(s string) string {
	if s == "" {
		return s
	}

	out := " " + s + " "
	for _, r := range pyExprReplacements {
		out = strings.ReplaceAll(out, r.old, r.new)
	}

	out = pyNotRe.ReplaceAllString(out, "!")
	out = wordReplace(out, "None", "nil")
	out = wordReplace(out, "True", "true")
	out = wordReplace(out, "False", "false")

	out = out[1 : len(out)-1] // drop sentinel spaces

	out = membershipRe.ReplaceAllStringFunc(out, rewriteMembership)
	out = ternaryRe.ReplaceAllStringFunc(out, rewriteTernary)
	out = orDefaultRe.ReplaceAllString(out, "$1")
	out = goifyComprehensions(out)
	out = goifyCalls(out)
	out = bareInRe.ReplaceAllStringFunc(out, rewriteBareIn)

	return out
}

// orDefaultRe drops an empty-collection/zero default on a Python `or`
// (already normalized to `||`): `tags || []` → `tags` (Go zero values make
// the default redundant and the bare literal is untyped).
var orDefaultRe = regexp.MustCompile(`([A-Za-z_][\w.]*)\s*\|\|\s*(?:\[\]|\{\}|""|''|nil)`)

// ternaryRe matches a Python conditional expression `X if C else Y` with no
// nested conditional (conservative).
var ternaryRe = regexp.MustCompile(`(\S[^?]*?)\s+\bif\b\s+(.+?)\s+\belse\b\s+(.+)`)

// rewriteTernary lowers `X if C else Y` to a Go IIFE that returns the value.
func rewriteTernary(m string) string {
	g := ternaryRe.FindStringSubmatch(m)
	if g == nil || strings.Contains(g[1], " if ") {
		return m
	}

	x, c, y := strings.TrimSpace(g[1]), strings.TrimSpace(g[2]), strings.TrimSpace(g[3])

	return "func() any { if " + c + " { return " + x + " }; return " + y + " }()"
}

// bareInRe matches Python membership with no literal collection on the RHS
// (`id in self._store`, `tag not in p.tags`), which `membershipRe` skips.
var bareInRe = regexp.MustCompile(
	`([A-Za-z_][\w.]*(?:\([^()]*\))?)\s+(not\s+)?\bin\b\s+([A-Za-z_][\w.]*(?:\([^()]*\))?)`)

// rewriteBareIn lowers `a in b` to a deterministic map-membership IIFE
// (`func() bool { _, _ok := b[a]; return _ok }()`), negated for `not in`.
// Correct for dict/map; for slices it still parses (LLM refines semantics).
func rewriteBareIn(m string) string {
	g := bareInRe.FindStringSubmatch(m)
	if g == nil {
		return m
	}

	lhs, neg, rhs := g[1], g[2] != "", g[3]
	expr := "func() bool { _, _ok := " + rhs + "[" + lhs + "]; return _ok }()"

	if neg {
		return "!" + expr
	}

	return expr
}

// --- paren/bracket-aware expression rewriting (robust, not regex) ---

// matchDelim returns the index of the delimiter that closes the opener at
// position open in s, or -1. It is string-literal aware.
func matchDelim(s string, open int) int {
	closer := map[byte]byte{'(': ')', '[': ']', '{': '}'}[s[open]]

	depth := 0

	for i := open; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'':
			i = skipString(s, i)
		case s[open]:
			depth++
		case closer:
			depth--
			if depth == 0 {
				return i
			}
		}
	}

	return -1
}

// skipString returns the index of the closing quote of the literal that
// starts at i (handles backslash escapes); i is left on the close quote.
func skipString(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		if s[j] == '\\' {
			j++
			continue
		}

		if s[j] == q {
			return j
		}
	}

	return len(s) - 1
}

// splitTopArgs splits an argument list on top-level commas (ignoring commas
// nested in (), [], {} or string literals).
func splitTopArgs(s string) []string {
	var (
		args  []string
		start int
		depth int
	)

	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\'':
			i = skipString(s, i)
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}

	if rest := strings.TrimSpace(s[start:]); rest != "" {
		args = append(args, rest)
	}

	return args
}

var callHeadRe = regexp.MustCompile(`[A-Za-z_][\w.]*$`)
var kwArgRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*([^=].*)$|^([A-Za-z_]\w*)\s*=\s*$`)

// goifyCalls rewrites Python call syntax to Go: keyword-only constructor
// calls (`Pkg.Cls` / `Cls`) become composite literals `Cls{Field: v}`;
// other keyword args are dropped to positional. Balanced + recursive.
func goifyCalls(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\'' {
			i = skipString(s, i)
			continue
		}

		if s[i] != '(' {
			continue
		}

		head := callHeadRe.FindString(s[:i])
		if head == "" {
			continue // grouping paren, not a call
		}

		close := matchDelim(s, i)
		if close < 0 {
			continue
		}

		inner := goifyCalls(s[i+1 : close]) // recurse into args first
		args := splitTopArgs(inner)
		repl := rebuildCall(head, args)

		s = s[:i-len(head)] + repl + s[close+1:]
		i = i - len(head) + len(repl) - 1
	}

	return s
}

func rebuildCall(head string, args []string) string {
	type kv struct{ k, v string }

	var (
		kws    []kv
		hasKW  bool
		hasPos bool
		pos    []string
	)

	for _, a := range args {
		if m := kwArgRe.FindStringSubmatch(a); m != nil {
			hasKW = true

			if m[1] != "" {
				kws = append(kws, kv{m[1], m[2]})
			} else {
				kws = append(kws, kv{m[3], ""})
			}

			continue
		}

		hasPos = true

		pos = append(pos, a)
	}

	leaf := head
	if i := strings.LastIndexByte(head, '.'); i >= 0 {
		leaf = head[i+1:]
	}

	ctor := !strings.Contains(head, ".") && leaf != "" && leaf[0] >= 'A' && leaf[0] <= 'Z'

	// All-keyword call to a Capitalized name → struct composite literal.
	if hasKW && !hasPos && ctor {
		var fields []string
		for _, p := range kws {
			fields = append(fields, exportName(p.k)+": "+p.v)
		}

		return head + "{" + strings.Join(fields, ", ") + "}"
	}

	// Otherwise: drop keyword names, keep values positionally.
	if hasKW {
		out := append([]string{}, pos...)
		for _, p := range kws {
			if p.v != "" {
				out = append(out, p.v)
			}
		}

		return head + "(" + strings.Join(out, ", ") + ")"
	}

	return head + "(" + strings.Join(args, ", ") + ")"
}

// compRe finds a comprehension's keyword skeleton inside a bracket body.
var compForRe = regexp.MustCompile(`^(.*?)\bfor\b\s+(.+?)\s+\bin\b\s+(.+?)(?:\s+\bif\b\s+(.+))?$`)

// goifyComprehensions converts list/dict comprehensions to deterministic Go
// IIFEs. `[e for x in xs if c]` → an immediately-invoked func returning a
// slice. Element type is `any` (LLM can refine). Balanced + recursive.
func goifyComprehensions(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '"' || s[i] == '\'' {
			i = skipString(s, i)
			continue
		}

		if s[i] != '[' && s[i] != '{' {
			continue
		}

		close := matchDelim(s, i)
		if close < 0 {
			continue
		}

		body := s[i+1 : close]
		if !strings.Contains(" "+body+" ", " for ") {
			continue
		}

		m := compForRe.FindStringSubmatch(strings.TrimSpace(body))
		if m == nil {
			continue
		}

		elem := goifyComprehensions(strings.TrimSpace(m[1]))
		tgt := strings.TrimSpace(m[2])
		iter := goifyComprehensions(strings.TrimSpace(m[3]))
		cond := strings.TrimSpace(m[4])

		key, val := "_", tgt
		if parts := splitTopArgs(tgt); len(parts) == 2 {
			key, val = parts[0], parts[1]
		}

		guardOpen, guardClose := "", ""
		if cond != "" {
			guardOpen = "if " + goifyComprehensions(cond) + " { "
			guardClose = " }"
		}

		var iife string
		if isDictComp := s[i] == '{' && strings.Contains(elem, ":"); isDictComp {
			kvp := splitTopArgs(elem)
			iife = "func() map[any]any { _r := map[any]any{}; for " + key + ", " + val +
				" := range " + iter + " { " + guardOpen + "_r[" + strings.TrimSpace(kvp[0]) +
				"] = " + strings.TrimSpace(strings.TrimPrefix(elem, kvp[0]+":")) + guardClose +
				" }; return _r }()"
		} else {
			iife = "func() []any { var _r []any; for " + key + ", " + val +
				" := range " + iter + " { " + guardOpen + "_r = append(_r, " + elem + ")" +
				guardClose + " }; return _r }()"
		}

		s = s[:i] + iife + s[close+1:]
		i = i + len(iife) - 1
	}

	return s
}

// membershipRe matches `LHS [not] in (a, b, ...)` / `[ ... ]`.
var membershipRe = regexp.MustCompile(`([\w.]+)\s+(not\s+)?in\s+[\(\[]([^)\]]*)[\)\]]`)

// rewriteMembership turns Python membership into a Go boolean chain:
// `x in (a, b)` → `(x == a || x == b)`; `x not in (a, b)` → `(x != a && x != b)`.
func rewriteMembership(m string) string {
	g := membershipRe.FindStringSubmatch(m)
	if g == nil {
		return m
	}

	lhs, neg, items := g[1], g[2] != "", strings.Split(g[3], ",")

	eq, join := " == ", " || "
	if neg {
		eq, join = " != ", " && "
	}

	var parts []string

	for _, it := range items {
		it = strings.TrimSpace(it)
		if it != "" {
			parts = append(parts, lhs+eq+it)
		}
	}

	if len(parts) == 0 {
		return m
	}

	return "(" + strings.Join(parts, join) + ")"
}

// fStringToSprintf converts one f-string to a fmt.Sprintf call (or a plain
// string literal when it has no interpolations). `{expr:spec}` / `{expr!r}`
// drop the spec; `{{`/`}}` become literal braces.
func fStringToSprintf(m string) string {
	g := fStrRe.FindStringSubmatch(m)
	if g == nil {
		return m
	}

	raw := g[1]
	body := raw[1 : len(raw)-1] // strip surrounding quotes

	var (
		format strings.Builder
		args   []string
		i      int
	)

	for i < len(body) {
		switch {
		case strings.HasPrefix(body[i:], "{{"):
			format.WriteString("{")

			i += 2
		case strings.HasPrefix(body[i:], "}}"):
			format.WriteString("}")

			i += 2
		case body[i] == '{':
			end := strings.IndexByte(body[i:], '}')
			if end < 0 {
				format.WriteString(body[i:])
				i = len(body)

				continue
			}

			expr := body[i+1 : i+end]
			if c := strings.IndexAny(expr, ":!"); c >= 0 {
				expr = expr[:c]
			}

			args = append(args, normalizeCode(strings.TrimSpace(expr)))
			format.WriteString("%v")

			i += end + 1
		case body[i] == '%':
			format.WriteString("%%")

			i++
		default:
			format.WriteByte(body[i])
			i++
		}
	}

	if len(args) == 0 {
		return `"` + format.String() + `"`
	}

	return `fmt.Sprintf("` + format.String() + `", ` + strings.Join(args, ", ") + `)`
}

// wordReplace replaces whole-word occurrences of old with new.
func wordReplace(s, old, neu string) string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(old) + `\b`)
	return re.ReplaceAllString(s, neu)
}

// bareAssignRe matches a statement whose LHS is a single plain identifier
// (`total = Money(0)`), as opposed to attribute/subscript/augmented targets
// (`p.stock -= qty`) which are already valid Go statements.
var bareAssignRe = regexp.MustCompile(`^([A-Za-z_]\w*)\s*=\s*([^=].*)$`)

// pyAssignToGo normalizes a Python assignment statement to Go operators
// (`is`→`==`, `None`→`nil`, …) while preserving its form. New-local `:=`
// promotion is decided later by declareLocals (needs scope context).
func pyAssignToGo(s string) string {
	return pyExprToGo(strings.TrimSpace(s))
}

// declareLocals promotes the first plain-identifier assignment to a Go short
// declaration (`x := v`) and leaves subsequent rebinds as `x = v`, so a
// function body compiles without "undefined" or "no new variables" errors.
// Block scoping is approximated by sharing one seen-set across nested
// blocks (conservative: avoids redeclaration).
func declareLocals(nodes []ir.Node, seen map[string]bool) {
	for _, n := range nodes {
		switch s := n.(type) {
		case *ir.RawStmt:
			if m := bareAssignRe.FindStringSubmatch(strings.TrimSpace(s.Text)); m != nil {
				name := m[1]
				if !seen[name] {
					seen[name] = true
					s.Text = name + " := " + m[2]
				}
			}
		case *ir.IfStmt:
			declareLocals(s.Then, seen)
			declareLocals(s.Else, seen)
		case *ir.ForStmt:
			declareLocals(s.Body, seen)
		case *ir.RangeStmt:
			declareLocals(s.Body, seen)
		}
	}
}

// lowerRaise converts a Python `raise` into a deterministic Go panic.
// `raise ValueError("msg")` → `panic("msg")` when the argument is a simple
// literal; otherwise `panic(<expr>)`. Bare `raise` → re-panic via recover.
func (l *Lowerer) lowerRaise(node *pymodel.Node) ir.Node {
	expr := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(node.Value), "raise"))
	// Drop `from <cause>` chaining.
	if i := strings.Index(expr, " from "); i >= 0 {
		expr = strings.TrimSpace(expr[:i])
	}

	if expr == "" {
		return &ir.RawStmt{Text: "panic(recover())", Comment: "Python bare raise"}
	}

	// ExceptionType(args...) → panic(args...) so the message survives and
	// the result compiles (the Python exception type has no Go analog yet).
	if m := regexp.MustCompile(`^[A-Za-z_]\w*\((.*)\)$`).FindStringSubmatch(expr); m != nil {
		inner := strings.TrimSpace(m[1])
		if inner == "" {
			inner = `"` + expr + `"`
		}

		return &ir.RawStmt{Text: "panic(" + pyExprToGo(inner) + ")"}
	}

	return &ir.RawStmt{Text: "panic(" + pyExprToGo(expr) + ")"}
}

// selfRe matches the Python implicit-receiver name `self` as a whole word.
var selfRe = regexp.MustCompile(`\bself\b`)

// rewriteSelf replaces `self` with the Go receiver name throughout a method
// body so structurally lowered expressions reference the right variable.
func rewriteSelf(nodes []ir.Node, recv string) {
	if recv == "" {
		return
	}

	for _, n := range nodes {
		switch s := n.(type) {
		case *ir.RawStmt:
			s.Text = selfRe.ReplaceAllString(s.Text, recv)
		case *ir.ExprStmt:
			rewriteSelfExpr(s.Expr, recv)
		case *ir.ReturnStmt:
			for _, e := range s.Values {
				rewriteSelfExpr(e, recv)
			}
		case *ir.VarDecl:
			rewriteSelfExpr(s.Value, recv)
		case *ir.IfStmt:
			rewriteSelfExpr(s.Cond, recv)
			rewriteSelf(s.Then, recv)
			rewriteSelf(s.Else, recv)
		case *ir.ForStmt:
			rewriteSelfExpr(s.Cond, recv)
			rewriteSelf(s.Body, recv)
		case *ir.RangeStmt:
			rewriteSelfExpr(s.Range, recv)
			rewriteSelf(s.Body, recv)
		}
	}
}

func rewriteSelfExpr(e ir.Expr, recv string) {
	if r, ok := e.(*ir.RawExpr); ok {
		r.Text = selfRe.ReplaceAllString(r.Text, recv)
	}
}

// lowerFieldDecl creates an IR field from a pymodel assign node.
func (l *Lowerer) lowerFieldDecl(node *pymodel.Node) *ir.FieldDecl {
	if node.Name == "" {
		return nil
	}

	typeHint := node.Metadata["type_hint"]
	if typeHint == "" {
		typeHint = node.Value // for annotation-only fields like "name: str"
	}

	return &ir.FieldDecl{
		Name: exportName(node.Name),
		Type: mapTypeHint(typeHint),
	}
}

// --- Type mapping ---

var genericRe = regexp.MustCompile(`^(\w+)\[(.+)\]$`)

// mapTypeHint converts a Python type hint to an IR TypeRef.
func mapTypeHint(hint string) *ir.TypeRef {
	hint = strings.TrimSpace(hint)
	if hint == "" {
		return &ir.TypeRef{Kind: ir.KindInterface, Name: "any"}
	}

	// Forward-reference string annotations: "OrderStatus" → OrderStatus.
	if len(hint) >= 2 && (hint[0] == '"' || hint[0] == '\'') && hint[len(hint)-1] == hint[0] {
		hint = strings.TrimSpace(hint[1 : len(hint)-1])
	}

	// PEP 604 / typing unions:  T | None → *T ;  A | B → any.
	if parts := splitTopArgs(strings.ReplaceAll(hint, "|", ",")); strings.Contains(hint, "|") && len(parts) >= 2 {
		var nonNone []string

		for _, p := range parts {
			if p := strings.TrimSpace(p); p != "None" && p != "" {
				nonNone = append(nonNone, p)
			}
		}

		if len(nonNone) == 1 {
			return &ir.TypeRef{Kind: ir.KindPointer, ElemType: mapTypeHint(nonNone[0])}
		}

		return &ir.TypeRef{Kind: ir.KindInterface, Name: "any"}
	}

	// Check for generic types like list[str], dict[str, int], Optional[str]
	if m := genericRe.FindStringSubmatch(hint); m != nil {
		outer := m[1]
		inner := m[2]

		switch outer {
		case "list", "List":
			return &ir.TypeRef{Kind: ir.KindSlice, ElemType: mapTypeHint(inner)}
		case "dict", "Dict":
			parts := splitGenericArgs(inner)
			if len(parts) == 2 {
				return &ir.TypeRef{Kind: ir.KindMap, KeyType: mapTypeHint(parts[0]), ValType: mapTypeHint(parts[1])}
			}
			return &ir.TypeRef{Kind: ir.KindMap, KeyType: mapTypeHint("str"), ValType: mapTypeHint("")}
		case "set", "Set":
			return &ir.TypeRef{Kind: ir.KindMap, KeyType: mapTypeHint(inner), ValType: &ir.TypeRef{Kind: ir.KindStruct, Name: "struct{}"}}
		case "Optional":
			return &ir.TypeRef{Kind: ir.KindPointer, ElemType: mapTypeHint(inner)}
		case "tuple", "Tuple":
			// Tuple mapped to struct or any
			return &ir.TypeRef{Kind: ir.KindInterface, Name: "any"}
		}
	}

	// Primitive types
	switch hint {
	case "str":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "string"}
	case "int":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "int"}
	case "float":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "float64"}
	case "bool":
		return &ir.TypeRef{Kind: ir.KindPrimitive, Name: "bool"}
	case "bytes":
		return &ir.TypeRef{Kind: ir.KindSlice, ElemType: &ir.TypeRef{Kind: ir.KindPrimitive, Name: "byte"}}
	case "None":
		return nil
	case "datetime":
		return &ir.TypeRef{Kind: ir.KindStruct, Name: "time.Time"}
	}

	// User-defined type (class reference)
	return &ir.TypeRef{Kind: ir.KindStruct, Name: exportName(hint)}
}

// splitGenericArgs splits "str, int" respecting nested brackets.
func splitGenericArgs(s string) []string {
	var parts []string
	depth := 0
	start := 0
	for i, c := range s {
		switch c {
		case '[':
			depth++
		case ']':
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

func hasDecorator(node *pymodel.Node, name string) bool {
	for _, d := range node.Decorators {
		if d == name || strings.HasPrefix(d, name+"(") {
			return true
		}
	}
	return false
}

func hasBase(node *pymodel.Node, name string) bool {
	bases := node.Metadata["bases"]
	if bases == "" {
		return false
	}
	for part := range strings.SplitSeq(bases, ",") {
		if strings.TrimSpace(part) == name {
			return true
		}
	}
	return false
}

func isFieldAssign(node *pymodel.Node) bool {
	// Field annotations in class body (e.g., "name: str = ''")
	return node.Name != "" && node.Metadata["type_hint"] != ""
}

func isConstantName(name string) bool {
	for _, r := range name {
		if r != '_' && !unicode.IsUpper(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return len(name) > 0
}

func exportName(name string) string {
	if name == "" {
		return ""
	}
	// Strip leading underscores for export
	clean := strings.TrimLeft(name, "_")
	if clean == "" {
		return name
	}
	// PascalCase
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

func mapDunderName(goName, pyName string) string {
	switch pyName {
	case "__str__", "__repr__":
		return "String"
	case "__len__":
		return "Len"
	case "__eq__":
		return "Equal"
	case "__lt__":
		return "Less"
	case "__add__":
		return "Add"
	case "__sub__":
		return "Sub"
	case "__mul__":
		return "Mul"
	case "__contains__":
		return "Contains"
	case "__iter__":
		return "Iter"
	case "__enter__":
		return "Open"
	case "__exit__":
		return "Close"
	}
	return goName
}

func nodeText(node *pymodel.Node) string {
	if node.Value != "" {
		return node.Value
	}
	if node.Name != "" {
		return node.Name
	}
	return fmt.Sprintf("/* %s */", node.Type)
}
