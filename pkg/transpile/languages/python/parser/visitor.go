package parser

import (
	"regexp"
	"strings"

	"github.com/antlr4-go/antlr/v4"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/parser/generated"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/python/pymodel"
)

// visitor walks the ANTLR parse tree and builds the IR.
type visitor struct {
	generated.BasePython3ParserVisitor
}

// ctxText returns the original source text for a rule context, preserving
// whitespace. ANTLR's ctx.GetText() concatenates token text with no
// separators ("x is None" → "xisNone"), which destroys expression syntax;
// reading the char interval from the input stream keeps it intact.
func ctxText(ctx antlr.ParserRuleContext) string {
	if ctx == nil {
		return ""
	}

	start, stop := ctx.GetStart(), ctx.GetStop()
	if start == nil || stop == nil {
		return ctx.GetText()
	}

	cs := start.GetInputStream()
	if cs == nil {
		return ctx.GetText()
	}

	return cs.GetText(start.GetStart(), stop.GetStop())
}

func newVisitor() *visitor {
	return &visitor{}
}

func (v *visitor) visitModule(ctx generated.IFile_inputContext) *pymodel.Module {
	module := &pymodel.Module{}

	for _, child := range ctx.GetChildren() {
		nodes := v.visitTree(child)
		for _, node := range nodes {
			if node.Type == pymodel.NodeImport {
				module.Imports = append(module.Imports, node)
			} else {
				module.Body = append(module.Body, node)
			}
		}
	}

	return module
}

// visitTree recursively walks a tree node and returns all IR nodes found.
func (v *visitor) visitTree(tree antlr.Tree) []*pymodel.Node {
	switch ctx := tree.(type) {
	case *generated.Import_stmtContext:
		return one(v.visitImport(ctx))
	case *generated.FuncdefContext:
		return one(v.visitFuncDef(ctx))
	case *generated.ClassdefContext:
		return one(v.visitClassDef(ctx))
	case *generated.If_stmtContext:
		return one(v.visitIfStmt(ctx))
	case *generated.For_stmtContext:
		return one(v.visitForStmt(ctx))
	case *generated.While_stmtContext:
		return one(v.visitWhileStmt(ctx))
	case *generated.Return_stmtContext:
		return one(v.visitReturnStmt(ctx))
	case *generated.Expr_stmtContext:
		return one(v.visitExprStmt(ctx))
	case *generated.With_stmtContext:
		return one(v.visitWithStmt(ctx))
	case *generated.Try_stmtContext:
		return one(v.visitTryStmt(ctx))
	case *generated.Raise_stmtContext:
		return one(v.visitRaiseStmt(ctx))
	case *generated.Assert_stmtContext:
		return one(v.visitAssertStmt(ctx))
	case *generated.Pass_stmtContext:
		return one(v.visitPassStmt(ctx))
	case *generated.Break_stmtContext:
		return one(v.visitBreakStmt(ctx))
	case *generated.Continue_stmtContext:
		return one(v.visitContinueStmt(ctx))
	case *generated.Yield_exprContext:
		return one(v.visitYieldExpr(ctx))
	case *generated.DecoratedContext:
		return one(v.visitDecorated(ctx))
	case *generated.Async_funcdefContext:
		return one(v.visitAsyncFuncDef(ctx))
	default:
		return v.visitChildren(tree)
	}
}

func (v *visitor) visitChildren(tree antlr.Tree) []*pymodel.Node {
	rc, ok := tree.(antlr.RuleContext)
	if !ok {
		return nil
	}

	var nodes []*pymodel.Node

	for _, child := range rc.GetChildren() {
		if _, isTerminal := child.(antlr.TerminalNode); isTerminal {
			continue
		}

		nodes = append(nodes, v.visitTree(child)...)
	}

	return nodes
}

func (v *visitor) visitImport(ctx *generated.Import_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type:  pymodel.NodeImport,
		Value: ctx.GetText(),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitFuncDef(ctx *generated.FuncdefContext) *pymodel.Node {
	node := &pymodel.Node{
		Type: pymodel.NodeFunction,
		Name: ctx.Name().GetText(),
		Line: ctx.GetStart().GetLine(),
	}

	if params := ctx.Parameters(); params != nil {
		if tal := params.Typedargslist(); tal != nil {
			node.Params = v.extractParams(tal)
		}
	}

	if ctx.ARROW() != nil {
		if testCtx := ctx.Test(); testCtx != nil {
			if node.Metadata == nil {
				node.Metadata = make(map[string]string)
			}

			node.Metadata["return_type"] = testCtx.GetText()
		}
	}

	if block := ctx.Block(); block != nil {
		node.Children = v.visitTree(block)
	}

	return node
}

func (v *visitor) extractParams(ctx generated.ITypedargslistContext) []*pymodel.Param {
	tal, ok := ctx.(*generated.TypedargslistContext)
	if !ok {
		return nil
	}

	var params []*pymodel.Param

	starSeen := false
	powerSeen := false

	if tal.STAR() != nil {
		_ = starSeen
	}

	if tal.POWER() != nil {
		_ = powerSeen
	}

	for i, tfp := range tal.AllTfpdef() {
		tfpCtx, ok := tfp.(*generated.TfpdefContext)
		if !ok {
			continue
		}

		p := &pymodel.Param{
			Name: tfpCtx.Name().GetText(),
		}

		if tfpCtx.COLON() != nil {
			if testCtx := tfpCtx.Test(); testCtx != nil {
				p.TypeHint = testCtx.GetText()
			}
		}

		if tal.STAR() != nil && !starSeen {
			starPos := tal.STAR().GetSymbol().GetTokenIndex()
			tfpPos := tfpCtx.GetStart().GetTokenIndex()

			if tfpPos > starPos {
				p.IsVariadic = true
				starSeen = true
			}
		}

		if tal.POWER() != nil && !powerSeen {
			powerPos := tal.POWER().GetSymbol().GetTokenIndex()
			tfpPos := tfpCtx.GetStart().GetTokenIndex()

			if tfpPos > powerPos {
				p.IsKwarg = true
				powerSeen = true
			}
		}

		if i < len(tal.AllASSIGN()) {
			if testCtx := tal.Test(i); testCtx != nil {
				p.Default = testCtx.GetText()
			}
		}

		params = append(params, p)
	}

	return params
}

func (v *visitor) visitClassDef(ctx *generated.ClassdefContext) *pymodel.Node {
	node := &pymodel.Node{
		Type: pymodel.NodeClass,
		Name: ctx.Name().GetText(),
		Line: ctx.GetStart().GetLine(),
	}

	if arglist := ctx.Arglist(); arglist != nil {
		if node.Metadata == nil {
			node.Metadata = make(map[string]string)
		}

		node.Metadata["bases"] = arglist.GetText()
	}

	if block := ctx.Block(); block != nil {
		node.Children = v.visitTree(block)
	}

	return node
}

// blockBody recurses a Block context into structured child statements.
func (v *visitor) blockBody(block generated.IBlockContext) []*pymodel.Node {
	if block == nil {
		return nil
	}

	return v.visitTree(block)
}

// visitIfStmt builds a structured if/elif/else chain. Grammar:
// 'if' test ':' block ('elif' test ':' block)* ('else' ':' block)?
// An elif is represented as a nested NodeIf inside Orelse.
func (v *visitor) visitIfStmt(ctx *generated.If_stmtContext) *pymodel.Node {
	return v.buildIfChain(ctx, ctx.AllTest(), ctx.AllBlock(), 0, ctx.ELSE() != nil)
}

func (v *visitor) buildIfChain(
	ctx *generated.If_stmtContext,
	tests []generated.ITestContext,
	blocks []generated.IBlockContext,
	i int,
	hasElse bool,
) *pymodel.Node {
	node := &pymodel.Node{
		Type: pymodel.NodeIf,
		Line: ctx.GetStart().GetLine(),
	}

	if i < len(tests) {
		node.Cond = ctxText(tests[i])
	}

	if i < len(blocks) {
		node.Children = v.blockBody(blocks[i])
	}

	// Another test remains → it is an elif: nest it under Orelse.
	if i+1 < len(tests) {
		node.Orelse = []*pymodel.Node{v.buildIfChain(ctx, tests, blocks, i+1, hasElse)}
		return node
	}

	// No more tests; a block beyond the tests is the else body.
	if hasElse && len(blocks) > len(tests) {
		node.Orelse = v.blockBody(blocks[len(blocks)-1])
	}

	return node
}

// visitForStmt builds a structured for-each loop. Grammar:
// 'for' exprlist 'in' testlist ':' block ('else' ':' block)?
func (v *visitor) visitForStmt(ctx *generated.For_stmtContext) *pymodel.Node {
	node := &pymodel.Node{
		Type: pymodel.NodeFor,
		Line: ctx.GetStart().GetLine(),
	}

	if el := ctx.Exprlist(); el != nil {
		node.Target = ctxText(el)
	}

	if tl := ctx.Testlist(); tl != nil {
		node.Cond = ctxText(tl)
	}

	if blocks := ctx.AllBlock(); len(blocks) > 0 {
		node.Children = v.blockBody(blocks[0])

		if ctx.ELSE() != nil && len(blocks) > 1 {
			node.Orelse = v.blockBody(blocks[len(blocks)-1])
		}
	}

	return node
}

// visitWhileStmt builds a structured while loop. Grammar:
// 'while' test ':' block ('else' ':' block)?
func (v *visitor) visitWhileStmt(ctx *generated.While_stmtContext) *pymodel.Node {
	node := &pymodel.Node{
		Type: pymodel.NodeWhile,
		Line: ctx.GetStart().GetLine(),
	}

	if t := ctx.Test(); t != nil {
		node.Cond = ctxText(t)
	}

	if blocks := ctx.AllBlock(); len(blocks) > 0 {
		node.Children = v.blockBody(blocks[0])

		if ctx.ELSE() != nil && len(blocks) > 1 {
			node.Orelse = v.blockBody(blocks[len(blocks)-1])
		}
	}

	return node
}

func (v *visitor) visitReturnStmt(ctx *generated.Return_stmtContext) *pymodel.Node {
	node := &pymodel.Node{
		Type: pymodel.NodeReturn,
		Line: ctx.GetStart().GetLine(),
	}

	if tl := ctx.Testlist(); tl != nil {
		node.Value = ctxText(tl)
	}

	return node
}

func (v *visitor) visitExprStmt(ctx *generated.Expr_stmtContext) *pymodel.Node {
	if aug := ctx.Augassign(); aug != nil {
		node := &pymodel.Node{
			Type:  pymodel.NodeAssign,
			Value: ctxText(ctx),
			Line:  ctx.GetStart().GetLine(),
		}

		node.Metadata = map[string]string{"augmented": aug.GetText()}

		return node
	}

	// Annotated assignment / declaration:  name: Type [= value]
	if ann := ctx.Annassign(); ann != nil {
		node := &pymodel.Node{
			Type:     pymodel.NodeAssign,
			Line:     ctx.GetStart().GetLine(),
			Metadata: map[string]string{},
		}

		if tses := ctx.AllTestlist_star_expr(); len(tses) > 0 {
			node.Name = simpleIdent(ctxText(tses[0]))
		}

		ac, _ := ann.(*generated.AnnassignContext)
		if ac != nil {
			if typ := ac.Test(0); typ != nil {
				node.Metadata["type_hint"] = ctxText(typ)
			}

			if ac.ASSIGN() != nil {
				if val := ac.Test(1); val != nil {
					node.Value = ctxText(val)
				}
			} else {
				node.Metadata["annotation_only"] = "true"
			}
		}

		return node
	}

	// Plain assignment:  target = [target = ...] rhs
	if len(ctx.AllASSIGN()) > 0 {
		node := &pymodel.Node{
			Type:  pymodel.NodeAssign,
			Value: ctxText(ctx),
			Line:  ctx.GetStart().GetLine(),
		}

		// Only split into name/RHS when the target is a single plain
		// identifier. For attribute/subscript/tuple targets keep the full
		// statement text (Value) so the lowerer emits a valid Go statement.
		tses := ctx.AllTestlist_star_expr()
		if len(tses) >= 1 {
			if id := simpleIdent(ctxText(tses[0])); id != "" {
				switch {
				case len(tses) >= 2:
					node.Name = id
					node.Value = ctxText(tses[len(tses)-1])
				case ctx.Testlist() != nil:
					node.Name = id
					node.Value = ctxText(ctx.Testlist())
				}
			}
		}

		return node
	}

	return &pymodel.Node{
		Type:  pymodel.NodeExpr,
		Value: ctxText(ctx),
		Line:  ctx.GetStart().GetLine(),
	}
}

// simpleIdentRe matches a lone Python identifier (no attribute/subscript/
// tuple target). Only such targets are safe to treat as a named binding.
var simpleIdentRe = regexp.MustCompile(`^[A-Za-z_]\w*$`)

// simpleIdent returns s if it is a single identifier, else "" (signalling
// the lowerer to keep the assignment as a raw statement).
func simpleIdent(s string) string {
	s = strings.TrimSpace(s)
	if simpleIdentRe.MatchString(s) {
		return s
	}

	return ""
}

func (v *visitor) visitWithStmt(ctx *generated.With_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type:  pymodel.NodeWith,
		Value: ctx.GetText(),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitTryStmt(ctx *generated.Try_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type:  pymodel.NodeTry,
		Value: ctx.GetText(),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitRaiseStmt(ctx *generated.Raise_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type:  pymodel.NodeRaise,
		Value: ctxText(ctx),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitAssertStmt(ctx *generated.Assert_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type:  pymodel.NodeExpr,
		Value: ctx.GetText(),
		Line:  ctx.GetStart().GetLine(),
		Metadata: map[string]string{
			"kind": "assert",
		},
	}
}

func (v *visitor) visitPassStmt(ctx *generated.Pass_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type: pymodel.NodePass,
		Line: ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitBreakStmt(ctx *generated.Break_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type: pymodel.NodeBreak,
		Line: ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitContinueStmt(ctx *generated.Continue_stmtContext) *pymodel.Node {
	return &pymodel.Node{
		Type: pymodel.NodeContinue,
		Line: ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitYieldExpr(ctx *generated.Yield_exprContext) *pymodel.Node {
	return &pymodel.Node{
		Type:  pymodel.NodeYield,
		Value: ctx.GetText(),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitDecorated(ctx *generated.DecoratedContext) *pymodel.Node {
	var decorators []string

	if decsCtx := ctx.Decorators(); decsCtx != nil {
		for _, dec := range decsCtx.AllDecorator() {
			if dn := dec.Dotted_name(); dn != nil {
				decorators = append(decorators, dn.GetText())
			}
		}
	}

	var node *pymodel.Node

	switch {
	case ctx.Funcdef() != nil:
		node = v.visitFuncDef(ctx.Funcdef().(*generated.FuncdefContext))
	case ctx.Classdef() != nil:
		node = v.visitClassDef(ctx.Classdef().(*generated.ClassdefContext))
	case ctx.Async_funcdef() != nil:
		node = v.visitAsyncFuncDef(ctx.Async_funcdef().(*generated.Async_funcdefContext))
	default:
		return nil
	}

	if node != nil {
		node.Decorators = decorators
	}

	return node
}

func (v *visitor) visitAsyncFuncDef(ctx *generated.Async_funcdefContext) *pymodel.Node {
	if fdef := ctx.Funcdef(); fdef != nil {
		node := v.visitFuncDef(fdef.(*generated.FuncdefContext))

		if node.Metadata == nil {
			node.Metadata = make(map[string]string)
		}

		node.Metadata["async"] = "true"

		return node
	}

	return nil
}

func one(n *pymodel.Node) []*pymodel.Node {
	if n == nil {
		return nil
	}

	return []*pymodel.Node{n}
}
