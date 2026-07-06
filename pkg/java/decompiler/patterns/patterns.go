package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// Stats tracks how many patterns were applied.
type Stats struct {
	StringConcat     int
	Autobox          int
	Ternary          int
	ForEach          int
	AssertRewrite    int
	TryWithResources int
	Total            int
}

// Apply runs all pattern recognizers on a statement list and returns
// the transformed list with a Stats summary.
func Apply(stmts []stmt.Statement) ([]stmt.Statement, *Stats) {
	stats := &Stats{}
	result := stmts

	// Phase 1: Expression-level transforms (walk all expressions in all statements)
	result = walkStatements(result, func(e ast.Expression) ast.Expression {
		// String concatenation: new StringBuilder().append(...).toString() -> "a" + "b"
		if simplified, ok := simplifyStringConcat(e); ok {
			stats.StringConcat++
			stats.Total++
			return simplified
		}
		// Autoboxing: Integer.valueOf(x) -> x, x.intValue() -> x
		if simplified, ok := simplifyAutobox(e); ok {
			stats.Autobox++
			stats.Total++
			return simplified
		}
		return e
	})

	// Phase 2: Statement-level transforms

	// Ternary collapse: if/else with same target -> x = cond ? a : b
	var ternaryCount int
	result, ternaryCount = collapseTernary(result)
	stats.Ternary += ternaryCount
	stats.Total += ternaryCount

	// For-each collapse: Iterator while loop -> for (T x : collection)
	var forEachCount int
	result, forEachCount = collapseForEach(result)
	stats.ForEach += forEachCount
	stats.Total += forEachCount

	// new/init merge: new Foo; foo.<init>(args) -> new Foo(args)
	var newInitCount int
	result, newInitCount = mergeNewInit(result)
	stats.Total += newInitCount

	// Return inlining: var0 = expr; return var0; -> return expr;
	var inlineCount int
	result, inlineCount = inlineReturns(result)
	stats.Total += inlineCount

	// Assert reconstruction: $assertionsDisabled pattern -> assert comment
	var assertCount int
	result, assertCount = collapseAssertions(result)
	stats.AssertRewrite += assertCount
	stats.Total += assertCount

	// Try-with-resources detection (informational only for now)
	_, tryWithCount := collapseTryWithResources(result)
	stats.TryWithResources += tryWithCount

	return result, stats
}

// exprTransform is a function that transforms an expression, returning
// the (possibly modified) expression.
type exprTransform func(ast.Expression) ast.Expression

// walkStatements applies an expression transform to every expression reachable
// from each statement, returning the (possibly modified) statement list.
func walkStatements(stmts []stmt.Statement, transform exprTransform) []stmt.Statement {
	result := make([]stmt.Statement, len(stmts))
	for i, s := range stmts {
		result[i] = walkStatement(s, transform)
	}

	return result
}

// walkStatement recursively walks a single statement and transforms its expressions.
func walkStatement(s stmt.Statement, transform exprTransform) stmt.Statement {
	switch v := s.(type) {
	case *stmt.AssignmentStatement:
		newValue := walkExpr(v.Value, transform)
		if newValue != v.Value {
			return stmt.NewAssignment(v.Target, newValue)
		}
	case *stmt.ExpressionStatement:
		newExpr := walkExpr(v.Expr, transform)
		if newExpr != v.Expr {
			return stmt.NewExpressionStatement(newExpr)
		}
	case *stmt.ReturnStatement:
		newValue := walkExpr(v.Value, transform)
		if newValue != v.Value {
			return stmt.NewReturn(newValue)
		}
	case *stmt.ThrowStatement:
		newValue := walkExpr(v.Value, transform)
		if newValue != v.Value {
			return stmt.NewThrow(newValue)
		}
	case *stmt.StructuredIf:
		newCond := walkExpr(v.Condition, transform)
		newThen := walkStatement(v.Then, transform)
		var newElse stmt.Statement
		if v.Else != nil {
			newElse = walkStatement(v.Else, transform)
		}
		if newCond != v.Condition || newThen != v.Then || newElse != v.Else {
			return stmt.NewStructuredIf(newCond, newThen, newElse)
		}
	case *stmt.StructuredWhile:
		newCond := walkExpr(v.Condition, transform)
		newBody := walkStatement(v.Body, transform)
		if newCond != v.Condition || newBody != v.Body {
			w := stmt.NewStructuredWhile(newCond, newBody)
			w.Label = v.Label
			return w
		}
	case *stmt.StructuredDoWhile:
		newCond := walkExpr(v.Condition, transform)
		newBody := walkStatement(v.Body, transform)
		if newCond != v.Condition || newBody != v.Body {
			w := stmt.NewStructuredDoWhile(newCond, newBody)
			w.Label = v.Label
			return w
		}
	case *stmt.StructuredFor:
		var newInit stmt.Statement
		if v.Init != nil {
			newInit = walkStatement(v.Init, transform)
		}
		var newCond ast.Expression
		if v.Condition != nil {
			newCond = walkExpr(v.Condition, transform)
		}
		var newUpdate stmt.Statement
		if v.Update != nil {
			newUpdate = walkStatement(v.Update, transform)
		}
		newBody := walkStatement(v.Body, transform)
		if newInit != v.Init || newCond != v.Condition || newUpdate != v.Update || newBody != v.Body {
			f := stmt.NewStructuredFor(newInit, newCond, newUpdate, newBody)
			f.Label = v.Label
			return f
		}
	case *stmt.StructuredForEach:
		newIterable := walkExpr(v.Iterable, transform)
		newBody := walkStatement(v.Body, transform)
		if newIterable != v.Iterable || newBody != v.Body {
			f := stmt.NewStructuredForEach(v.Variable, newIterable, newBody)
			f.Label = v.Label
			return f
		}
	case *stmt.StructuredSwitch:
		newValue := walkExpr(v.Value, transform)
		casesChanged := newValue != v.Value
		newCases := make([]stmt.StructuredCase, len(v.Cases))
		for i, c := range v.Cases {
			newCases[i] = c
			if c.Body != nil {
				newBody := walkStatement(c.Body, transform)
				if newBody != c.Body {
					casesChanged = true
					newCases[i].Body = newBody
				}
			}
		}
		if casesChanged {
			return stmt.NewStructuredSwitch(newValue, newCases)
		}
	case *stmt.StructuredTry:
		newBody := walkStatement(v.Body, transform)
		catchesChanged := newBody != v.Body
		newCatches := make([]stmt.CatchClause, len(v.Catches))
		for i, c := range v.Catches {
			newCatches[i] = c
			newCatchBody := walkStatement(c.Body, transform)
			if newCatchBody != c.Body {
				catchesChanged = true
				newCatches[i].Body = newCatchBody
			}
		}
		var newFinally stmt.Statement
		if v.Finally != nil {
			newFinally = walkStatement(v.Finally, transform)
			if newFinally != v.Finally {
				catchesChanged = true
			}
		}
		if catchesChanged {
			return stmt.NewStructuredTry(newBody, newCatches, newFinally)
		}
	case *stmt.StructuredSynchronized:
		newObj := walkExpr(v.Object, transform)
		newBody := walkStatement(v.Body, transform)
		if newObj != v.Object || newBody != v.Body {
			return stmt.NewStructuredSynchronized(newObj, newBody)
		}
	case *stmt.Block:
		newStmts := walkStatements(v.Stmts, transform)
		changed := false
		for i, ns := range newStmts {
			if ns != v.Stmts[i] {
				changed = true
				break
			}
		}
		if changed {
			return stmt.NewBlock(newStmts...)
		}
	}

	return s
}

// walkExpr applies a bottom-up transform to an expression tree.
// Children are transformed first, then the transform is applied to the result.
func walkExpr(e ast.Expression, transform exprTransform) ast.Expression {
	if e == nil {
		return nil
	}

	// Transform children first (bottom-up)
	switch v := e.(type) {
	case *ast.MethodInvocation:
		changed := false
		var newObj ast.Expression
		if v.Object != nil {
			newObj = walkExpr(v.Object, transform)
			if newObj != v.Object {
				changed = true
			}
		}
		newArgs := make([]ast.Expression, len(v.Args))
		for i, arg := range v.Args {
			newArgs[i] = walkExpr(arg, transform)
			if newArgs[i] != arg {
				changed = true
			}
		}
		if changed {
			inv := &ast.MethodInvocation{
				Kind:   v.Kind,
				Object: newObj,
				Method: v.Method,
				Args:   newArgs,
				JType:  v.JType,
			}
			return transform(inv)
		}
	case *ast.ArithmeticOperation:
		newLHS := walkExpr(v.LHS, transform)
		newRHS := walkExpr(v.RHS, transform)
		if newLHS != v.LHS || newRHS != v.RHS {
			return transform(ast.NewArithmeticOperation(v.Op, newLHS, newRHS, v.JType))
		}
	case *ast.ComparisonOperation:
		newLHS := walkExpr(v.LHS, transform)
		newRHS := walkExpr(v.RHS, transform)
		if newLHS != v.LHS || newRHS != v.RHS {
			return transform(ast.NewComparisonOperation(v.Op, newLHS, newRHS))
		}
	case *ast.BooleanOperation:
		newLHS := walkExpr(v.LHS, transform)
		newRHS := walkExpr(v.RHS, transform)
		if newLHS != v.LHS || newRHS != v.RHS {
			return transform(ast.NewBooleanOperation(v.Op, newLHS, newRHS))
		}
	case *ast.NegationExpression:
		newOp := walkExpr(v.Operand, transform)
		if newOp != v.Operand {
			return transform(ast.NewNegationExpression(newOp))
		}
	case *ast.ArithmeticNegation:
		newOp := walkExpr(v.Operand, transform)
		if newOp != v.Operand {
			return transform(ast.NewArithmeticNegation(newOp, v.JType))
		}
	}

	// Apply transform to this node (may be a leaf or unchanged compound)
	return transform(e)
}
