package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// collapseForEach looks for Iterator-based while loops and collapses them
// to for-each statements. Returns transformed list and count.
//
// Pattern:
//
//	Iterator var1 = collection.iterator();
//	while (var1.hasNext()) {
//	    Type item = (Type) var1.next();
//	    ...body...
//	}
//	→  for (Type item : collection) { ...body... }
func collapseForEach(stmts []stmt.Statement) ([]stmt.Statement, int) {
	count := 0
	result := make([]stmt.Statement, 0, len(stmts))

	i := 0
	for i < len(stmts) {
		// Need at least two consecutive statements: assignment + while.
		if i+1 >= len(stmts) {
			result = append(result, stmts[i])
			i++

			continue
		}

		// Step 1: Check if first statement is an assignment whose value is
		// a method call to .iterator().
		iterAssign, ok := stmts[i].(*stmt.AssignmentStatement)
		if !ok {
			result = append(result, stmts[i])
			i++

			continue
		}

		iterCall, ok := iterAssign.Value.(*ast.MethodInvocation)
		if !ok || iterCall.Method.MethodName != "iterator" || iterCall.Object == nil {
			result = append(result, stmts[i])
			i++

			continue
		}

		iterVarName := iterAssign.Target.LValueName()
		collection := iterCall.Object

		// Step 2: Check if next statement is a while loop whose condition
		// calls .hasNext() on the same iterator variable.
		whileLoop, ok := stmts[i+1].(*stmt.StructuredWhile)
		if !ok {
			result = append(result, stmts[i])
			i++

			continue
		}

		hasNextCall, ok := whileLoop.Condition.(*ast.MethodInvocation)
		if !ok || hasNextCall.Method.MethodName != "hasNext" || hasNextCall.Object == nil {
			result = append(result, stmts[i])
			i++

			continue
		}

		if !isVarNamed(hasNextCall.Object, iterVarName) {
			result = append(result, stmts[i])
			i++

			continue
		}

		// Step 3: Check if the first statement in the while body is an
		// assignment from .next() (possibly with a cast) on the same iterator.
		bodyStmts := extractBodyStatements(whileLoop.Body)
		if len(bodyStmts) == 0 {
			result = append(result, stmts[i])
			i++

			continue
		}

		elemAssign, ok := bodyStmts[0].(*stmt.AssignmentStatement)
		if !ok {
			result = append(result, stmts[i])
			i++

			continue
		}

		nextExpr := unwrapCast(elemAssign.Value)

		nextCall, ok := nextExpr.(*ast.MethodInvocation)
		if !ok || nextCall.Method.MethodName != "next" || nextCall.Object == nil {
			result = append(result, stmts[i])
			i++

			continue
		}

		if !isVarNamed(nextCall.Object, iterVarName) {
			result = append(result, stmts[i])
			i++

			continue
		}

		// All patterns match. Build the for-each statement.
		// The loop body is everything after the first assignment in the
		// original while body.
		var forBody stmt.Statement
		if len(bodyStmts) > 1 {
			forBody = stmt.NewBlock(bodyStmts[1:]...)
		} else {
			forBody = stmt.NewBlock()
		}

		forEach := stmt.NewStructuredForEach(elemAssign.Target, collection, forBody)
		forEach.Label = whileLoop.Label

		result = append(result, forEach)
		count++
		i += 2 // consumed both the iterator assignment and the while loop

		continue
	}

	return result, count
}

// isVarNamed returns true if the expression resolves to a variable (or
// var-expression) with the given LValue name.
func isVarNamed(e ast.Expression, name string) bool {
	switch v := e.(type) {
	case ast.LValue:
		return v.LValueName() == name
	case *ast.VarExpression:
		return v.LVal.LValueName() == name
	}

	return false
}

// unwrapCast strips a single outer cast expression, returning the inner
// operand. If the expression is not a cast, it is returned as-is.
func unwrapCast(e ast.Expression) ast.Expression {
	if cast, ok := e.(*ast.CastExpression); ok {
		return cast.Operand
	}

	return e
}

// extractBodyStatements returns the flat statement list from a loop body.
// If the body is a Block, its inner statements are returned; otherwise a
// single-element slice is returned.
func extractBodyStatements(body stmt.Statement) []stmt.Statement {
	if body == nil {
		return nil
	}

	if block, ok := body.(*stmt.Block); ok {
		return block.Stmts
	}

	return []stmt.Statement{body}
}
