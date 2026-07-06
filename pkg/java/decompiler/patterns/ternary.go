package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// collapseTernary checks a statement list for if/else patterns that can be
// collapsed to ternary expressions. Returns the transformed list and count.
//
// Pattern 1 - assignment:
//
//	if (cond) { x = a; } else { x = b; }  →  x = cond ? a : b;
//
// Pattern 2 - return:
//
//	if (cond) { return a; } else { return b; }  →  return cond ? a : b;
func collapseTernary(stmts []stmt.Statement) ([]stmt.Statement, int) {
	count := 0
	result := make([]stmt.Statement, 0, len(stmts))

	for _, s := range stmts {
		ifStmt, ok := s.(*stmt.StructuredIf)
		if !ok || ifStmt.Else == nil {
			result = append(result, s)
			continue
		}

		thenSingle := unwrapSingleStatement(ifStmt.Then)
		elseSingle := unwrapSingleStatement(ifStmt.Else)
		if thenSingle == nil || elseSingle == nil {
			result = append(result, s)
			continue
		}

		// Pattern 1: both branches assign to the same target.
		thenAssign, thenIsAssign := thenSingle.(*stmt.AssignmentStatement)
		elseAssign, elseIsAssign := elseSingle.(*stmt.AssignmentStatement)

		if thenIsAssign && elseIsAssign &&
			thenAssign.Target.LValueName() == elseAssign.Target.LValueName() {
			ternary := ast.NewTernaryExpression(
				ifStmt.Condition,
				thenAssign.Value,
				elseAssign.Value,
				thenAssign.Value.Type(),
			)
			result = append(result, stmt.NewAssignment(thenAssign.Target, ternary))
			count++

			continue
		}

		// Pattern 2: both branches return a value.
		thenReturn, thenIsReturn := thenSingle.(*stmt.ReturnStatement)
		elseReturn, elseIsReturn := elseSingle.(*stmt.ReturnStatement)

		if thenIsReturn && elseIsReturn {
			ternary := ast.NewTernaryExpression(
				ifStmt.Condition,
				thenReturn.Value,
				elseReturn.Value,
				thenReturn.Value.Type(),
			)
			result = append(result, stmt.NewReturn(ternary))
			count++

			continue
		}

		// No match; keep original.
		result = append(result, s)
	}

	return result, count
}

// unwrapSingleStatement extracts a single statement from a block.
// If the statement is a *stmt.Block containing exactly one statement, returns
// the inner statement. If it is already a non-block statement, returns it
// directly. Returns nil when the block contains zero or multiple statements.
func unwrapSingleStatement(s stmt.Statement) stmt.Statement {
	if s == nil {
		return nil
	}

	block, ok := s.(*stmt.Block)
	if !ok {
		return s
	}

	if len(block.Stmts) == 1 {
		return block.Stmts[0]
	}

	return nil
}
