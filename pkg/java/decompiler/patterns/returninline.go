/*
Copyright (c) 2026 Security Research
*/
package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// inlineReturns collapses the pattern:
//
//	varX = expr;
//	return varX;
//
// Into:
//
//	return expr;
//
// This eliminates redundant temporaries produced by register-to-stack translation.
func inlineReturns(stmts []stmt.Statement) ([]stmt.Statement, int) {
	if len(stmts) < 2 {
		return stmts, 0
	}

	result := make([]stmt.Statement, 0, len(stmts))
	count := 0
	i := 0

	for i < len(stmts) {
		if i+1 < len(stmts) {
			if merged, ok := tryInlineReturn(stmts[i], stmts[i+1]); ok {
				result = append(result, merged)
				count++
				i += 2
				continue
			}
		}

		// Recurse into blocks
		result = append(result, inlineReturnInStatement(stmts[i]))
		i++
	}

	return result, count
}

func tryInlineReturn(s1, s2 stmt.Statement) (stmt.Statement, bool) {
	// s1 must be: varX = expr
	assign, ok := s1.(*stmt.AssignmentStatement)
	if !ok {
		return nil, false
	}

	// s2 must be: return varX
	ret, ok := s2.(*stmt.ReturnStatement)
	if !ok || ret.Value == nil {
		return nil, false
	}

	// Check that the return value matches the assignment target
	assignVar, isVar := assign.Target.(*ast.LocalVariable)
	retVar, retIsVar := ret.Value.(*ast.LocalVariable)

	if isVar && retIsVar && assignVar.Slot == retVar.Slot {
		// Inline: return the assigned expression directly
		return stmt.NewReturn(assign.Value), true
	}

	return nil, false
}

func inlineReturnInStatement(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.Block:
		st.Stmts, _ = inlineReturns(st.Stmts)
	case *stmt.StructuredIf:
		if block, ok := st.Then.(*stmt.Block); ok {
			block.Stmts, _ = inlineReturns(block.Stmts)
		}
		if st.Else != nil {
			if block, ok := st.Else.(*stmt.Block); ok {
				block.Stmts, _ = inlineReturns(block.Stmts)
			}
		}
	case *stmt.StructuredTry:
		if block, ok := st.Body.(*stmt.Block); ok {
			block.Stmts, _ = inlineReturns(block.Stmts)
		}
	}
	return s
}
