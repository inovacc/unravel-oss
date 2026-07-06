/*
Copyright (c) 2026 Security Research
*/
package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// mergeNewInit collapses the pattern:
//
//	var0 = new Foo;         // AssignmentStatement with NewExpression
//	var0.<init>(arg1, arg2) // ExpressionStatement with InvokeSpecial(<init>)
//
// Into:
//
//	var0 = new Foo(arg1, arg2)
//
// This is a statement-level transform that looks at consecutive pairs.
func mergeNewInit(stmts []stmt.Statement) ([]stmt.Statement, int) {
	if len(stmts) < 2 {
		return stmts, 0
	}

	result := make([]stmt.Statement, 0, len(stmts))
	count := 0
	i := 0

	for i < len(stmts) {
		// Check if this is a "new" followed by "<init>"
		if i+1 < len(stmts) {
			if merged, ok := tryMergeNewInit(stmts[i], stmts[i+1]); ok {
				result = append(result, merged)
				count++
				i += 2
				continue
			}
		}

		// Recurse into blocks
		result = append(result, mergeNewInitInStatement(stmts[i]))
		i++
	}

	return result, count
}

func tryMergeNewInit(s1, s2 stmt.Statement) (stmt.Statement, bool) {
	// s1 must be: varX = new ClassName
	assign, ok := s1.(*stmt.AssignmentStatement)
	if !ok {
		return nil, false
	}

	_, isNewObj := assign.Value.(*ast.NewObject)
	if !isNewObj {
		return nil, false
	}

	// s2 must be: <expression statement> with invokespecial <init>
	exprStmt, ok := s2.(*stmt.ExpressionStatement)
	if !ok {
		return nil, false
	}

	invoke, ok := exprStmt.Expr.(*ast.MethodInvocation)
	if !ok {
		return nil, false
	}

	if invoke.Method == nil || invoke.Method.MethodName != "<init>" {
		return nil, false
	}

	if invoke.Kind != ast.InvokeSpecial {
		return nil, false
	}

	// Merge: the <init> invocation already renders as "new ClassName(args)"
	// when the decompiler sees it. Just replace the assignment value with
	// the invoke (which has the args).
	return stmt.NewAssignment(assign.Target, invoke), true
}

func mergeNewInitInStatement(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.Block:
		stmts, _ := mergeNewInit(st.Stmts)
		st.Stmts = stmts
	case *stmt.StructuredIf:
		if block, ok := st.Then.(*stmt.Block); ok {
			block.Stmts, _ = mergeNewInit(block.Stmts)
		}
		if st.Else != nil {
			if block, ok := st.Else.(*stmt.Block); ok {
				block.Stmts, _ = mergeNewInit(block.Stmts)
			}
		}
	case *stmt.StructuredWhile:
		if block, ok := st.Body.(*stmt.Block); ok {
			block.Stmts, _ = mergeNewInit(block.Stmts)
		}
	case *stmt.StructuredTry:
		if block, ok := st.Body.(*stmt.Block); ok {
			block.Stmts, _ = mergeNewInit(block.Stmts)
		}
		for i := range st.Catches {
			if block, ok := st.Catches[i].Body.(*stmt.Block); ok {
				block.Stmts, _ = mergeNewInit(block.Stmts)
			}
		}
	}
	return s
}
