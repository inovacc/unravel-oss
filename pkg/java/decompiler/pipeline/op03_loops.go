package pipeline

import (
	"fmt"
	"slices"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// structureLoops detects loops via back edges and converts them to
// StructuredWhile, StructuredDoWhile, or StructuredFor.
func structureLoops(nodes []*Op03Node) []*Op03Node {
	backEdges := FindBackEdges(nodes)
	if len(backEdges) == 0 {
		return nodes
	}

	labelCounter := 0

	for _, be := range backEdges {
		header := be.Target
		latch := be.Source
		body := FindLoopBody(header, latch)

		if len(body) == 0 {
			continue
		}

		loopStmt := structureLoop(header, latch, body, &labelCounter)
		header.ReplaceStatement(loopStmt)

		for _, n := range body {
			if n != header {
				n.ReplaceStatement(stmt.NewNop())
			}
		}

		UnlinkOp03(latch, header)
	}

	return nodes
}

func structureLoop(header, latch *Op03Node, body []*Op03Node, labelCounter *int) stmt.Statement {
	bodyStmts := collectLoopBodyStatements(header, body)

	if isWhileLoop(header, body) {
		cond, loopBody := extractWhileCondition(header, body, bodyStmts)
		if cond != nil {
			loop := stmt.NewStructuredWhile(cond, loopBody)

			if loopNeedsLabel(body) {
				*labelCounter++
				loop.Label = fmt.Sprintf("loop_%d", *labelCounter)
			}

			return loop
		}
	}

	if isDoWhileLoop(header, latch) {
		cond, loopBody := extractDoWhileCondition(latch, bodyStmts)
		if cond != nil {
			loop := stmt.NewStructuredDoWhile(cond, loopBody)

			if loopNeedsLabel(body) {
				*labelCounter++
				loop.Label = fmt.Sprintf("loop_%d", *labelCounter)
			}

			return loop
		}
	}

	loop := stmt.NewStructuredWhile(ast.LitTrue, stmt.NewBlock(bodyStmts...))

	if loopNeedsLabel(body) {
		*labelCounter++
		loop.Label = fmt.Sprintf("loop_%d", *labelCounter)
	}

	return loop
}

func isWhileLoop(header *Op03Node, body []*Op03Node) bool {
	if header.Statement == nil || header.Statement.Kind() != stmt.KindIf {
		return false
	}

	bodySet := makeBodySet(body)
	insideCount := 0

	for _, t := range header.Targets {
		if bodySet[t.Index] {
			insideCount++
		}
	}

	return insideCount > 0 && insideCount < len(header.Targets)
}

func isDoWhileLoop(header, latch *Op03Node) bool {
	if latch == header {
		return false
	}

	if latch.Statement == nil || latch.Statement.Kind() != stmt.KindIf {
		return false
	}

	return slices.Contains(latch.Targets, header)
}

func extractWhileCondition(header *Op03Node, body []*Op03Node, bodyStmts []stmt.Statement) (ast.Expression, stmt.Statement) {
	ifStmt, ok := header.Statement.(*stmt.IfStatement)
	if !ok {
		return nil, nil
	}

	bodySet := makeBodySet(body)
	cond := ifStmt.Condition

	if len(header.Targets) >= 2 {
		branchTarget := header.Targets[0]
		if !bodySet[branchTarget.Index] {
			cond = negateCondition(cond)
		}
	}

	return cond, stmt.NewBlock(bodyStmts...)
}

func extractDoWhileCondition(latch *Op03Node, bodyStmts []stmt.Statement) (ast.Expression, stmt.Statement) {
	ifStmt, ok := latch.Statement.(*stmt.IfStatement)
	if !ok {
		return nil, nil
	}

	return ifStmt.Condition, stmt.NewBlock(bodyStmts...)
}

func collectLoopBodyStatements(header *Op03Node, body []*Op03Node) []stmt.Statement {
	stmts := make([]stmt.Statement, 0, len(body))
	for _, n := range body {
		if n == header {
			continue
		}

		if n.Statement != nil && n.Statement.Kind() != stmt.KindNop {
			stmts = append(stmts, n.Statement)
		}
	}

	return stmts
}

func loopNeedsLabel(body []*Op03Node) bool {
	bodySet := makeBodySet(body)
	for _, n := range body {
		for _, t := range n.Targets {
			if !bodySet[t.Index] && n.Statement != nil && n.Statement.Kind() == stmt.KindGoto {
				return true
			}
		}
	}

	return false
}

func makeBodySet(body []*Op03Node) map[int]bool {
	set := make(map[int]bool, len(body))
	for _, n := range body {
		set[n.Index] = true
	}

	return set
}

func negateCondition(expr ast.Expression) ast.Expression {
	if neg, ok := expr.(*ast.NegationExpression); ok {
		return neg.Operand
	}

	if cmp, ok := expr.(*ast.ComparisonOperation); ok {
		return ast.NewComparisonOperation(cmp.Op.Negate(), cmp.LHS, cmp.RHS)
	}

	return ast.NewNegationExpression(expr)
}
