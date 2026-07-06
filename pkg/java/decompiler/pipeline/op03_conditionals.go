package pipeline

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// structureConditionals converts flat if-goto patterns into StructuredIf.
func structureConditionals(nodes []*Op03Node) []*Op03Node {
	for i := range nodes {
		node := nodes[i]
		if node.Statement == nil || node.Statement.Kind() != stmt.KindIf {
			continue
		}

		ifStmt, ok := node.Statement.(*stmt.IfStatement)
		if !ok {
			continue
		}

		branchTarget := findNodeByOffset(nodes, ifStmt.TargetOffset)
		if branchTarget == nil {
			continue
		}

		fallThrough := op03CollectRange(nodes, i+1, branchTarget.Index)
		if len(fallThrough) == 0 {
			continue
		}

		var thenBody, elseBody []stmt.Statement

		hasElse := false

		lastFT := fallThrough[len(fallThrough)-1]
		if lastFT.Statement != nil && lastFT.Statement.Kind() == stmt.KindGoto {
			gotoStmt, gok := lastFT.Statement.(*stmt.GotoStatement)
			if gok {
				elseEnd := findNodeByOffset(nodes, gotoStmt.TargetOffset)
				if elseEnd != nil && elseEnd.Index > branchTarget.Index {
					hasElse = true
					elseBody = op03CollectStatements(fallThrough[:len(fallThrough)-1])
					thenRange := op03CollectRange(nodes, branchTarget.Index, elseEnd.Index)
					thenBody = op03CollectStatements(thenRange)
				}
			}
		}

		if hasElse {
			// Save the else-end offset before nop-ing
			elseEndGoto := lastFT.Statement.(*stmt.GotoStatement)
			elseEnd := findNodeByOffset(nodes, elseEndGoto.TargetOffset)

			structured := stmt.NewStructuredIf(
				ifStmt.Condition,
				stmt.NewBlock(thenBody...),
				stmt.NewBlock(elseBody...),
			)
			node.ReplaceStatement(structured)

			op03NopRange(nodes, i+1, branchTarget.Index)
			op03NopRange(nodes, branchTarget.Index, elseEnd.Index)
		} else {
			structured := stmt.NewStructuredIf(
				negateCondition(ifStmt.Condition),
				stmt.NewBlock(op03CollectStatements(fallThrough)...),
				nil,
			)
			node.ReplaceStatement(structured)
			op03NopRange(nodes, i+1, branchTarget.Index)
		}
	}

	return nodes
}

func findNodeByOffset(nodes []*Op03Node, offset int) *Op03Node {
	for _, n := range nodes {
		if n.Offset() == offset {
			return n
		}
	}

	// A branch target points to the first instruction of the target statement,
	// but value-producing instructions (e.g. the `iconst` before an `ireturn`)
	// are folded into the consuming statement and nop-removed, so no surviving
	// node carries the exact target offset. Resolve to the first surviving node
	// at or after the target — the statement the folded region became part of.
	var best *Op03Node
	for _, n := range nodes {
		off := n.Offset()
		if off < offset {
			continue
		}

		if best == nil || off < best.Offset() {
			best = n
		}
	}

	return best
}

func op03CollectRange(nodes []*Op03Node, start, end int) []*Op03Node {
	if start >= end || start >= len(nodes) {
		return nil
	}

	if end > len(nodes) {
		end = len(nodes)
	}

	result := make([]*Op03Node, 0, end-start)
	for i := start; i < end; i++ {
		result = append(result, nodes[i])
	}

	return result
}

func op03CollectStatements(nodes []*Op03Node) []stmt.Statement {
	stmts := make([]stmt.Statement, 0, len(nodes))
	for _, n := range nodes {
		if n.Statement != nil && n.Statement.Kind() != stmt.KindNop {
			stmts = append(stmts, n.Statement)
		}
	}

	return stmts
}

func op03NopRange(nodes []*Op03Node, start, end int) {
	if start >= len(nodes) {
		return
	}

	if end > len(nodes) {
		end = len(nodes)
	}

	for i := start; i < end; i++ {
		nodes[i].ReplaceStatement(stmt.NewNop())
	}
}
