package pipeline

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// RemoveEmptyBlocks collapses empty block wrappers: Block{} → Nop.
func RemoveEmptyBlocks(nodes []*Op03Node) {
	for _, n := range nodes {
		if n.Statement != nil {
			n.Statement = removeEmptyBlock(n.Statement)
		}
	}
}

func removeEmptyBlock(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.Block:
		// Recursively clean children first
		filtered := make([]stmt.Statement, 0, len(st.Stmts))
		for _, child := range st.Stmts {
			child = removeEmptyBlock(child)
			if child.Kind() != stmt.KindNop {
				filtered = append(filtered, child)
			}
		}

		if len(filtered) == 0 {
			return stmt.NewNop()
		}
		// Unwrap single-statement blocks
		if len(filtered) == 1 {
			return filtered[0]
		}

		st.Stmts = filtered

		return st

	case *stmt.StructuredIf:
		st.Then = removeEmptyBlock(st.Then)
		if st.Else != nil {
			st.Else = removeEmptyBlock(st.Else)
			if st.Else.Kind() == stmt.KindNop {
				st.Else = nil
			}
		}
		// If the then body is empty and there's no else, the entire if is a nop
		if st.Then.Kind() == stmt.KindNop && st.Else == nil {
			return stmt.NewNop()
		}

		return st

	case *stmt.StructuredWhile:
		st.Body = removeEmptyBlock(st.Body)
		return st

	case *stmt.StructuredDoWhile:
		st.Body = removeEmptyBlock(st.Body)
		return st

	case *stmt.StructuredFor:
		st.Body = removeEmptyBlock(st.Body)
		return st

	case *stmt.StructuredTry:
		st.Body = removeEmptyBlock(st.Body)
		for i := range st.Catches {
			st.Catches[i].Body = removeEmptyBlock(st.Catches[i].Body)
		}

		if st.Finally != nil {
			st.Finally = removeEmptyBlock(st.Finally)
			if st.Finally.Kind() == stmt.KindNop {
				st.Finally = nil
			}
		}

		return st

	case *stmt.StructuredSynchronized:
		st.Body = removeEmptyBlock(st.Body)
		return st

	case *stmt.StructuredSwitch:
		for i := range st.Cases {
			if st.Cases[i].Body != nil {
				st.Cases[i].Body = removeEmptyBlock(st.Cases[i].Body)
			}
		}

		return st
	}

	return s
}

// RemoveRedundantGotos removes goto statements that target the immediately
// following node (i.e., fallthrough gotos that were not consumed by structuring).
func RemoveRedundantGotos(nodes []*Op03Node) {
	for i := 0; i < len(nodes)-1; i++ {
		if nodes[i].Statement == nil {
			continue
		}

		gotoStmt, ok := nodes[i].Statement.(*stmt.GotoStatement)
		if !ok {
			continue
		}
		// If goto targets the next node, it's redundant
		nextOffset := nodes[i+1].Offset()
		if nextOffset >= 0 && gotoStmt.TargetOffset == nextOffset {
			nodes[i].ReplaceStatement(stmt.NewNop())
		}
	}
}

// CollapseLinearBlocks merges adjacent nodes that form a linear chain
// (single target → single source) into Block statements.
func CollapseLinearBlocks(nodes []*Op03Node) {
	for _, n := range nodes {
		if n.Statement != nil {
			n.Statement = flattenNestedBlocks(n.Statement)
		}
	}
}

// flattenNestedBlocks recursively flattens Block{Block{...}} → Block{...}.
func flattenNestedBlocks(s stmt.Statement) stmt.Statement {
	block, ok := s.(*stmt.Block)
	if !ok {
		return s
	}

	flat := make([]stmt.Statement, 0, len(block.Stmts))
	for _, child := range block.Stmts {
		child = flattenNestedBlocks(child)
		// Flatten nested blocks
		if inner, ok := child.(*stmt.Block); ok {
			flat = append(flat, inner.Stmts...)
		} else {
			flat = append(flat, child)
		}
	}

	block.Stmts = flat

	return block
}
