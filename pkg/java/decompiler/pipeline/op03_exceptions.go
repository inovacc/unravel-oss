package pipeline

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

type excCatchInfo struct {
	catchNode *Op03Node
	catchIdx  int
	blockID   int
}

type excTryInfo struct {
	tryNode   *Op03Node
	tryIdx    int
	blockID   int
	catches   []excCatchInfo
	tryEndIdx int
}

// structureExceptions converts flat try/catch markers into StructuredTry.
func structureExceptions(nodes []*Op03Node) []*Op03Node {
	var tries []excTryInfo

	for i, n := range nodes {
		if n.Statement == nil {
			continue
		}

		if n.Statement.Kind() == stmt.KindTry {
			ts, ok := n.Statement.(*stmt.TryStatement)
			if ok {
				tries = append(tries, excTryInfo{
					tryNode: n,
					tryIdx:  i,
					blockID: ts.BlockID,
				})
			}
		}
	}

	if len(tries) == 0 {
		return nodes
	}

	for ti := range tries {
		for i, n := range nodes {
			if n.Statement == nil {
				continue
			}

			if n.Statement.Kind() == stmt.KindCatch {
				cs, ok := n.Statement.(*stmt.CatchStatement)
				if ok && cs.BlockID == tries[ti].blockID {
					tries[ti].catches = append(tries[ti].catches, excCatchInfo{
						catchNode: n,
						catchIdx:  i,
						blockID:   cs.BlockID,
					})
				}
			}
		}

		if len(tries[ti].catches) > 0 {
			tries[ti].tryEndIdx = tries[ti].catches[0].catchIdx
		}
	}

	for i := len(tries) - 1; i >= 0; i-- {
		t := tries[i]
		if len(t.catches) == 0 {
			continue
		}

		structureTryBlock(nodes, t.tryIdx, t.tryEndIdx, t.catches)
	}

	return nodes
}

func structureTryBlock(nodes []*Op03Node, tryIdx, tryEndIdx int, catches []excCatchInfo) {
	tryBody := op03CollectStatements(op03CollectRange(nodes, tryIdx+1, tryEndIdx))

	var (
		clauses     []stmt.CatchClause
		hasFinally  bool
		finallyBody stmt.Statement
	)

	for ci, c := range catches {
		cs, ok := c.catchNode.Statement.(*stmt.CatchStatement)
		if !ok {
			continue
		}

		var catchEnd int
		if ci+1 < len(catches) {
			catchEnd = catches[ci+1].catchIdx
		} else {
			catchEnd = findCatchEnd(nodes, c.catchIdx)
		}

		catchBodyStmts := op03CollectStatements(op03CollectRange(nodes, c.catchIdx+1, catchEnd))

		if cs.ExceptionType == nil {
			hasFinally = true
			finallyBody = stmt.NewBlock(catchBodyStmts...)
		} else {
			clauses = append(clauses, stmt.CatchClause{
				ExceptionType: cs.ExceptionType,
				ExceptionVar:  cs.ExceptionVar,
				Body:          stmt.NewBlock(catchBodyStmts...),
			})
		}

		op03NopRange(nodes, c.catchIdx, catchEnd)
	}

	var fin stmt.Statement
	if hasFinally {
		fin = finallyBody
	}

	structured := stmt.NewStructuredTry(stmt.NewBlock(tryBody...), clauses, fin)

	nodes[tryIdx].ReplaceStatement(structured)
	op03NopRange(nodes, tryIdx+1, tryEndIdx)
}

func findCatchEnd(nodes []*Op03Node, catchIdx int) int {
	for i := catchIdx + 1; i < len(nodes); i++ {
		n := nodes[i]
		if n.Statement == nil {
			continue
		}

		switch n.Statement.Kind() {
		case stmt.KindTry, stmt.KindCatch:
			return i
		case stmt.KindReturn, stmt.KindReturnVoid, stmt.KindThrow:
			return i + 1
		}
	}

	return len(nodes)
}
