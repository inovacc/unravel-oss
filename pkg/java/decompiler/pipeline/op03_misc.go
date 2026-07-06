package pipeline

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// structureSynchronized converts monitorenter/monitorexit pairs into
// StructuredSynchronized statements.
func structureSynchronized(nodes []*Op03Node) []*Op03Node {
	for i := range nodes {
		n := nodes[i]
		if n.Statement == nil || n.Statement.Kind() != stmt.KindMonitorEnter {
			continue
		}

		monEnter, ok := n.Statement.(*stmt.MonitorEnterStatement)
		if !ok {
			continue
		}

		exitIdx := -1

		for j := i + 1; j < len(nodes); j++ {
			if nodes[j].Statement != nil && nodes[j].Statement.Kind() == stmt.KindMonitorExit {
				exitIdx = j
				break
			}
		}

		if exitIdx < 0 {
			continue
		}

		bodyStmts := op03CollectStatements(op03CollectRange(nodes, i+1, exitIdx))

		structured := stmt.NewStructuredSynchronized(
			monEnter.Object,
			stmt.NewBlock(bodyStmts...),
		)

		n.ReplaceStatement(structured)
		op03NopRange(nodes, i+1, exitIdx+1)
	}

	return nodes
}
