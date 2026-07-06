package pipeline

import (
	"sort"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// structureSwitches converts flat SwitchStatements into StructuredSwitch with case bodies.
func structureSwitches(nodes []*Op03Node) []*Op03Node {
	for i := range nodes {
		node := nodes[i]
		if node.Statement == nil || node.Statement.Kind() != stmt.KindSwitch {
			continue
		}

		switchStmt, ok := node.Statement.(*stmt.SwitchStatement)
		if !ok {
			continue
		}

		structured := structureSwitchStmt(switchStmt, nodes, i)
		if structured != nil {
			node.ReplaceStatement(structured)
		}
	}

	return nodes
}

type switchCaseTarget struct {
	sc     stmt.SwitchCase
	target *Op03Node
}

func structureSwitchStmt(sw *stmt.SwitchStatement, nodes []*Op03Node, switchIdx int) *stmt.StructuredSwitch {
	if len(sw.Cases) == 0 {
		return nil
	}

	var targets []switchCaseTarget

	for _, c := range sw.Cases {
		target := findNodeByOffset(nodes, c.TargetOffset)
		if target == nil {
			return nil
		}

		targets = append(targets, switchCaseTarget{sc: c, target: target})
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].target.Index < targets[j].target.Index
	})

	switchEnd := findSwitchEnd(targets, nodes, switchIdx)

	cases := make([]stmt.StructuredCase, len(targets))
	for i, ct := range targets {
		var bodyEnd int
		if i+1 < len(targets) {
			bodyEnd = targets[i+1].target.Index
		} else if switchEnd != nil {
			bodyEnd = switchEnd.Index
		} else {
			bodyEnd = len(nodes)
		}

		bodyNodes := op03CollectRange(nodes, ct.target.Index, bodyEnd)
		bodyStmts := op03CollectStatements(bodyNodes)

		if len(bodyStmts) > 0 {
			last := bodyStmts[len(bodyStmts)-1]
			if g, gok := last.(*stmt.GotoStatement); gok {
				if switchEnd != nil && g.TargetOffset == switchEnd.Offset() {
					bodyStmts = bodyStmts[:len(bodyStmts)-1]
					bodyStmts = append(bodyStmts, stmt.NewBreak(""))
				}
			}
		}

		cases[i] = stmt.StructuredCase{
			Values:    ct.sc.Values,
			IsDefault: ct.sc.IsDefault,
			Body:      stmt.NewBlock(bodyStmts...),
		}

		op03NopRange(nodes, ct.target.Index, bodyEnd)
	}

	return stmt.NewStructuredSwitch(sw.Value, cases)
}

func findSwitchEnd(targets []switchCaseTarget, nodes []*Op03Node, switchIdx int) *Op03Node {
	if len(targets) == 0 {
		return nil
	}

	maxIdx := 0
	for _, ct := range targets {
		if ct.target.Index > maxIdx {
			maxIdx = ct.target.Index
		}
	}

	for i := switchIdx + 1; i < len(nodes) && i <= maxIdx+20; i++ {
		n := nodes[i]
		if n.Statement != nil && n.Statement.Kind() == stmt.KindGoto {
			g, gok := n.Statement.(*stmt.GotoStatement)
			if gok {
				endNode := findNodeByOffset(nodes, g.TargetOffset)
				if endNode != nil && endNode.Index > maxIdx {
					return endNode
				}
			}
		}
	}

	if maxIdx+1 < len(nodes) {
		return nodes[maxIdx+1]
	}

	return nil
}
