package pipeline

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// ---------- Op03Node construction ----------

func TestNewOp03Node(t *testing.T) {
	instr := NewInstrNode(3, nil)
	instr.Statement = stmt.NewNop()

	n := NewOp03Node(3, instr)
	if n.Index != 3 {
		t.Errorf("Index: want 3, got %d", n.Index)
	}
	if n.InstrNode != instr {
		t.Error("InstrNode not set")
	}
	if n.BlockIdx != -1 {
		t.Errorf("BlockIdx: want -1, got %d", n.BlockIdx)
	}
	if !n.IsNop() {
		t.Error("statement is nop, IsNop should be true")
	}
}

func TestNewSyntheticOp03Node(t *testing.T) {
	s := stmt.NewReturnVoid()
	n := NewSyntheticOp03Node(7, s)
	if n.InstrNode != nil {
		t.Error("synthetic node should have nil InstrNode")
	}
	if n.Statement != s {
		t.Error("statement mismatch")
	}
	if n.IsNop() {
		t.Error("non-nop statement should not report IsNop")
	}
}

func TestOp03Node_IsNop_Nil(t *testing.T) {
	n := &Op03Node{Statement: nil}
	if !n.IsNop() {
		t.Error("nil statement should be nop")
	}
}

func TestOp03Node_Offset_Synthetic(t *testing.T) {
	n := NewSyntheticOp03Node(0, stmt.NewNop())
	if n.Offset() != -1 {
		t.Errorf("synthetic offset: want -1, got %d", n.Offset())
	}
}

// ---------- LinkOp03 / UnlinkOp03 ----------

func TestLinkOp03_Bidirectional(t *testing.T) {
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewNop())

	LinkOp03(a, b)
	if len(a.Targets) != 1 || a.Targets[0] != b {
		t.Error("LinkOp03: a should target b")
	}
	if len(b.Sources) != 1 || b.Sources[0] != a {
		t.Error("LinkOp03: b should source a")
	}
}

func TestUnlinkOp03_RemovesEdges(t *testing.T) {
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewNop())

	LinkOp03(a, b)
	UnlinkOp03(a, b)

	if len(a.Targets) != 0 {
		t.Errorf("targets not cleared: %d", len(a.Targets))
	}
	if len(b.Sources) != 0 {
		t.Errorf("sources not cleared: %d", len(b.Sources))
	}
}

// ---------- BasicBlock ----------

func TestBasicBlock_HeadTail_Empty(t *testing.T) {
	b := &BasicBlock{}
	if b.Head() != nil {
		t.Error("empty block Head should be nil")
	}
	if b.Tail() != nil {
		t.Error("empty block Tail should be nil")
	}
	if len(b.Statements()) != 0 {
		t.Error("empty block Statements should be empty")
	}
}

func TestBasicBlock_HeadTail_Single(t *testing.T) {
	n := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	b := &BasicBlock{Index: 0, Nodes: []*Op03Node{n}}
	if b.Head() != n {
		t.Error("Head mismatch")
	}
	if b.Tail() != n {
		t.Error("Tail mismatch")
	}
	stmts := b.Statements()
	if len(stmts) != 1 {
		t.Errorf("want 1 statement, got %d", len(stmts))
	}
}

func TestBasicBlock_Statements_FiltersNop(t *testing.T) {
	nopNode := NewSyntheticOp03Node(0, stmt.NewNop())
	retNode := NewSyntheticOp03Node(1, stmt.NewReturnVoid())
	b := &BasicBlock{Nodes: []*Op03Node{nopNode, retNode}}
	stmts := b.Statements()
	if len(stmts) != 1 {
		t.Errorf("want 1 non-nop statement, got %d", len(stmts))
	}
	if stmts[0].Kind() != stmt.KindReturnVoid {
		t.Error("expected ReturnVoid")
	}
}

// ---------- BuildOp03Graph ----------

func TestBuildOp03Graph_Empty(t *testing.T) {
	nodes := BuildOp03Graph(nil)
	if len(nodes) != 0 {
		t.Errorf("want 0, got %d", len(nodes))
	}
}

func TestBuildOp03Graph_EdgesPreserved(t *testing.T) {
	// Create two linked InstrNodes
	a := NewInstrNode(0, nil)
	b := NewInstrNode(1, nil)
	a.Statement = stmt.NewNop()
	b.Statement = stmt.NewReturnVoid()
	Link(a, b)

	op03 := BuildOp03Graph([]*InstrNode{a, b})
	if len(op03) != 2 {
		t.Fatalf("want 2, got %d", len(op03))
	}
	if len(op03[0].Targets) != 1 || op03[0].Targets[0] != op03[1] {
		t.Error("edges not rebuilt correctly")
	}
}

// ---------- CollectStatements ----------

func TestCollectStatements_FiltersNops(t *testing.T) {
	nodes := []*Op03Node{
		NewSyntheticOp03Node(0, stmt.NewNop()),
		NewSyntheticOp03Node(1, stmt.NewReturnVoid()),
		NewSyntheticOp03Node(2, stmt.NewNop()),
	}
	stmts := CollectStatements(nodes)
	if len(stmts) != 1 {
		t.Errorf("want 1, got %d", len(stmts))
	}
}

func TestCollectStatements_Empty(t *testing.T) {
	if len(CollectStatements(nil)) != 0 {
		t.Error("nil input should produce empty slice")
	}
}

// ---------- RemoveNops ----------

func TestRemoveNops_RemovesNopNodes(t *testing.T) {
	a := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	nop := NewSyntheticOp03Node(1, stmt.NewNop())

	result := RemoveNops([]*Op03Node{a, nop})
	if len(result) != 1 {
		t.Errorf("want 1, got %d", len(result))
	}
	if result[0].Statement.Kind() != stmt.KindReturnVoid {
		t.Error("wrong node retained")
	}
}

func TestRemoveNops_ReIndexes(t *testing.T) {
	nodes := make([]*Op03Node, 3)
	for i := range nodes {
		nodes[i] = NewSyntheticOp03Node(i, stmt.NewReturnVoid())
	}
	// Remove middle node (make it nop)
	nodes[1].Statement = stmt.NewNop()
	result := RemoveNops(nodes)
	for i, n := range result {
		if n.Index != i {
			t.Errorf("node at pos %d has Index=%d", i, n.Index)
		}
	}
}

func TestRemoveNops_PatchesEdges(t *testing.T) {
	// a → nop → b: after removing nop, a → b
	a := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	nop := NewSyntheticOp03Node(1, stmt.NewNop())
	b := NewSyntheticOp03Node(2, stmt.NewReturnVoid())
	LinkOp03(a, nop)
	LinkOp03(nop, b)

	result := RemoveNops([]*Op03Node{a, nop, b})
	if len(result) != 2 {
		t.Fatalf("want 2, got %d", len(result))
	}
	// a should now target b
	if len(result[0].Targets) != 1 || result[0].Targets[0] != b {
		t.Error("edge not patched after nop removal")
	}
}

func TestLinkOp03_NoDuplicateEdges(t *testing.T) {
	// The op03 graph is a simple graph: removeOp03Node/hasTarget assume set
	// semantics, so LinkOp03 must not create parallel edges.
	a := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	b := NewSyntheticOp03Node(1, stmt.NewReturnVoid())
	LinkOp03(a, b)
	LinkOp03(a, b)
	if got := len(a.Targets); got != 1 {
		t.Fatalf("a.Targets = %d, want 1 (no duplicate edges)", got)
	}
	if got := len(b.Sources); got != 1 {
		t.Fatalf("b.Sources = %d, want 1 (no duplicate edges)", got)
	}
}

func TestRemoveNops_NoDuplicateEdgesAcrossParallelNops(t *testing.T) {
	// a → nop1 → b and a → nop2 → b. Removing both nops must leave a single
	// a→b edge. Duplicate edges here compound across chained nops into a
	// super-exponential edge blowup that hangs op03 (IRPF2020 classes/dt,dA,dG).
	a := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	nop1 := NewSyntheticOp03Node(1, stmt.NewNop())
	nop2 := NewSyntheticOp03Node(2, stmt.NewNop())
	b := NewSyntheticOp03Node(3, stmt.NewReturnVoid())
	LinkOp03(a, nop1)
	LinkOp03(nop1, b)
	LinkOp03(a, nop2)
	LinkOp03(nop2, b)

	result := RemoveNops([]*Op03Node{a, nop1, nop2, b})
	if len(result) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(result))
	}

	targets := 0
	for _, tgt := range a.Targets {
		if tgt == b {
			targets++
		}
	}
	if targets != 1 {
		t.Fatalf("a→b edge count = %d, want 1 (duplicate edges cause op03 blowup)", targets)
	}

	sources := 0
	for _, src := range b.Sources {
		if src == a {
			sources++
		}
	}
	if sources != 1 {
		t.Fatalf("b←a source count = %d, want 1", sources)
	}
}

// ---------- BuildBasicBlocks ----------

func TestBuildBasicBlocks_Empty(t *testing.T) {
	if len(BuildBasicBlocks(nil)) != 0 {
		t.Error("nil input should produce empty")
	}
}

func TestBuildBasicBlocks_Single(t *testing.T) {
	n := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	blocks := BuildBasicBlocks([]*Op03Node{n})
	if len(blocks) != 1 {
		t.Fatalf("want 1 block, got %d", len(blocks))
	}
	if len(blocks[0].Nodes) != 1 {
		t.Errorf("want 1 node in block, got %d", len(blocks[0].Nodes))
	}
}

func TestBuildBasicBlocks_LinearChain(t *testing.T) {
	// a → b → c (linear, no branches) — should be one block
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewNop())
	c := NewSyntheticOp03Node(2, stmt.NewReturnVoid())
	LinkOp03(a, b)
	LinkOp03(b, c)

	blocks := BuildBasicBlocks([]*Op03Node{a, b, c})
	// All have single in/out — should merge into one block
	if len(blocks) == 0 {
		t.Error("expected at least one block")
	}
}

// ---------- TopologicalSort ----------

func TestTopologicalSort_Empty(t *testing.T) {
	if len(TopologicalSort(nil)) != 0 {
		t.Error("nil input should return nil")
	}
}

func TestTopologicalSort_Single(t *testing.T) {
	n := NewSyntheticOp03Node(0, stmt.NewReturnVoid())
	result := TopologicalSort([]*Op03Node{n})
	if len(result) != 1 || result[0] != n {
		t.Error("single node topo sort should return same node")
	}
}

func TestTopologicalSort_Linear(t *testing.T) {
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewNop())
	c := NewSyntheticOp03Node(2, stmt.NewReturnVoid())
	LinkOp03(a, b)
	LinkOp03(b, c)

	result := TopologicalSort([]*Op03Node{a, b, c})
	if len(result) != 3 {
		t.Fatalf("want 3, got %d", len(result))
	}
	// a must come before b, b before c
	indexOf := func(n *Op03Node) int {
		for i, x := range result {
			if x == n {
				return i
			}
		}
		return -1
	}
	if indexOf(a) > indexOf(b) || indexOf(b) > indexOf(c) {
		t.Error("topological order violated")
	}
}

func TestTopologicalSort_WithCycle(t *testing.T) {
	// Loop: a → b → a (cycle), c unreachable
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewNop())
	c := NewSyntheticOp03Node(2, stmt.NewReturnVoid())
	LinkOp03(a, b)
	LinkOp03(b, a) // back edge
	// c is unreachable but present

	result := TopologicalSort([]*Op03Node{a, b, c})
	// Should not hang or panic — all nodes visited
	if len(result) < 2 {
		t.Errorf("want at least 2 nodes, got %d", len(result))
	}
}

// ---------- FindBackEdges ----------

func TestFindBackEdges_Empty(t *testing.T) {
	if len(FindBackEdges(nil)) != 0 {
		t.Error("nil input should return nil")
	}
}

func TestFindBackEdges_NoLoop(t *testing.T) {
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewReturnVoid())
	LinkOp03(a, b)

	edges := FindBackEdges([]*Op03Node{a, b})
	if len(edges) != 0 {
		t.Errorf("no loops, expected 0 back edges, got %d", len(edges))
	}
}

func TestFindBackEdges_SimpleLoop(t *testing.T) {
	// a → b → a
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	b := NewSyntheticOp03Node(1, stmt.NewNop())
	LinkOp03(a, b)
	LinkOp03(b, a)

	edges := FindBackEdges([]*Op03Node{a, b})
	if len(edges) == 0 {
		t.Error("expected a back edge for simple loop")
	}
	// The back edge should be b→a (b is latch, a is header)
	found := false
	for _, e := range edges {
		if e.Source == b && e.Target == a {
			found = true
		}
	}
	if !found {
		t.Error("expected back edge b→a")
	}
}

// ---------- FindLoopBody ----------

func TestFindLoopBody_SelfLoop(t *testing.T) {
	a := NewSyntheticOp03Node(0, stmt.NewNop())
	body := FindLoopBody(a, a)
	if len(body) != 1 || body[0] != a {
		t.Error("self-loop body should be just the header")
	}
}

func TestFindLoopBody_SimpleLoop(t *testing.T) {
	header := NewSyntheticOp03Node(0, stmt.NewNop())
	body1 := NewSyntheticOp03Node(1, stmt.NewNop())
	latch := NewSyntheticOp03Node(2, stmt.NewNop())
	LinkOp03(header, body1)
	LinkOp03(body1, latch)
	LinkOp03(latch, header)

	result := FindLoopBody(header, latch)
	if len(result) != 3 {
		t.Errorf("want 3 body nodes, got %d", len(result))
	}
}

// ---------- sortOp03Nodes ----------

func TestSortOp03Nodes(t *testing.T) {
	nodes := []*Op03Node{
		{Index: 5},
		{Index: 1},
		{Index: 3},
	}
	sortOp03Nodes(nodes)
	for i := 1; i < len(nodes); i++ {
		if nodes[i-1].Index > nodes[i].Index {
			t.Errorf("not sorted at %d: %d > %d", i, nodes[i-1].Index, nodes[i].Index)
		}
	}
}

// ---------- ReplaceStatement ----------

func TestOp03Node_ReplaceStatement(t *testing.T) {
	n := NewSyntheticOp03Node(0, stmt.NewNop())
	ret := stmt.NewReturnVoid()
	n.ReplaceStatement(ret)
	if n.Statement != ret {
		t.Error("ReplaceStatement did not replace")
	}
}
