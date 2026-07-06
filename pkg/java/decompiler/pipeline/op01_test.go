package pipeline

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
)

// makeInstr is a minimal helper to build a decoded Instruction for testing.
func makeInstr(offset int, op bytecode.Opcode, operand []byte) *bytecode.Instruction {
	length := 1 + len(operand)
	return &bytecode.Instruction{
		Offset:  offset,
		Op:      op,
		Operand: operand,
		Length:  length,
	}
}

// ---------- BuildCFG ----------

func TestBuildCFG_SingleReturn(t *testing.T) {
	instrs := []*bytecode.Instruction{
		makeInstr(0, bytecode.RETURN, nil),
	}
	nodes, err := buildCFGFromInstrs(instrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1 node, got %d", len(nodes))
	}
	if len(nodes[0].Targets) != 0 {
		t.Errorf("RETURN should have no successors")
	}
}

func TestBuildCFG_FallthroughChain(t *testing.T) {
	// NOP NOP RETURN — linear fallthrough
	instrs := []*bytecode.Instruction{
		makeInstr(0, bytecode.NOP, nil),
		makeInstr(1, bytecode.NOP, nil),
		makeInstr(2, bytecode.RETURN, nil),
	}
	nodes, err := buildCFGFromInstrs(instrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("want 3, got %d", len(nodes))
	}
	// Each non-terminal should target next
	if len(nodes[0].Targets) != 1 || nodes[0].Targets[0] != nodes[1] {
		t.Error("nodes[0] should target nodes[1]")
	}
	if len(nodes[1].Targets) != 1 || nodes[1].Targets[0] != nodes[2] {
		t.Error("nodes[1] should target nodes[2]")
	}
	if len(nodes[2].Targets) != 0 {
		t.Error("RETURN should have no targets")
	}
}

func TestBuildCFG_GotoSelf(t *testing.T) {
	// GOTO targeting offset 0 (infinite loop)
	// offset=0, opcode=GOTO (0xa7), operand: int16 big-endian offset 0 (relative) = 0x0000
	instrs := []*bytecode.Instruction{
		{Offset: 0, Op: bytecode.GOTO, Operand: []byte{0x00, 0x00}, Length: 3},
	}
	nodes, err := buildCFGFromInstrs(instrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("want 1, got %d", len(nodes))
	}
	// GOTO self — should link to itself
	if len(nodes[0].Targets) != 1 || nodes[0].Targets[0] != nodes[0] {
		t.Error("GOTO self should link to itself")
	}
}

func TestBuildCFG_UnknownOpcode(t *testing.T) {
	// Use an opcode value not in the table — 0xFE is reserved/unknown
	instrs := []*bytecode.Instruction{
		{Offset: 0, Op: bytecode.Opcode(0xFE), Operand: nil, Length: 1},
	}
	_, err := buildCFGFromInstrs(instrs)
	if err == nil {
		t.Error("expected error for unknown opcode")
	}
}

func TestBuildCFG_ATHROWIsTerminal(t *testing.T) {
	instrs := []*bytecode.Instruction{
		makeInstr(0, bytecode.ATHROW, nil),
	}
	nodes, err := buildCFGFromInstrs(instrs)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes[0].Targets) != 0 {
		t.Error("ATHROW should have no successors")
	}
}

func TestBuildCFG_ConditionalBranch(t *testing.T) {
	// IFEQ at offset 0 branching to offset 3; NOP at 3; RETURN at 4
	// IFEQ operand: big-endian int16 offset=+3 → branch to 0+3=3
	instrs := []*bytecode.Instruction{
		{Offset: 0, Op: bytecode.IFEQ, Operand: []byte{0x00, 0x03}, Length: 3},
		{Offset: 3, Op: bytecode.NOP, Operand: nil, Length: 1},
		{Offset: 4, Op: bytecode.RETURN, Operand: nil, Length: 1},
	}
	nodes, err := buildCFGFromInstrs(instrs)
	if err != nil {
		t.Fatal(err)
	}
	// IFEQ should have 2 targets: branch target (offset 3) and fallthrough (offset 3 also here)
	// Actually branch=3 and fallthrough=nodes[1]; since both are same offset it may dedup
	if len(nodes) != 3 {
		t.Fatalf("want 3 nodes, got %d", len(nodes))
	}
	// nodes[0] (IFEQ) should target both nodes[1] (offset 3) via branch
	// and nodes[1] via fallthrough — both point to same node
	ifeqNode := nodes[0]
	if len(ifeqNode.Targets) < 1 {
		t.Errorf("IFEQ should have targets, got %d", len(ifeqNode.Targets))
	}
}

func TestBuildCFG_InvalidBranchTarget(t *testing.T) {
	// GOTO targeting offset 999 which doesn't exist
	instrs := []*bytecode.Instruction{
		{Offset: 0, Op: bytecode.GOTO, Operand: []byte{0x03, 0xE7}, Length: 3}, // offset=+999 → target=999
	}
	_, err := buildCFGFromInstrs(instrs)
	if err == nil {
		t.Error("expected error for invalid branch target")
	}
}

// buildCFGFromInstrs is a convenience wrapper that calls BuildCFG.
func buildCFGFromInstrs(instrs []*bytecode.Instruction) ([]*InstrNode, error) {
	return BuildCFG(instrs)
}

// ---------- InsertExceptionEdges ----------

func TestInsertExceptionEdges_Empty(t *testing.T) {
	nodes := []*InstrNode{
		{Index: 0, Instr: makeInstr(0, bytecode.NOP, nil)},
	}
	err := InsertExceptionEdges(nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInsertExceptionEdges_AddsEdge(t *testing.T) {
	// try range: offset 0..2; handler at offset 4
	instrs := []*bytecode.Instruction{
		makeInstr(0, bytecode.NOP, nil),
		makeInstr(1, bytecode.NOP, nil),
		makeInstr(4, bytecode.RETURN, nil),
	}
	nodes := make([]*InstrNode, len(instrs))
	for i, instr := range instrs {
		nodes[i] = NewInstrNode(i, instr)
	}

	exc := []ExceptionEntry{
		{StartPC: 0, EndPC: 2, HandlerPC: 4, CatchType: "java/lang/Exception"},
	}
	err := InsertExceptionEdges(nodes, exc)
	if err != nil {
		t.Fatal(err)
	}
	// nodes[0] (offset 0) should have an edge to nodes[2] (offset 4)
	hasEdge := false
	for _, t2 := range nodes[0].Targets {
		if t2 == nodes[2] {
			hasEdge = true
		}
	}
	if !hasEdge {
		t.Error("expected exception edge from offset 0 to handler at offset 4")
	}
}

func TestInsertExceptionEdges_InvalidHandler(t *testing.T) {
	nodes := []*InstrNode{
		{Index: 0, Instr: makeInstr(0, bytecode.NOP, nil)},
	}
	exc := []ExceptionEntry{
		{StartPC: 0, EndPC: 1, HandlerPC: 999},
	}
	err := InsertExceptionEdges(nodes, exc)
	if err == nil {
		t.Error("expected error for invalid handler offset")
	}
}

func TestInsertExceptionEdges_DoesNotDuplicateEdge(t *testing.T) {
	instrs := []*bytecode.Instruction{
		makeInstr(0, bytecode.NOP, nil),
		makeInstr(1, bytecode.RETURN, nil),
	}
	nodes := make([]*InstrNode, len(instrs))
	for i, instr := range instrs {
		nodes[i] = NewInstrNode(i, instr)
		nodes[i].Index = i
	}
	// Pre-link node 0 → node 1 (as if it already targets the handler)
	Link(nodes[0], nodes[1])

	exc := []ExceptionEntry{
		{StartPC: 0, EndPC: 1, HandlerPC: 1},
	}
	err := InsertExceptionEdges(nodes, exc)
	if err != nil {
		t.Fatal(err)
	}
	// Should still be exactly 1 target (no dup)
	if len(nodes[0].Targets) != 1 {
		t.Errorf("want 1 target (no dup), got %d", len(nodes[0].Targets))
	}
}

// ---------- FindReachable ----------

func TestFindReachable_SingleNode(t *testing.T) {
	n := NewInstrNode(0, nil)
	r := FindReachable([]*InstrNode{n})
	if !r[0] {
		t.Error("entry node should be reachable")
	}
}

func TestFindReachable_ChainAllReachable(t *testing.T) {
	a := NewInstrNode(0, nil)
	b := NewInstrNode(1, nil)
	c := NewInstrNode(2, nil)
	Link(a, b)
	Link(b, c)

	r := FindReachable([]*InstrNode{a, b, c})
	for i := range 3 {
		if !r[i] {
			t.Errorf("node %d should be reachable", i)
		}
	}
}

func TestFindReachable_UnreachableNode(t *testing.T) {
	a := NewInstrNode(0, nil)
	b := NewInstrNode(1, nil) // b has no incoming edge from a

	r := FindReachable([]*InstrNode{a, b})
	if !r[0] {
		t.Error("entry should be reachable")
	}
	if r[1] {
		t.Error("b is unreachable from a")
	}
}

// ---------- InsertExceptionMarkers ----------

func TestInsertExceptionMarkers_NoExceptions(t *testing.T) {
	nodes := []*InstrNode{
		{Index: 0, Instr: makeInstr(0, bytecode.NOP, nil), Statement: stmt.NewNop()},
	}
	result := InsertExceptionMarkers(nodes, nil)
	if len(result) != 1 {
		t.Errorf("no exceptions: want 1 node, got %d", len(result))
	}
}

func TestInsertExceptionMarkers_InsertsMarkers(t *testing.T) {
	nodes := []*InstrNode{
		{Index: 0, Instr: makeInstr(0, bytecode.NOP, nil), Statement: stmt.NewNop()},
		{Index: 1, Instr: makeInstr(1, bytecode.NOP, nil), Statement: stmt.NewNop()},
		{Index: 2, Instr: makeInstr(5, bytecode.RETURN, nil), Statement: stmt.NewReturnVoid()},
	}

	exc := []ExceptionEntry{
		{StartPC: 0, EndPC: 2, HandlerPC: 5, CatchType: "java/lang/RuntimeException"},
	}
	result := InsertExceptionMarkers(nodes, exc)
	// Should have original 3 + 2 markers (try + catch) = 5
	if len(result) < 4 {
		t.Errorf("expected ≥4 nodes after inserting markers, got %d", len(result))
	}

	// All nodes should be re-indexed
	for i, n := range result {
		if n.Index != i {
			t.Errorf("node at pos %d has Index=%d", i, n.Index)
		}
	}

	// Synthetic nodes should be flagged
	syntheticCount := 0
	for _, n := range result {
		if n.Synthetic {
			syntheticCount++
		}
	}
	if syntheticCount < 2 {
		t.Errorf("expected ≥2 synthetic markers, got %d", syntheticCount)
	}
}

func TestInsertExceptionMarkers_FinallyNilType(t *testing.T) {
	// CatchType="" means finally (catch-all)
	nodes := []*InstrNode{
		{Index: 0, Instr: makeInstr(0, bytecode.NOP, nil), Statement: stmt.NewNop()},
		{Index: 1, Instr: makeInstr(5, bytecode.RETURN, nil), Statement: stmt.NewReturnVoid()},
	}
	exc := []ExceptionEntry{
		{StartPC: 0, EndPC: 1, HandlerPC: 5, CatchType: ""},
	}
	result := InsertExceptionMarkers(nodes, exc)
	if len(result) == 0 {
		t.Error("expected nodes")
	}
	// Find catch marker and verify nil exception type
	for _, n := range result {
		if n.Synthetic {
			if catchStmt, ok := n.Statement.(*stmt.CatchStatement); ok {
				if catchStmt.ExceptionType != nil {
					t.Error("finally catch should have nil exception type")
				}
			}
		}
	}
}
