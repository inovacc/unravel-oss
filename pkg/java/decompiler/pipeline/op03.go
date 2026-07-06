package pipeline

import (
	"slices"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// Op03Node wraps an InstrNode with block tracking and graph manipulation
// for the control flow structuring phase.
type Op03Node struct {
	Index     int            // position in the linearized node list
	InstrNode *InstrNode     // underlying instruction node (nil for synthetic)
	Statement stmt.Statement // current statement (may be replaced during structuring)
	BlockIdx  int            // basic block index (-1 = unassigned)
	Targets   []*Op03Node    // successor nodes
	Sources   []*Op03Node    // predecessor nodes
	Visited   bool           // scratch flag for graph traversal
}

// NewOp03Node creates an Op03Node from an InstrNode.
func NewOp03Node(index int, instrNode *InstrNode) *Op03Node {
	return &Op03Node{
		Index:     index,
		InstrNode: instrNode,
		Statement: instrNode.Statement,
		BlockIdx:  -1,
	}
}

// NewSyntheticOp03Node creates a synthetic Op03Node with a given statement.
func NewSyntheticOp03Node(index int, statement stmt.Statement) *Op03Node {
	return &Op03Node{
		Index:     index,
		Statement: statement,
		BlockIdx:  -1,
	}
}

// Offset returns the bytecode offset of the underlying instruction, or -1 if synthetic.
func (n *Op03Node) Offset() int {
	if n.InstrNode != nil && n.InstrNode.Instr != nil {
		return n.InstrNode.Instr.Offset
	}

	return -1
}

// ReplaceStatement replaces this node's statement.
func (n *Op03Node) ReplaceStatement(s stmt.Statement) {
	n.Statement = s
}

// IsNop returns true if this node's statement is a nop or nil.
func (n *Op03Node) IsNop() bool {
	if n.Statement == nil {
		return true
	}

	return n.Statement.Kind() == stmt.KindNop
}

// AddTarget adds a successor edge.
func (n *Op03Node) AddTarget(target *Op03Node) {
	n.Targets = append(n.Targets, target)
}

// AddSource adds a predecessor edge.
func (n *Op03Node) AddSource(source *Op03Node) {
	n.Sources = append(n.Sources, source)
}

// LinkOp03 creates bidirectional edges between two Op03 nodes. The op03 graph
// is a simple graph (removeOp03Node/hasTarget treat edges as a set), so a
// duplicate edge is a no-op. Without this guard, RemoveNops patching chained
// nops multiplies parallel edges super-exponentially and hangs on some
// obfuscated classes.
func LinkOp03(source, target *Op03Node) {
	if hasTarget(source, target) {
		return
	}
	source.AddTarget(target)
	target.AddSource(source)
}

// UnlinkOp03 removes bidirectional edges between two Op03 nodes.
func UnlinkOp03(source, target *Op03Node) {
	source.Targets = removeOp03Node(source.Targets, target)
	target.Sources = removeOp03Node(target.Sources, source)
}

func removeOp03Node(nodes []*Op03Node, target *Op03Node) []*Op03Node {
	result := make([]*Op03Node, 0, len(nodes))
	for _, n := range nodes {
		if n != target {
			result = append(result, n)
		}
	}

	return result
}

// BasicBlock represents a sequence of Op03 nodes with single-entry/single-exit flow.
type BasicBlock struct {
	Index int
	Nodes []*Op03Node
}

// Head returns the first node in the block.
func (b *BasicBlock) Head() *Op03Node {
	if len(b.Nodes) > 0 {
		return b.Nodes[0]
	}

	return nil
}

// Tail returns the last node in the block.
func (b *BasicBlock) Tail() *Op03Node {
	if len(b.Nodes) > 0 {
		return b.Nodes[len(b.Nodes)-1]
	}

	return nil
}

// Statements returns all non-nop statements in the block.
func (b *BasicBlock) Statements() []stmt.Statement {
	stmts := make([]stmt.Statement, 0, len(b.Nodes))
	for _, n := range b.Nodes {
		if n.Statement != nil && n.Statement.Kind() != stmt.KindNop {
			stmts = append(stmts, n.Statement)
		}
	}

	return stmts
}

// BuildOp03Graph converts the Op02 InstrNode CFG into Op03Node graph.
func BuildOp03Graph(instrNodes []*InstrNode) []*Op03Node {
	op03Nodes := make([]*Op03Node, len(instrNodes))
	for i, n := range instrNodes {
		op03Nodes[i] = NewOp03Node(i, n)
	}

	// Rebuild edges using Op03 nodes
	for i, instrN := range instrNodes {
		for _, target := range instrN.Targets {
			LinkOp03(op03Nodes[i], op03Nodes[target.Index])
		}
	}

	return op03Nodes
}

// BuildBasicBlocks groups nodes into basic blocks.
// A new block starts when:
// - Node has multiple predecessors
// - Node has multiple successors
// - Previous node has multiple successors
func BuildBasicBlocks(nodes []*Op03Node) []*BasicBlock {
	if len(nodes) == 0 {
		return nil
	}

	var (
		blocks  []*BasicBlock
		current *BasicBlock
	)

	for _, node := range nodes {
		startNew := current == nil
		if !startNew {
			// Start new block if this node has multiple predecessors
			if len(node.Sources) != 1 {
				startNew = true
			}
			// Start new block if previous node has multiple successors
			tail := current.Tail()
			if tail != nil && len(tail.Targets) != 1 {
				startNew = true
			}
			// Start new block if previous node doesn't link to this one
			if tail != nil && !hasTarget(tail, node) {
				startNew = true
			}
		}

		if startNew {
			current = &BasicBlock{Index: len(blocks)}
			blocks = append(blocks, current)
		}

		node.BlockIdx = current.Index
		current.Nodes = append(current.Nodes, node)
	}

	return blocks
}

func hasTarget(source, target *Op03Node) bool {
	return slices.Contains(source.Targets, target)
}

// TopologicalSort returns nodes in topological order (handles cycles via DFS).
func TopologicalSort(nodes []*Op03Node) []*Op03Node {
	if len(nodes) == 0 {
		return nil
	}

	visited := make(map[int]bool)
	onStack := make(map[int]bool)

	var result []*Op03Node

	var visit func(n *Op03Node)

	visit = func(n *Op03Node) {
		if visited[n.Index] {
			return
		}

		if onStack[n.Index] {
			// Back edge (cycle) — skip to avoid infinite recursion
			return
		}

		onStack[n.Index] = true

		for _, target := range n.Targets {
			visit(target)
		}

		onStack[n.Index] = false
		visited[n.Index] = true
		result = append(result, n)
	}

	// Start from node 0 (method entry)
	visit(nodes[0])

	// Also visit any unreachable nodes
	for _, n := range nodes {
		if !visited[n.Index] {
			visit(n)
		}
	}

	// Reverse for topological order (post-order DFS gives reverse topo)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// CollectStatements linearizes the Op03 graph into a flat statement list,
// collecting all non-nop statements in node order.
func CollectStatements(nodes []*Op03Node) []stmt.Statement {
	stmts := make([]stmt.Statement, 0, len(nodes))
	for _, n := range nodes {
		if n.Statement != nil && n.Statement.Kind() != stmt.KindNop {
			stmts = append(stmts, n.Statement)
		}
	}

	return stmts
}

// FindBackEdges identifies back edges in the CFG using DFS.
// A back edge (source → target) exists when target dominates source,
// indicating a loop.
type BackEdge struct {
	Source *Op03Node
	Target *Op03Node // loop header
}

func FindBackEdges(nodes []*Op03Node) []BackEdge {
	if len(nodes) == 0 {
		return nil
	}

	visited := make(map[int]bool)
	onStack := make(map[int]bool)

	var edges []BackEdge

	var visit func(n *Op03Node)

	visit = func(n *Op03Node) {
		visited[n.Index] = true
		onStack[n.Index] = true

		for _, target := range n.Targets {
			if onStack[target.Index] {
				// Back edge found: n → target (target is loop header)
				edges = append(edges, BackEdge{Source: n, Target: target})
			} else if !visited[target.Index] {
				visit(target)
			}
		}

		onStack[n.Index] = false
	}

	visit(nodes[0])

	return edges
}

// FindLoopBody collects all nodes belonging to a natural loop
// defined by the back edge (latch → header).
func FindLoopBody(header, latch *Op03Node) []*Op03Node {
	body := make(map[int]*Op03Node)
	body[header.Index] = header
	body[latch.Index] = latch

	if header == latch {
		return []*Op03Node{header}
	}

	// Walk backwards from latch to header, collecting all nodes
	// that can reach the latch without going through the header.
	var stack []*Op03Node

	stack = append(stack, latch)

	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		for _, pred := range n.Sources {
			if _, ok := body[pred.Index]; !ok {
				body[pred.Index] = pred
				stack = append(stack, pred)
			}
		}
	}

	// Return in node index order
	result := make([]*Op03Node, 0, len(body))
	for _, n := range body {
		result = append(result, n)
	}

	// Sort by index
	sortOp03Nodes(result)

	return result
}

func sortOp03Nodes(nodes []*Op03Node) {
	// Simple insertion sort (loop bodies are usually small)
	for i := 1; i < len(nodes); i++ {
		key := nodes[i]

		j := i - 1
		for j >= 0 && nodes[j].Index > key.Index {
			nodes[j+1] = nodes[j]
			j--
		}

		nodes[j+1] = key
	}
}

// RemoveNops removes nop nodes from the graph, patching edges.
func RemoveNops(nodes []*Op03Node) []*Op03Node {
	result := make([]*Op03Node, 0, len(nodes))
	for _, n := range nodes {
		if n.IsNop() {
			// Patch edges: connect sources directly to targets
			for _, src := range n.Sources {
				for _, tgt := range n.Targets {
					LinkOp03(src, tgt)
				}

				UnlinkOp03(src, n)
			}

			for _, tgt := range n.Targets {
				UnlinkOp03(n, tgt)
			}

			continue
		}

		result = append(result, n)
	}
	// Re-index
	for i, n := range result {
		n.Index = i
	}

	return result
}
