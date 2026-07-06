package pipeline

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
)

// InstrNode wraps a decoded instruction with control flow graph edges.
// This is the Go equivalent of CFR's Op01WithProcessedDataAndByteJumps + Op02 graph structure.
type InstrNode struct {
	Index   int                   // instruction index in the list
	Instr   *bytecode.Instruction // the decoded instruction
	Targets []*InstrNode          // successor nodes (jump targets, fallthrough)
	Sources []*InstrNode          // predecessor nodes

	// Stack simulation results (populated by Op02)
	StackConsumed []*StackEntry // stack values consumed by this instruction
	StackProduced []*StackEntry // stack values produced by this instruction
	StackDepth    int           // stack depth before execution

	// Statement produced by this instruction (populated by Op02)
	Statement stmt.Statement

	// Synthetic flag for fake instructions (FAKE_TRY, FAKE_CATCH)
	Synthetic bool

	// Exception handling
	ExceptionBlockIDs []int // try block IDs this instruction belongs to
}

func NewInstrNode(index int, instr *bytecode.Instruction) *InstrNode {
	return &InstrNode{Index: index, Instr: instr}
}

// AddTarget adds a successor edge.
func (n *InstrNode) AddTarget(target *InstrNode) {
	n.Targets = append(n.Targets, target)
}

// AddSource adds a predecessor edge.
func (n *InstrNode) AddSource(source *InstrNode) {
	n.Sources = append(n.Sources, source)
}

// Link creates bidirectional edges: source → target, target ← source.
func Link(source, target *InstrNode) {
	source.AddTarget(target)
	target.AddSource(source)
}

// Unlink removes bidirectional edges between source and target.
func Unlink(source, target *InstrNode) {
	source.Targets = removeNode(source.Targets, target)
	target.Sources = removeNode(target.Sources, source)
}

func removeNode(nodes []*InstrNode, target *InstrNode) []*InstrNode {
	result := make([]*InstrNode, 0, len(nodes))
	for _, n := range nodes {
		if n != target {
			result = append(result, n)
		}
	}

	return result
}

func (n *InstrNode) String() string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "[%d] %s", n.Index, n.Instr)
	if len(n.Targets) > 0 {
		b.WriteString(" -> [")

		for i, t := range n.Targets {
			if i > 0 {
				b.WriteString(", ")
			}

			_, _ = fmt.Fprintf(&b, "%d", t.Index)
		}

		b.WriteByte(']')
	}

	return b.String()
}

// StackEntry represents a value on the simulated operand stack.
type StackEntry struct {
	Value ast.Expression
	Slot  int // stack slot position
}

// ExceptionEntry represents an entry in the exception table of a Code attribute.
type ExceptionEntry struct {
	StartPC   int    // start of try range (bytecode offset)
	EndPC     int    // end of try range (bytecode offset, exclusive)
	HandlerPC int    // start of handler (bytecode offset)
	CatchType string // exception class name (empty for catch-all/finally)
}
