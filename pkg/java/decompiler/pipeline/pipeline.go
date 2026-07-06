package pipeline

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
)

// DecompileResult holds the output of the decompilation pipeline.
type DecompileResult struct {
	Nodes      []*InstrNode     // CFG nodes with statements
	Op03Nodes  []*Op03Node      // Structured Op03 nodes (after control flow structuring)
	Statements []stmt.Statement // Linearized statement list
}

// Decompile runs the full decompilation pipeline on raw bytecode.
// Stages:
//  1. Op01: Decode bytecode → instructions → CFG
//  2. Op02: Stack simulation → expression trees / statements
//  3. Op03: Control flow structuring → structured statements
//  4. Op04: Final transforms (expression simplification, lambdas, cleanup)
func Decompile(code []byte, method *MethodInfo, cp CPResolver, exceptions []ExceptionEntry) (*DecompileResult, error) {
	// Stage 1: Decode bytecode
	instrs, err := bytecode.DecodeInstructions(code)
	if err != nil {
		return nil, fmt.Errorf("op01 decode: %w", err)
	}

	// Stage 1b: Build CFG
	nodes, err := BuildCFG(instrs)
	if err != nil {
		return nil, fmt.Errorf("op01 cfg: %w", err)
	}

	// Stage 1c: Insert exception handler edges
	if err := InsertExceptionEdges(nodes, exceptions); err != nil {
		return nil, fmt.Errorf("op01 exceptions: %w", err)
	}

	// Stage 2: Stack simulation
	if err := SimulateStack(nodes, method, cp); err != nil {
		return nil, fmt.Errorf("op02 stack: %w", err)
	}

	// Stage 2b: Insert exception markers (try/catch) from exception table
	nodes = InsertExceptionMarkers(nodes, exceptions)

	// Stage 3: Control flow structuring
	op03Nodes := StructureControlFlow(nodes)

	// Stage 4: Final transforms
	FinalTransforms(op03Nodes)

	// Collect statements in order
	stmts := CollectStatements(op03Nodes)

	return &DecompileResult{
		Nodes:      nodes,
		Op03Nodes:  op03Nodes,
		Statements: stmts,
	}, nil
}

// FinalTransforms runs all Op04 transforms on structured nodes.
// These are expression-level and statement-level cleanups that run
// after control flow has been structured.
func FinalTransforms(nodes []*Op03Node) {
	// Expression simplification: constant folding, identity ops, etc.
	SimplifyExpressions(nodes)

	// Boolean simplification: x == true → x, x == false → !x, etc.
	SimplifyBooleans(nodes)

	// Redundant cast removal (uses SimplifyExpressions internally)
	RemoveRedundantCasts(nodes)

	// Lambda/invokedynamic rewriting
	RewriteLambdas(nodes)

	// Synthetic bridge method inlining
	RemoveSyntheticBridges(nodes)

	// Remove redundant gotos that target the next node
	RemoveRedundantGotos(nodes)

	// Collapse and flatten empty/nested blocks
	RemoveEmptyBlocks(nodes)
	CollapseLinearBlocks(nodes)
}

// StructureControlFlow runs all control flow structuring passes.
// Converts flat goto-based statements into structured control flow
// (if/else, while, for, switch, try/catch/finally, synchronized).
func StructureControlFlow(instrNodes []*InstrNode) []*Op03Node {
	// Build Op03 graph from Op02 output
	nodes := BuildOp03Graph(instrNodes)

	// Remove nop nodes
	nodes = RemoveNops(nodes)

	// Structure exception handling (try/catch/finally)
	nodes = structureExceptions(nodes)

	// Structure loops (while, do-while, for)
	nodes = structureLoops(nodes)

	// Structure conditionals (if/else)
	nodes = structureConditionals(nodes)

	// Structure switch statements
	nodes = structureSwitches(nodes)

	// Structure synchronized blocks
	nodes = structureSynchronized(nodes)

	// Final cleanup: remove remaining nops
	nodes = RemoveNops(nodes)

	return nodes
}
