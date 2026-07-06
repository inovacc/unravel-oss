package pipeline

import (
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// InsertExceptionMarkers generates synthetic TryStatement and CatchStatement
// marker nodes from the exception table and inserts them into the node list.
// This bridges Op02 (stack simulation) output to Op03's structureExceptions()
// which expects these markers to be present in the node stream.
func InsertExceptionMarkers(nodes []*InstrNode, exceptions []ExceptionEntry) []*InstrNode {
	if len(exceptions) == 0 || len(nodes) == 0 {
		return nodes
	}

	// Build offset → node index lookup
	offsetToIdx := make(map[int]int, len(nodes))
	for i, n := range nodes {
		offsetToIdx[n.Instr.Offset] = i
	}

	// Collect insertions: each insertion is a (position, synthetic node) pair.
	// We insert TryStatement markers before StartPC and CatchStatement markers before HandlerPC.
	type insertion struct {
		beforeIdx int        // insert before this node index
		node      *InstrNode // synthetic marker node
		priority  int        // 0 = try marker, 1 = catch marker (try before catch at same position)
	}

	var insertions []insertion

	for blockID, exc := range exceptions {
		// Insert TryStatement marker before the first instruction in the try range
		if startIdx, ok := offsetToIdx[exc.StartPC]; ok {
			tryMarker := &InstrNode{
				Instr:     &bytecode.Instruction{Offset: exc.StartPC},
				Statement: stmt.NewTry(blockID),
				Synthetic: true,
			}
			insertions = append(insertions, insertion{
				beforeIdx: startIdx,
				node:      tryMarker,
				priority:  0,
			})
		}

		// Insert CatchStatement marker before the handler entry point
		if handlerIdx, ok := offsetToIdx[exc.HandlerPC]; ok {
			var exType types.JavaType

			if exc.CatchType != "" {
				// Convert internal name (e.g. "java/lang/ArithmeticException") to RefType
				className := strings.ReplaceAll(exc.CatchType, "/", ".")
				exType = types.NewRefType(className)
			}
			// exType == nil means finally (catch-all)

			// Create a variable for the caught exception
			var exVar ast.LValue
			if exType != nil {
				exVar = ast.NewNamedLocalVariable(0, "e", exType)
			}

			catchMarker := &InstrNode{
				Instr:     &bytecode.Instruction{Offset: exc.HandlerPC},
				Statement: stmt.NewCatch(blockID, exType, exVar),
				Synthetic: true,
			}
			insertions = append(insertions, insertion{
				beforeIdx: handlerIdx,
				node:      catchMarker,
				priority:  1,
			})
		}
	}

	if len(insertions) == 0 {
		return nodes
	}

	// Sort insertions by position (ascending), then by priority (try before catch)
	sort.Slice(insertions, func(i, j int) bool {
		if insertions[i].beforeIdx != insertions[j].beforeIdx {
			return insertions[i].beforeIdx < insertions[j].beforeIdx
		}

		return insertions[i].priority < insertions[j].priority
	})

	// Build new node list with synthetic markers inserted
	result := make([]*InstrNode, 0, len(nodes)+len(insertions))
	insertIdx := 0

	for i, node := range nodes {
		// Insert all markers that go before this node
		for insertIdx < len(insertions) && insertions[insertIdx].beforeIdx == i {
			result = append(result, insertions[insertIdx].node)
			insertIdx++
		}

		result = append(result, node)
	}

	// Append any remaining insertions (shouldn't happen, but be safe)
	for insertIdx < len(insertions) {
		result = append(result, insertions[insertIdx].node)
		insertIdx++
	}

	// Re-index all nodes
	for i, n := range result {
		n.Index = i
	}

	return result
}
