package pipeline

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
)

// BuildCFG constructs a control flow graph from decoded instructions.
// This is the Go equivalent of CFR's Op01 stage + CFG linking from CodeAnalyser.
//
// It creates InstrNode wrappers for each instruction, then links them
// with source/target edges based on:
// 1. Sequential fallthrough (non-jump, non-return instructions)
// 2. Branch targets (conditional and unconditional jumps)
// 3. Switch targets (tableswitch, lookupswitch)
func BuildCFG(instrs []*bytecode.Instruction) ([]*InstrNode, error) {
	if len(instrs) == 0 {
		return nil, nil
	}

	// Build offset → index lookup table
	offsetToIdx := make(map[int]int, len(instrs))
	for i, instr := range instrs {
		offsetToIdx[instr.Offset] = i
	}

	// Create nodes
	nodes := make([]*InstrNode, len(instrs))
	for i, instr := range instrs {
		nodes[i] = NewInstrNode(i, instr)
	}

	// Link edges
	for i, node := range nodes {
		op := node.Instr.Op
		info := bytecode.LookupOp(op)

		if info == nil {
			return nil, fmt.Errorf("unknown opcode 0x%02X at index %d", uint16(op), i)
		}

		switch {
		case op == bytecode.GOTO || op == bytecode.GOTO_W:
			// Unconditional jump — target only, no fallthrough
			targetOffset := node.Instr.BranchTarget()

			targetIdx, ok := offsetToIdx[targetOffset]
			if !ok {
				return nil, fmt.Errorf("invalid jump target offset %d at index %d", targetOffset, i)
			}

			Link(node, nodes[targetIdx])

		case op == bytecode.TABLESWITCH:
			sw, err := bytecode.DecodeTableSwitchInstr(node.Instr)
			if err != nil {
				return nil, fmt.Errorf("decoding tableswitch at index %d: %w", i, err)
			}
			// Default target
			if defIdx, ok := offsetToIdx[sw.Default]; ok {
				Link(node, nodes[defIdx])
			}
			// Case targets (absolute targets already computed by decoder)
			for _, target := range sw.Targets {
				if targetIdx, ok := offsetToIdx[target]; ok {
					// Avoid duplicate edges (same target as default)
					if target != sw.Default {
						Link(node, nodes[targetIdx])
					}
				}
			}

		case op == bytecode.LOOKUPSWITCH:
			sw, err := bytecode.DecodeLookupSwitchInstr(node.Instr)
			if err != nil {
				return nil, fmt.Errorf("decoding lookupswitch at index %d: %w", i, err)
			}
			// Default target
			if defIdx, ok := offsetToIdx[sw.Default]; ok {
				Link(node, nodes[defIdx])
			}
			// Case targets (absolute targets already computed by decoder)
			for _, pair := range sw.Pairs {
				if targetIdx, ok := offsetToIdx[pair.Target]; ok {
					if pair.Target != sw.Default {
						Link(node, nodes[targetIdx])
					}
				}
			}

		case info.IsReturn() || op == bytecode.ATHROW:
			// No successors — terminal instruction

		case info.IsJump():
			// Conditional jump — both branch target and fallthrough
			targetOffset := node.Instr.BranchTarget()

			targetIdx, ok := offsetToIdx[targetOffset]
			if !ok {
				return nil, fmt.Errorf("invalid branch target offset %d at index %d", targetOffset, i)
			}

			Link(node, nodes[targetIdx])

			// Fallthrough to next instruction
			if i+1 < len(nodes) {
				Link(node, nodes[i+1])
			}

		default:
			// Normal instruction — fallthrough to next
			if i+1 < len(nodes) {
				Link(node, nodes[i+1])
			}
		}
	}

	return nodes, nil
}

// InsertExceptionEdges adds exception handler edges to the CFG.
// For each exception table entry, instructions in the try range [startPC, endPC)
// get an edge to the handler at handlerPC.
func InsertExceptionEdges(nodes []*InstrNode, exceptions []ExceptionEntry) error {
	if len(exceptions) == 0 {
		return nil
	}

	// Build offset → index lookup
	offsetToIdx := make(map[int]int, len(nodes))
	for i, node := range nodes {
		offsetToIdx[node.Instr.Offset] = i
	}

	for blockID, exc := range exceptions {
		handlerIdx, ok := offsetToIdx[exc.HandlerPC]
		if !ok {
			return fmt.Errorf("invalid exception handler offset %d", exc.HandlerPC)
		}

		for _, node := range nodes {
			offset := node.Instr.Offset
			if offset >= exc.StartPC && offset < exc.EndPC {
				// This instruction is in the try range
				node.ExceptionBlockIDs = append(node.ExceptionBlockIDs, blockID)

				// Add edge to handler (if not already linked)
				hasEdge := false

				for _, t := range node.Targets {
					if t.Index == handlerIdx {
						hasEdge = true
						break
					}
				}

				if !hasEdge {
					Link(node, nodes[handlerIdx])
				}
			}
		}
	}

	return nil
}

// FindReachable returns the set of node indices reachable from the entry node (index 0).
func FindReachable(nodes []*InstrNode) map[int]bool {
	if len(nodes) == 0 {
		return nil
	}

	reachable := make(map[int]bool, len(nodes))
	stack := []*InstrNode{nodes[0]}

	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if reachable[n.Index] {
			continue
		}

		reachable[n.Index] = true

		for _, t := range n.Targets {
			if !reachable[t.Index] {
				stack = append(stack, t)
			}
		}
	}

	return reachable
}
