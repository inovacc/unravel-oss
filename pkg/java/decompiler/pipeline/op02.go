package pipeline

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// SimulateStack performs stack simulation on the CFG, converting each instruction
// into a statement by simulating the JVM operand stack.
// This is the Go equivalent of CFR's Op02WithProcessedDataAndRefs.
func SimulateStack(nodes []*InstrNode, method *MethodInfo, cp CPResolver) error {
	if len(nodes) == 0 {
		return nil
	}

	// BFS traversal with stack state propagation
	type workItem struct {
		node  *InstrNode
		stack *StackSim
	}

	visited := make(map[int]bool, len(nodes))
	queue := []workItem{{node: nodes[0], stack: NewStackSim()}}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		if visited[item.node.Index] {
			continue
		}

		visited[item.node.Index] = true

		node := item.node
		stack := item.stack

		// Create statement for this instruction. The createStatement switch
		// is huge and operates on adversarial decompiled bytecode (threat
		// T-08-05); a panic there must NOT crash the process. Recover and
		// convert it into the same structured error path the existing
		// fmt.Errorf wrap below uses — the unit stays visible and the error
		// is surfaced, never swallowed (D-03, mirrors orchestrator.go:206).
		s, err := guardCreateStatement(node, stack, method, cp)
		if err != nil {
			return fmt.Errorf("at instruction %d (%s): %w", node.Index, node.Instr.Op, err)
		}

		node.Statement = s

		// Propagate stack to successors
		for _, target := range node.Targets {
			if !visited[target.Index] {
				queue = append(queue, workItem{node: target, stack: stack.Clone()})
			}
		}
	}

	return nil
}

// guardCreateStatement wraps createStatement with a recover so a panic in the
// instruction switch becomes a structured error instead of a process crash
// (D-03 / T-08-05). The recovered panic is surfaced as a normal error return —
// it is NEVER swallowed (no nil-error return on the recover path), so the
// caller's existing fmt.Errorf wrap (op02.go) keeps the failing instruction
// visible in the decompile error trail.
func guardCreateStatement(node *InstrNode, stack *StackSim, method *MethodInfo, cp CPResolver) (s stmt.Statement, err error) {
	defer func() {
		if r := recover(); r != nil {
			s = nil
			err = fmt.Errorf("panic in createStatement: %v", r)
		}
	}()

	return createStatement(node, stack, method, cp)
}

// stmtCategory converts a single opcode (within one cohesive category) into a
// statement. The bool return reports whether the opcode belongs to this
// category: false means "not mine, try the next category"; true means the
// (statement, error) pair is the final result for this instruction.
type stmtCategory func(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, method *MethodInfo, cp CPResolver) (stmt.Statement, bool, error)

// op02Categories is the ordered list of category handlers. createStatement
// walks them in this fixed order and returns the first claim. This is a
// behavior-preserving decomposition of the former ~760-line switch
// (D-04 / SC4): the characterization tests (op02_characterize_test.go) and
// task golden:compare pin that the observable output is byte-identical.
var op02Categories = []stmtCategory{
	stmtConstants,
	stmtLoadsStores,
	stmtArrayOps,
	stmtArithmetic,
	stmtConversions,
	stmtBranches,
	stmtReturnsThrow,
	stmtObjectAlloc,
	stmtFieldAccess,
	stmtInvokes,
	stmtStackManip,
	stmtMonitors,
	stmtSwitches,
	stmtSubroutineSynthetic,
}

// createStatement converts a single instruction into a statement by
// consuming values from and producing values to the operand stack.
func createStatement(node *InstrNode, stack *StackSim, method *MethodInfo, cp CPResolver) (stmt.Statement, error) {
	inst := node.Instr
	op := inst.Op

	for _, handle := range op02Categories {
		s, ok, err := handle(op, inst, stack, method, cp)
		if ok {
			return s, err
		}
	}

	return nil, fmt.Errorf("unimplemented opcode: %s (0x%02X)", op, uint16(op))
}

// --- Category handlers ---

func stmtConstants(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, cp CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.NOP:
		return stmt.NewNop(), true, nil

	case bytecode.ACONST_NULL:
		stack.Push(ast.NewNullLiteral())
		return stmt.NewNop(), true, nil

	case bytecode.ICONST_M1:
		stack.Push(ast.LitIntM1)
		return stmt.NewNop(), true, nil
	case bytecode.ICONST_0:
		stack.Push(ast.LitIntZero)
		return stmt.NewNop(), true, nil
	case bytecode.ICONST_1:
		stack.Push(ast.LitIntOne)
		return stmt.NewNop(), true, nil
	case bytecode.ICONST_2:
		stack.Push(ast.NewIntLiteral(2))
		return stmt.NewNop(), true, nil
	case bytecode.ICONST_3:
		stack.Push(ast.NewIntLiteral(3))
		return stmt.NewNop(), true, nil
	case bytecode.ICONST_4:
		stack.Push(ast.NewIntLiteral(4))
		return stmt.NewNop(), true, nil
	case bytecode.ICONST_5:
		stack.Push(ast.NewIntLiteral(5))
		return stmt.NewNop(), true, nil

	case bytecode.LCONST_0:
		stack.Push(ast.LitLongZero)
		return stmt.NewNop(), true, nil
	case bytecode.LCONST_1:
		stack.Push(ast.LitLongOne)
		return stmt.NewNop(), true, nil

	case bytecode.FCONST_0:
		stack.Push(ast.LitFloatZero)
		return stmt.NewNop(), true, nil
	case bytecode.FCONST_1:
		stack.Push(ast.NewFloatLiteral(1))
		return stmt.NewNop(), true, nil
	case bytecode.FCONST_2:
		stack.Push(ast.NewFloatLiteral(2))
		return stmt.NewNop(), true, nil

	case bytecode.DCONST_0:
		stack.Push(ast.LitDoubleZero)
		return stmt.NewNop(), true, nil
	case bytecode.DCONST_1:
		stack.Push(ast.NewDoubleLiteral(1))
		return stmt.NewNop(), true, nil

	case bytecode.BIPUSH:
		stack.Push(ast.NewIntLiteral(int32(inst.ImmediateByte())))
		return stmt.NewNop(), true, nil

	case bytecode.SIPUSH:
		stack.Push(ast.NewIntLiteral(int32(inst.ImmediateShort())))
		return stmt.NewNop(), true, nil

	case bytecode.LDC, bytecode.LDC_W, bytecode.LDC2_W:
		cpIdx := inst.CPIndex()

		lit, err := cp.ResolveLiteral(cpIdx)
		if err != nil {
			return nil, true, fmt.Errorf("resolving LDC constant %d: %w", cpIdx, err)
		}

		stack.Push(lit)

		return stmt.NewNop(), true, nil
	}

	return nil, false, nil
}

func stmtLoadsStores(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, method *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	// --- Loads ---
	case bytecode.ILOAD, bytecode.ILOAD_0, bytecode.ILOAD_1, bytecode.ILOAD_2, bytecode.ILOAD_3:
		return loadLocal(stack, inst, types.TypeInt, method), true, nil
	case bytecode.LLOAD, bytecode.LLOAD_0, bytecode.LLOAD_1, bytecode.LLOAD_2, bytecode.LLOAD_3:
		return loadLocal(stack, inst, types.TypeLong, method), true, nil
	case bytecode.FLOAD, bytecode.FLOAD_0, bytecode.FLOAD_1, bytecode.FLOAD_2, bytecode.FLOAD_3:
		return loadLocal(stack, inst, types.TypeFloat, method), true, nil
	case bytecode.DLOAD, bytecode.DLOAD_0, bytecode.DLOAD_1, bytecode.DLOAD_2, bytecode.DLOAD_3:
		return loadLocal(stack, inst, types.TypeDouble, method), true, nil
	case bytecode.ALOAD, bytecode.ALOAD_0, bytecode.ALOAD_1, bytecode.ALOAD_2, bytecode.ALOAD_3:
		return loadLocal(stack, inst, types.ObjectType, method), true, nil

	// --- Stores ---
	case bytecode.ISTORE, bytecode.ISTORE_0, bytecode.ISTORE_1, bytecode.ISTORE_2, bytecode.ISTORE_3:
		s, err := storeLocal(stack, inst, types.TypeInt, method)
		return s, true, err
	case bytecode.LSTORE, bytecode.LSTORE_0, bytecode.LSTORE_1, bytecode.LSTORE_2, bytecode.LSTORE_3:
		s, err := storeLocal(stack, inst, types.TypeLong, method)
		return s, true, err
	case bytecode.FSTORE, bytecode.FSTORE_0, bytecode.FSTORE_1, bytecode.FSTORE_2, bytecode.FSTORE_3:
		s, err := storeLocal(stack, inst, types.TypeFloat, method)
		return s, true, err
	case bytecode.DSTORE, bytecode.DSTORE_0, bytecode.DSTORE_1, bytecode.DSTORE_2, bytecode.DSTORE_3:
		s, err := storeLocal(stack, inst, types.TypeDouble, method)
		return s, true, err
	case bytecode.ASTORE, bytecode.ASTORE_0, bytecode.ASTORE_1, bytecode.ASTORE_2, bytecode.ASTORE_3:
		s, err := storeLocal(stack, inst, types.ObjectType, method)
		return s, true, err

	// --- IINC ---
	case bytecode.IINC:
		localIdx := inst.LocalIndex()
		incr := inst.IIncValue()
		lv := localVarFor(method, int(localIdx), types.TypeInt)

		var arithOp ast.ArithOp

		litVal := incr
		if incr < 0 {
			arithOp = ast.OpSub
			litVal = -incr
		} else {
			arithOp = ast.OpAdd
		}

		rhs := ast.NewArithmeticOperation(arithOp,
			ast.NewVarExpression(lv),
			ast.NewIntLiteral(int32(litVal)),
			types.TypeInt)

		return stmt.NewAssignment(lv, rhs), true, nil
	}

	return nil, false, nil
}

func stmtArrayOps(op bytecode.Opcode, _ *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	// --- Array loads ---
	case bytecode.IALOAD:
		s, err := arrayLoad(stack, types.TypeInt)
		return s, true, err
	case bytecode.LALOAD:
		s, err := arrayLoad(stack, types.TypeLong)
		return s, true, err
	case bytecode.FALOAD:
		s, err := arrayLoad(stack, types.TypeFloat)
		return s, true, err
	case bytecode.DALOAD:
		s, err := arrayLoad(stack, types.TypeDouble)
		return s, true, err
	case bytecode.AALOAD:
		s, err := arrayLoad(stack, types.ObjectType)
		return s, true, err
	case bytecode.BALOAD:
		s, err := arrayLoad(stack, types.TypeByte)
		return s, true, err
	case bytecode.CALOAD:
		s, err := arrayLoad(stack, types.TypeChar)
		return s, true, err
	case bytecode.SALOAD:
		s, err := arrayLoad(stack, types.TypeShort)
		return s, true, err

	// --- Array stores ---
	case bytecode.IASTORE:
		s, err := arrayStore(stack, types.TypeInt)
		return s, true, err
	case bytecode.LASTORE:
		s, err := arrayStore(stack, types.TypeLong)
		return s, true, err
	case bytecode.FASTORE:
		s, err := arrayStore(stack, types.TypeFloat)
		return s, true, err
	case bytecode.DASTORE:
		s, err := arrayStore(stack, types.TypeDouble)
		return s, true, err
	case bytecode.AASTORE:
		s, err := arrayStore(stack, types.ObjectType)
		return s, true, err
	case bytecode.BASTORE:
		s, err := arrayStore(stack, types.TypeByte)
		return s, true, err
	case bytecode.CASTORE:
		s, err := arrayStore(stack, types.TypeChar)
		return s, true, err
	case bytecode.SASTORE:
		s, err := arrayStore(stack, types.TypeShort)
		return s, true, err
	}

	return nil, false, nil
}

func stmtArithmetic(op bytecode.Opcode, _ *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	// --- Arithmetic (binary) ---
	case bytecode.IADD:
		s, err := binaryArith(stack, ast.OpAdd, types.TypeInt)
		return s, true, err
	case bytecode.LADD:
		s, err := binaryArith(stack, ast.OpAdd, types.TypeLong)
		return s, true, err
	case bytecode.FADD:
		s, err := binaryArith(stack, ast.OpAdd, types.TypeFloat)
		return s, true, err
	case bytecode.DADD:
		s, err := binaryArith(stack, ast.OpAdd, types.TypeDouble)
		return s, true, err
	case bytecode.ISUB:
		s, err := binaryArith(stack, ast.OpSub, types.TypeInt)
		return s, true, err
	case bytecode.LSUB:
		s, err := binaryArith(stack, ast.OpSub, types.TypeLong)
		return s, true, err
	case bytecode.FSUB:
		s, err := binaryArith(stack, ast.OpSub, types.TypeFloat)
		return s, true, err
	case bytecode.DSUB:
		s, err := binaryArith(stack, ast.OpSub, types.TypeDouble)
		return s, true, err
	case bytecode.IMUL:
		s, err := binaryArith(stack, ast.OpMul, types.TypeInt)
		return s, true, err
	case bytecode.LMUL:
		s, err := binaryArith(stack, ast.OpMul, types.TypeLong)
		return s, true, err
	case bytecode.FMUL:
		s, err := binaryArith(stack, ast.OpMul, types.TypeFloat)
		return s, true, err
	case bytecode.DMUL:
		s, err := binaryArith(stack, ast.OpMul, types.TypeDouble)
		return s, true, err
	case bytecode.IDIV:
		s, err := binaryArith(stack, ast.OpDiv, types.TypeInt)
		return s, true, err
	case bytecode.LDIV:
		s, err := binaryArith(stack, ast.OpDiv, types.TypeLong)
		return s, true, err
	case bytecode.FDIV:
		s, err := binaryArith(stack, ast.OpDiv, types.TypeFloat)
		return s, true, err
	case bytecode.DDIV:
		s, err := binaryArith(stack, ast.OpDiv, types.TypeDouble)
		return s, true, err
	case bytecode.IREM:
		s, err := binaryArith(stack, ast.OpRem, types.TypeInt)
		return s, true, err
	case bytecode.LREM:
		s, err := binaryArith(stack, ast.OpRem, types.TypeLong)
		return s, true, err
	case bytecode.FREM:
		s, err := binaryArith(stack, ast.OpRem, types.TypeFloat)
		return s, true, err
	case bytecode.DREM:
		s, err := binaryArith(stack, ast.OpRem, types.TypeDouble)
		return s, true, err

	// --- Arithmetic (unary negation) ---
	case bytecode.INEG:
		s, err := unaryNeg(stack, types.TypeInt)
		return s, true, err
	case bytecode.LNEG:
		s, err := unaryNeg(stack, types.TypeLong)
		return s, true, err
	case bytecode.FNEG:
		s, err := unaryNeg(stack, types.TypeFloat)
		return s, true, err
	case bytecode.DNEG:
		s, err := unaryNeg(stack, types.TypeDouble)
		return s, true, err

	// --- Bitwise ---
	case bytecode.IAND:
		s, err := binaryArith(stack, ast.OpAnd, types.TypeInt)
		return s, true, err
	case bytecode.LAND:
		s, err := binaryArith(stack, ast.OpAnd, types.TypeLong)
		return s, true, err
	case bytecode.IOR:
		s, err := binaryArith(stack, ast.OpOr, types.TypeInt)
		return s, true, err
	case bytecode.LOR:
		s, err := binaryArith(stack, ast.OpOr, types.TypeLong)
		return s, true, err
	case bytecode.IXOR:
		s, err := binaryArith(stack, ast.OpXor, types.TypeInt)
		return s, true, err
	case bytecode.LXOR:
		s, err := binaryArith(stack, ast.OpXor, types.TypeLong)
		return s, true, err

	// --- Shifts ---
	case bytecode.ISHL:
		s, err := binaryArith(stack, ast.OpShl, types.TypeInt)
		return s, true, err
	case bytecode.LSHL:
		s, err := binaryArith(stack, ast.OpShl, types.TypeLong)
		return s, true, err
	case bytecode.ISHR:
		s, err := binaryArith(stack, ast.OpShr, types.TypeInt)
		return s, true, err
	case bytecode.LSHR:
		s, err := binaryArith(stack, ast.OpShr, types.TypeLong)
		return s, true, err
	case bytecode.IUSHR:
		s, err := binaryArith(stack, ast.OpUShr, types.TypeInt)
		return s, true, err
	case bytecode.LUSHR:
		s, err := binaryArith(stack, ast.OpUShr, types.TypeLong)
		return s, true, err

	// --- Comparisons ---
	case bytecode.LCMP:
		s, err := binaryArith(stack, ast.OpLCmp, types.TypeInt)
		return s, true, err
	case bytecode.FCMPL:
		s, err := binaryArith(stack, ast.OpFCmpL, types.TypeInt)
		return s, true, err
	case bytecode.FCMPG:
		s, err := binaryArith(stack, ast.OpFCmpG, types.TypeInt)
		return s, true, err
	case bytecode.DCMPL:
		s, err := binaryArith(stack, ast.OpDCmpL, types.TypeInt)
		return s, true, err
	case bytecode.DCMPG:
		s, err := binaryArith(stack, ast.OpDCmpG, types.TypeInt)
		return s, true, err
	}

	return nil, false, nil
}

func stmtConversions(op bytecode.Opcode, _ *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.I2B:
		s, err := typeCast(stack, types.TypeByte)
		return s, true, err
	case bytecode.I2C:
		s, err := typeCast(stack, types.TypeChar)
		return s, true, err
	case bytecode.I2S:
		s, err := typeCast(stack, types.TypeShort)
		return s, true, err
	case bytecode.I2L:
		s, err := typeCast(stack, types.TypeLong)
		return s, true, err
	case bytecode.I2F:
		s, err := typeCast(stack, types.TypeFloat)
		return s, true, err
	case bytecode.I2D:
		s, err := typeCast(stack, types.TypeDouble)
		return s, true, err
	case bytecode.L2I:
		s, err := typeCast(stack, types.TypeInt)
		return s, true, err
	case bytecode.L2F:
		s, err := typeCast(stack, types.TypeFloat)
		return s, true, err
	case bytecode.L2D:
		s, err := typeCast(stack, types.TypeDouble)
		return s, true, err
	case bytecode.F2I:
		s, err := typeCast(stack, types.TypeInt)
		return s, true, err
	case bytecode.F2L:
		s, err := typeCast(stack, types.TypeLong)
		return s, true, err
	case bytecode.F2D:
		s, err := typeCast(stack, types.TypeDouble)
		return s, true, err
	case bytecode.D2I:
		s, err := typeCast(stack, types.TypeInt)
		return s, true, err
	case bytecode.D2L:
		s, err := typeCast(stack, types.TypeLong)
		return s, true, err
	case bytecode.D2F:
		s, err := typeCast(stack, types.TypeFloat)
		return s, true, err
	}

	return nil, false, nil
}

func stmtBranches(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	// --- Conditional branches ---
	case bytecode.IFEQ:
		s, err := ifCompare(stack, inst, ast.CmpEq, ast.LitIntZero)
		return s, true, err
	case bytecode.IFNE:
		s, err := ifCompare(stack, inst, ast.CmpNe, ast.LitIntZero)
		return s, true, err
	case bytecode.IFLT:
		s, err := ifCompare(stack, inst, ast.CmpLt, ast.LitIntZero)
		return s, true, err
	case bytecode.IFGE:
		s, err := ifCompare(stack, inst, ast.CmpGe, ast.LitIntZero)
		return s, true, err
	case bytecode.IFGT:
		s, err := ifCompare(stack, inst, ast.CmpGt, ast.LitIntZero)
		return s, true, err
	case bytecode.IFLE:
		s, err := ifCompare(stack, inst, ast.CmpLe, ast.LitIntZero)
		return s, true, err

	case bytecode.IF_ICMPEQ:
		s, err := ifICmp(stack, inst, ast.CmpEq)
		return s, true, err
	case bytecode.IF_ICMPNE:
		s, err := ifICmp(stack, inst, ast.CmpNe)
		return s, true, err
	case bytecode.IF_ICMPLT:
		s, err := ifICmp(stack, inst, ast.CmpLt)
		return s, true, err
	case bytecode.IF_ICMPGE:
		s, err := ifICmp(stack, inst, ast.CmpGe)
		return s, true, err
	case bytecode.IF_ICMPGT:
		s, err := ifICmp(stack, inst, ast.CmpGt)
		return s, true, err
	case bytecode.IF_ICMPLE:
		s, err := ifICmp(stack, inst, ast.CmpLe)
		return s, true, err

	case bytecode.IF_ACMPEQ:
		s, err := ifICmp(stack, inst, ast.CmpEq)
		return s, true, err
	case bytecode.IF_ACMPNE:
		s, err := ifICmp(stack, inst, ast.CmpNe)
		return s, true, err

	case bytecode.IFNULL:
		s, err := ifCompare(stack, inst, ast.CmpEq, ast.NewNullLiteral())
		return s, true, err
	case bytecode.IFNONNULL:
		s, err := ifCompare(stack, inst, ast.CmpNe, ast.NewNullLiteral())
		return s, true, err

	// --- Unconditional jumps ---
	case bytecode.GOTO, bytecode.GOTO_W:
		return stmt.NewGoto(inst.BranchTarget()), true, nil
	}

	return nil, false, nil
}

func stmtReturnsThrow(op bytecode.Opcode, _ *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.RETURN:
		return stmt.NewReturnVoid(), true, nil

	case bytecode.IRETURN, bytecode.LRETURN, bytecode.FRETURN, bytecode.DRETURN, bytecode.ARETURN:
		entry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("return: %w", err)
		}

		return stmt.NewReturn(entry.Value), true, nil

	case bytecode.ATHROW:
		entry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("athrow: %w", err)
		}

		return stmt.NewThrow(entry.Value), true, nil
	}

	return nil, false, nil
}

func stmtObjectAlloc(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, cp CPResolver) (stmt.Statement, bool, error) {
	switch op {
	// --- NEW ---
	case bytecode.NEW:
		cpIdx := inst.CPIndex()

		classType, err := cp.ResolveClass(cpIdx)
		if err != nil {
			return nil, true, fmt.Errorf("new: resolving class %d: %w", cpIdx, err)
		}

		stack.Push(ast.NewNewObject(classType))

		return stmt.NewNop(), true, nil

	// --- NEWARRAY (primitive) ---
	case bytecode.NEWARRAY:
		sizeEntry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("newarray: %w", err)
		}

		elemType := newArrayElemType(inst.NewArrayElementType())
		stack.Push(ast.NewNewArray(elemType, sizeEntry.Value))

		return stmt.NewNop(), true, nil

	// --- ANEWARRAY (reference) ---
	case bytecode.ANEWARRAY:
		sizeEntry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("anewarray: %w", err)
		}

		cpIdx := inst.CPIndex()

		elemType, err := cp.ResolveClass(cpIdx)
		if err != nil {
			return nil, true, fmt.Errorf("anewarray: resolving class %d: %w", cpIdx, err)
		}

		stack.Push(ast.NewNewObjectArray(elemType, sizeEntry.Value))

		return stmt.NewNop(), true, nil

	// --- MULTIANEWARRAY ---
	case bytecode.MULTIANEWARRAY:
		cpIdx := inst.CPIndex()
		dims := inst.MultiANewArrayDimensions()

		arrayType, err := cp.ResolveClass(cpIdx)
		if err != nil {
			return nil, true, fmt.Errorf("multianewarray: resolving class %d: %w", cpIdx, err)
		}

		dimExprs := make([]ast.Expression, dims)
		for i := int(dims) - 1; i >= 0; i-- {
			entry, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, fmt.Errorf("multianewarray: %w", popErr)
			}

			dimExprs[i] = entry.Value
		}

		stack.Push(ast.NewMultiNewArray(arrayType, dimExprs))

		return stmt.NewNop(), true, nil

	// --- ARRAYLENGTH ---
	case bytecode.ARRAYLENGTH:
		arrEntry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("arraylength: %w", err)
		}

		stack.Push(ast.NewArrayLength(arrEntry.Value))

		return stmt.NewNop(), true, nil

	// --- INSTANCEOF ---
	case bytecode.INSTANCEOF:
		objEntry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("instanceof: %w", err)
		}

		cpIdx := inst.CPIndex()

		checkType, err := cp.ResolveClass(cpIdx)
		if err != nil {
			return nil, true, fmt.Errorf("instanceof: resolving class %d: %w", cpIdx, err)
		}

		stack.Push(ast.NewInstanceOfExpression(objEntry.Value, checkType))

		return stmt.NewNop(), true, nil

	// --- CHECKCAST ---
	case bytecode.CHECKCAST:
		objEntry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("checkcast: %w", err)
		}

		cpIdx := inst.CPIndex()

		castType, err := cp.ResolveClass(cpIdx)
		if err != nil {
			return nil, true, fmt.Errorf("checkcast: resolving class %d: %w", cpIdx, err)
		}

		stack.Push(ast.NewCastExpression(objEntry.Value, castType))

		return stmt.NewNop(), true, nil
	}

	return nil, false, nil
}

func stmtFieldAccess(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, cp CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.GETFIELD:
		s, err := getField(stack, inst, cp)
		return s, true, err
	case bytecode.GETSTATIC:
		s, err := getStatic(stack, inst, cp)
		return s, true, err
	case bytecode.PUTFIELD:
		s, err := putField(stack, inst, cp)
		return s, true, err
	case bytecode.PUTSTATIC:
		s, err := putStatic(stack, inst, cp)
		return s, true, err
	}

	return nil, false, nil
}

func stmtInvokes(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, cp CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.INVOKEVIRTUAL:
		s, err := invokeMethod(stack, inst, cp, ast.InvokeVirtual)
		return s, true, err
	case bytecode.INVOKESPECIAL:
		s, err := invokeMethod(stack, inst, cp, ast.InvokeSpecial)
		return s, true, err
	case bytecode.INVOKESTATIC:
		s, err := invokeStatic(stack, inst, cp)
		return s, true, err
	case bytecode.INVOKEINTERFACE:
		s, err := invokeMethod(stack, inst, cp, ast.InvokeInterface)
		return s, true, err
	case bytecode.INVOKEDYNAMIC:
		s, err := invokeDynamic(stack, inst, cp)
		return s, true, err
	}

	return nil, false, nil
}

func stmtStackManip(op bytecode.Opcode, _ *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.POP:
		entry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("pop: %w", err)
		}

		return stmt.NewExpressionStatement(entry.Value), true, nil

	case bytecode.POP2:
		// POP2: form 1 = pop two cat1 values, form 2 = pop one cat2 value
		entry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("pop2: %w", err)
		}

		if stackCategory(entry.Value.Type()) == 2 {
			return stmt.NewExpressionStatement(entry.Value), true, nil
		}

		entry2, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("pop2: %w", err)
		}

		return stmt.NewCompound(
			stmt.NewExpressionStatement(entry.Value),
			stmt.NewExpressionStatement(entry2.Value),
		), true, nil

	case bytecode.DUP:
		entry, err := stack.Peek()
		if err != nil {
			return nil, true, fmt.Errorf("dup: %w", err)
		}

		stack.Push(entry.Value)

		return stmt.NewNop(), true, nil

	case bytecode.DUP_X1:
		// ..., v2, v1 → ..., v1, v2, v1
		top, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup_x1: %w", err)
		}

		second, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup_x1: %w", err)
		}

		stack.Push(top.Value)
		stack.Push(second.Value)
		stack.Push(top.Value)

		return stmt.NewNop(), true, nil

	case bytecode.DUP_X2:
		top, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup_x2: %w", err)
		}

		second, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup_x2: %w", err)
		}

		if stackCategory(second.Value.Type()) == 2 {
			// Form 2: ..., v2(cat2), v1 → ..., v1, v2, v1
			stack.Push(top.Value)
			stack.Push(second.Value)
			stack.Push(top.Value)
		} else {
			// Form 1: ..., v3, v2, v1 → ..., v1, v3, v2, v1
			third, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, fmt.Errorf("dup_x2: %w", popErr)
			}

			stack.Push(top.Value)
			stack.Push(third.Value)
			stack.Push(second.Value)
			stack.Push(top.Value)
		}

		return stmt.NewNop(), true, nil

	case bytecode.DUP2:
		top, err := stack.Peek()
		if err != nil {
			return nil, true, fmt.Errorf("dup2: %w", err)
		}

		if stackCategory(top.Value.Type()) == 2 {
			// Form 2: dup one cat2 value
			stack.Push(top.Value)
		} else {
			// Form 1: dup top two cat1 values
			topEntry, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			secondEntry, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			stack.Push(secondEntry.Value)
			stack.Push(topEntry.Value)
			stack.Push(secondEntry.Value)
			stack.Push(topEntry.Value)
		}

		return stmt.NewNop(), true, nil

	case bytecode.DUP2_X1:
		top, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup2_x1: %w", err)
		}

		if stackCategory(top.Value.Type()) == 2 {
			// Form 2: ..., v2, v1(cat2) → ..., v1, v2, v1
			second, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			stack.Push(top.Value)
			stack.Push(second.Value)
			stack.Push(top.Value)
		} else {
			// Form 1: ..., v3, v2, v1 → ..., v2, v1, v3, v2, v1
			second, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			third, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			stack.Push(second.Value)
			stack.Push(top.Value)
			stack.Push(third.Value)
			stack.Push(second.Value)
			stack.Push(top.Value)
		}

		return stmt.NewNop(), true, nil

	case bytecode.DUP2_X2:
		// Most complex stack op — simplified: handle as form 1 (4 cat1 values)
		top, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup2_x2: %w", err)
		}

		second, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("dup2_x2: %w", err)
		}

		if stackCategory(top.Value.Type()) == 2 && stackCategory(second.Value.Type()) == 2 {
			// Form 4: ..., v2(cat2), v1(cat2) → ..., v1, v2, v1
			stack.Push(top.Value)
			stack.Push(second.Value)
			stack.Push(top.Value)
		} else if stackCategory(top.Value.Type()) == 2 {
			// Form 3: ..., v3, v2, v1(cat2) → ..., v1, v3, v2, v1
			third, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			stack.Push(top.Value)
			stack.Push(third.Value)
			stack.Push(second.Value)
			stack.Push(top.Value)
		} else if stackCategory(second.Value.Type()) == 1 {
			third, popErr := stack.Pop()
			if popErr != nil {
				return nil, true, popErr
			}

			if stackCategory(third.Value.Type()) == 2 {
				// Form 2: ..., v3(cat2), v2, v1 → ..., v2, v1, v3, v2, v1
				stack.Push(second.Value)
				stack.Push(top.Value)
				stack.Push(third.Value)
				stack.Push(second.Value)
				stack.Push(top.Value)
			} else {
				// Form 1: ..., v4, v3, v2, v1 → ..., v2, v1, v4, v3, v2, v1
				fourth, popErr := stack.Pop()
				if popErr != nil {
					return nil, true, popErr
				}

				stack.Push(second.Value)
				stack.Push(top.Value)
				stack.Push(fourth.Value)
				stack.Push(third.Value)
				stack.Push(second.Value)
				stack.Push(top.Value)
			}
		}

		return stmt.NewNop(), true, nil

	case bytecode.SWAP:
		top, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("swap: %w", err)
		}

		second, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("swap: %w", err)
		}

		stack.Push(top.Value)
		stack.Push(second.Value)

		return stmt.NewNop(), true, nil
	}

	return nil, false, nil
}

func stmtMonitors(op bytecode.Opcode, _ *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.MONITORENTER:
		entry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("monitorenter: %w", err)
		}

		return stmt.NewMonitorEnter(entry.Value), true, nil

	case bytecode.MONITOREXIT:
		entry, err := stack.Pop()
		if err != nil {
			return nil, true, fmt.Errorf("monitorexit: %w", err)
		}

		return stmt.NewMonitorExit(entry.Value), true, nil
	}

	return nil, false, nil
}

func stmtSwitches(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	case bytecode.TABLESWITCH:
		s, err := handleTableSwitch(stack, inst)
		return s, true, err

	case bytecode.LOOKUPSWITCH:
		s, err := handleLookupSwitch(stack, inst)
		return s, true, err
	}

	return nil, false, nil
}

func stmtSubroutineSynthetic(op bytecode.Opcode, inst *bytecode.Instruction, stack *StackSim, _ *MethodInfo, _ CPResolver) (stmt.Statement, bool, error) {
	switch op {
	// --- JSR/RET (legacy subroutine calls) ---
	case bytecode.JSR, bytecode.JSR_W:
		stack.Push(ast.NewIntLiteral(int32(inst.Offset)))
		return stmt.NewGoto(inst.BranchTarget()), true, nil

	case bytecode.RET:
		return stmt.NewGoto(0), true, nil // Simplified — target resolved later

	// --- Synthetic opcodes ---
	case bytecode.FAKE_TRY:
		return stmt.NewTry(0), true, nil

	case bytecode.FAKE_CATCH:
		catchVar := ast.NewLocalVariable(0, types.ThrowableType)
		stack.Push(catchVar)

		return stmt.NewCatch(0, types.ThrowableType, catchVar), true, nil
	}

	return nil, false, nil
}

// --- Helper functions ---

// localVarFor creates a LocalVariable with the name from LocalVariableTable if available.
// For non-static methods, slot 0 is always "this".
func localVarFor(method *MethodInfo, slot int, jtype types.JavaType) *ast.LocalVariable {
	if method != nil {
		// Slot 0 in instance methods is always "this"
		if slot == 0 && !method.IsStatic {
			return ast.NewNamedLocalVariable(0, "this", jtype)
		}

		if method.LocalVarNames != nil {
			if name, ok := method.LocalVarNames[slot]; ok {
				return ast.NewNamedLocalVariable(slot, name, jtype)
			}
		}
	}

	return ast.NewLocalVariable(slot, jtype)
}

func loadLocal(stack *StackSim, inst *bytecode.Instruction, jtype types.JavaType, method *MethodInfo) stmt.Statement {
	localIdx := inst.LocalIndex()
	lv := localVarFor(method, int(localIdx), jtype)
	stack.Push(ast.NewVarExpression(lv))

	return stmt.NewNop()
}

func storeLocal(stack *StackSim, inst *bytecode.Instruction, jtype types.JavaType, method *MethodInfo) (stmt.Statement, error) {
	entry, err := stack.Pop()
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	localIdx := inst.LocalIndex()
	lv := localVarFor(method, int(localIdx), jtype)

	return stmt.NewAssignment(lv, entry.Value), nil
}

func binaryArith(stack *StackSim, op ast.ArithOp, jtype types.JavaType) (stmt.Statement, error) {
	rhs, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	lhs, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	result := ast.NewArithmeticOperation(op, lhs.Value, rhs.Value, jtype)
	stack.Push(result)

	return stmt.NewNop(), nil
}

func unaryNeg(stack *StackSim, jtype types.JavaType) (stmt.Statement, error) {
	entry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	stack.Push(ast.NewArithmeticNegation(entry.Value, jtype))

	return stmt.NewNop(), nil
}

func typeCast(stack *StackSim, targetType types.JavaType) (stmt.Statement, error) {
	entry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	stack.Push(ast.NewCastExpression(entry.Value, targetType))

	return stmt.NewNop(), nil
}

func ifCompare(stack *StackSim, inst *bytecode.Instruction, op ast.CompOp, rhs ast.Expression) (stmt.Statement, error) {
	entry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	// Boolean-as-int: the JVM stores booleans as ints, so `ifeq`/`ifne` on a
	// boolean value naively renders as `expr == 0` / `expr != 0` — which does
	// not compile (boolean compared to int) and reads worse than the idiomatic
	// `!expr` / `expr` that CFR/procyon emit. Rewrite only the eq/ne-against-zero
	// case when the popped value is boolean-typed; numeric iflt/ifge/... fall
	// through unchanged.
	if entry.Value != nil && entry.Value.Type() == types.TypeBoolean {
		switch op {
		case ast.CmpNe: // `!= 0` ≡ the boolean expression is true
			return stmt.NewIf(entry.Value, inst.BranchTarget()), nil
		case ast.CmpEq: // `== 0` ≡ the boolean expression is false
			// A nested comparison negates cleanly to another comparison
			// (`(a == b) == 0` → `a != b`), avoiding a `!a == b` misparse.
			if cmp, ok := entry.Value.(*ast.ComparisonOperation); ok {
				return stmt.NewIf(cmp.Negate(), inst.BranchTarget()), nil
			}

			return stmt.NewIf(ast.NewNegationExpression(entry.Value), inst.BranchTarget()), nil
		}
	}

	cond := ast.NewComparisonOperation(op, entry.Value, rhs)

	return stmt.NewIf(cond, inst.BranchTarget()), nil
}

func ifICmp(stack *StackSim, inst *bytecode.Instruction, op ast.CompOp) (stmt.Statement, error) {
	rhs, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	lhs, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	cond := ast.NewComparisonOperation(op, lhs.Value, rhs.Value)

	return stmt.NewIf(cond, inst.BranchTarget()), nil
}

func arrayLoad(stack *StackSim, elemType types.JavaType) (stmt.Statement, error) {
	indexEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	arrayEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	access := ast.NewArrayAccess(arrayEntry.Value, indexEntry.Value, elemType)
	stack.Push(access)

	return stmt.NewNop(), nil
}

func arrayStore(stack *StackSim, _ types.JavaType) (stmt.Statement, error) {
	valueEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	indexEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	arrayEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	target := ast.NewArrayAccess(arrayEntry.Value, indexEntry.Value, valueEntry.Value.Type())

	return stmt.NewAssignment(target, valueEntry.Value), nil
}

func getField(stack *StackSim, inst *bytecode.Instruction, cp CPResolver) (stmt.Statement, error) {
	objEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	cpIdx := inst.CPIndex()

	fieldRef, err := cp.ResolveFieldRef(cpIdx)
	if err != nil {
		return nil, fmt.Errorf("getfield: resolving field %d: %w", cpIdx, err)
	}

	stack.Push(ast.NewFieldAccess(objEntry.Value, fieldRef))

	return stmt.NewNop(), nil
}

func getStatic(stack *StackSim, inst *bytecode.Instruction, cp CPResolver) (stmt.Statement, error) {
	cpIdx := inst.CPIndex()

	fieldRef, err := cp.ResolveFieldRef(cpIdx)
	if err != nil {
		return nil, fmt.Errorf("getstatic: resolving field %d: %w", cpIdx, err)
	}

	stack.Push(ast.NewStaticFieldAccess(fieldRef))

	return stmt.NewNop(), nil
}

func putField(stack *StackSim, inst *bytecode.Instruction, cp CPResolver) (stmt.Statement, error) {
	valueEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	objEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	cpIdx := inst.CPIndex()

	fieldRef, err := cp.ResolveFieldRef(cpIdx)
	if err != nil {
		return nil, fmt.Errorf("putfield: resolving field %d: %w", cpIdx, err)
	}

	target := ast.NewFieldAccess(objEntry.Value, fieldRef)

	return stmt.NewAssignment(target, valueEntry.Value), nil
}

func putStatic(stack *StackSim, inst *bytecode.Instruction, cp CPResolver) (stmt.Statement, error) {
	valueEntry, err := stack.Pop()
	if err != nil {
		return nil, err
	}

	cpIdx := inst.CPIndex()

	fieldRef, err := cp.ResolveFieldRef(cpIdx)
	if err != nil {
		return nil, fmt.Errorf("putstatic: resolving field %d: %w", cpIdx, err)
	}

	target := ast.NewStaticFieldAccess(fieldRef)

	return stmt.NewAssignment(target, valueEntry.Value), nil
}

func invokeMethod(stack *StackSim, inst *bytecode.Instruction, cp CPResolver, kind ast.InvokeKind) (stmt.Statement, error) {
	cpIdx := inst.CPIndex()

	var (
		methodRef *ast.MethodRef
		err       error
	)

	if kind == ast.InvokeInterface {
		methodRef, err = cp.ResolveInterfaceMethodRef(cpIdx)
	} else {
		methodRef, err = cp.ResolveMethodRef(cpIdx)
	}

	if err != nil {
		return nil, fmt.Errorf("invoke: resolving method %d: %w", cpIdx, err)
	}

	// Pop arguments (right-to-left)
	argCount := len(methodRef.ParamTypes)

	args := make([]ast.Expression, argCount)
	for i := argCount - 1; i >= 0; i-- {
		entry, popErr := stack.Pop()
		if popErr != nil {
			return nil, fmt.Errorf("invoke args: %w", popErr)
		}

		args[i] = entry.Value
	}

	// Pop receiver object
	objEntry, err := stack.Pop()
	if err != nil {
		return nil, fmt.Errorf("invoke receiver: %w", err)
	}

	invocation := ast.NewMethodInvocation(kind, objEntry.Value, methodRef, args)

	// Push result if non-void
	if methodRef.ReturnType != types.TypeVoid {
		stack.Push(invocation)
		return stmt.NewNop(), nil
	}

	return stmt.NewExpressionStatement(invocation), nil
}

func invokeStatic(stack *StackSim, inst *bytecode.Instruction, cp CPResolver) (stmt.Statement, error) {
	cpIdx := inst.CPIndex()

	methodRef, err := cp.ResolveMethodRef(cpIdx)
	if err != nil {
		return nil, fmt.Errorf("invokestatic: resolving method %d: %w", cpIdx, err)
	}

	// Pop arguments (right-to-left)
	argCount := len(methodRef.ParamTypes)

	args := make([]ast.Expression, argCount)
	for i := argCount - 1; i >= 0; i-- {
		entry, popErr := stack.Pop()
		if popErr != nil {
			return nil, fmt.Errorf("invokestatic args: %w", popErr)
		}

		args[i] = entry.Value
	}

	invocation := ast.NewStaticInvocation(methodRef, args)

	if methodRef.ReturnType != types.TypeVoid {
		stack.Push(invocation)
		return stmt.NewNop(), nil
	}

	return stmt.NewExpressionStatement(invocation), nil
}

func invokeDynamic(stack *StackSim, inst *bytecode.Instruction, cp CPResolver) (stmt.Statement, error) {
	cpIdx := inst.CPIndex()

	dynInvoke, err := cp.ResolveInvokeDynamic(cpIdx)
	if err != nil {
		return nil, fmt.Errorf("invokedynamic: resolving %d: %w", cpIdx, err)
	}

	// Pop arguments from stack
	argCount := len(dynInvoke.Args)
	if argCount > 0 {
		args := make([]ast.Expression, argCount)
		for i := argCount - 1; i >= 0; i-- {
			entry, popErr := stack.Pop()
			if popErr != nil {
				return nil, fmt.Errorf("invokedynamic args: %w", popErr)
			}

			args[i] = entry.Value
		}

		dynInvoke.Args = args
	}

	if dynInvoke.JType != types.TypeVoid {
		stack.Push(dynInvoke)
		return stmt.NewNop(), nil
	}

	return stmt.NewExpressionStatement(dynInvoke), nil
}

func handleTableSwitch(stack *StackSim, inst *bytecode.Instruction) (stmt.Statement, error) {
	keyEntry, err := stack.Pop()
	if err != nil {
		return nil, fmt.Errorf("tableswitch: %w", err)
	}

	sw, err := bytecode.DecodeTableSwitchInstr(inst)
	if err != nil {
		return nil, fmt.Errorf("tableswitch decode: %w", err)
	}

	var cases []stmt.SwitchCase
	// Default case
	cases = append(cases, stmt.SwitchCase{
		TargetOffset: sw.Default,
		IsDefault:    true,
	})
	// Value cases
	for i, target := range sw.Targets {
		if target != sw.Default {
			cases = append(cases, stmt.SwitchCase{
				Values:       []int32{sw.Low + int32(i)},
				TargetOffset: target,
			})
		}
	}

	return stmt.NewSwitch(keyEntry.Value, cases), nil
}

func handleLookupSwitch(stack *StackSim, inst *bytecode.Instruction) (stmt.Statement, error) {
	keyEntry, err := stack.Pop()
	if err != nil {
		return nil, fmt.Errorf("lookupswitch: %w", err)
	}

	sw, err := bytecode.DecodeLookupSwitchInstr(inst)
	if err != nil {
		return nil, fmt.Errorf("lookupswitch decode: %w", err)
	}

	var cases []stmt.SwitchCase

	cases = append(cases, stmt.SwitchCase{
		TargetOffset: sw.Default,
		IsDefault:    true,
	})
	for _, pair := range sw.Pairs {
		if pair.Target != sw.Default {
			cases = append(cases, stmt.SwitchCase{
				Values:       []int32{pair.Match},
				TargetOffset: pair.Target,
			})
		}
	}

	return stmt.NewSwitch(keyEntry.Value, cases), nil
}

func newArrayElemType(nat bytecode.NewArrayType) types.JavaType {
	switch nat {
	case bytecode.ArrayTypeBoolean:
		return types.TypeBoolean
	case bytecode.ArrayTypeChar:
		return types.TypeChar
	case bytecode.ArrayTypeFloat:
		return types.TypeFloat
	case bytecode.ArrayTypeDouble:
		return types.TypeDouble
	case bytecode.ArrayTypeByte:
		return types.TypeByte
	case bytecode.ArrayTypeShort:
		return types.TypeShort
	case bytecode.ArrayTypeInt:
		return types.TypeInt
	case bytecode.ArrayTypeLong:
		return types.TypeLong
	default:
		return types.TypeInt
	}
}

func stackCategory(t types.JavaType) int {
	if t == nil {
		return 1
	}

	return t.StackCategory()
}
