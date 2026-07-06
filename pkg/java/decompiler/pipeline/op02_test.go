package pipeline

import (
	"fmt"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ---------- stub CPResolver ----------

type stubCP struct {
	classType   types.JavaType
	fieldRef    *ast.FieldRef
	methodRef   *ast.MethodRef
	literal     *ast.Literal
	dynInvoke   *ast.DynamicInvocation
	failClass   bool
	failField   bool
	failMethod  bool
	failLiteral bool
	failDynamic bool
}

func (s *stubCP) ResolveClass(index uint16) (types.JavaType, error) {
	if s.failClass {
		return nil, fmt.Errorf("class resolve fail")
	}
	if s.classType != nil {
		return s.classType, nil
	}
	return types.NewRefType("java.lang.Object"), nil
}

func (s *stubCP) ResolveFieldRef(index uint16) (*ast.FieldRef, error) {
	if s.failField {
		return nil, fmt.Errorf("field resolve fail")
	}
	if s.fieldRef != nil {
		return s.fieldRef, nil
	}
	return &ast.FieldRef{ClassName: "Foo", FieldName: "bar", FieldType: types.TypeInt}, nil
}

func (s *stubCP) ResolveMethodRef(index uint16) (*ast.MethodRef, error) {
	if s.failMethod {
		return nil, fmt.Errorf("method resolve fail")
	}
	if s.methodRef != nil {
		return s.methodRef, nil
	}
	return &ast.MethodRef{
		ClassName:  "Foo",
		MethodName: "doIt",
		ParamTypes: nil,
		ReturnType: types.TypeVoid,
	}, nil
}

func (s *stubCP) ResolveInterfaceMethodRef(index uint16) (*ast.MethodRef, error) {
	return s.ResolveMethodRef(index)
}

func (s *stubCP) ResolveLiteral(index uint16) (*ast.Literal, error) {
	if s.failLiteral {
		return nil, fmt.Errorf("literal resolve fail")
	}
	if s.literal != nil {
		return s.literal, nil
	}
	return ast.NewStringLiteral("hello"), nil
}

func (s *stubCP) ResolveInvokeDynamic(index uint16) (*ast.DynamicInvocation, error) {
	if s.failDynamic {
		return nil, fmt.Errorf("dynamic resolve fail")
	}
	if s.dynInvoke != nil {
		return s.dynInvoke, nil
	}
	return &ast.DynamicInvocation{
		Name:       "run",
		Descriptor: "()V",
		JType:      types.TypeVoid,
	}, nil
}

func (s *stubCP) ResolveNameAndType(index uint16) (string, string, error) {
	return "name", "descriptor", nil
}

// ---------- helpers ----------

func instrOf(op bytecode.Opcode, operand []byte) *bytecode.Instruction {
	return &bytecode.Instruction{Op: op, Operand: operand}
}

func nodeOf(op bytecode.Opcode, operand []byte) *InstrNode {
	return &InstrNode{Instr: instrOf(op, operand)}
}

// ---------- stmtConstants ----------

func TestStmtConstants_NOP(t *testing.T) {
	stack := NewStackSim()
	s, ok, err := stmtConstants(bytecode.NOP, instrOf(bytecode.NOP, nil), stack, nil, nil)
	if !ok || err != nil || s == nil {
		t.Fatalf("NOP: ok=%v err=%v s=%v", ok, err, s)
	}
	if s.Kind() != stmt.KindNop {
		t.Errorf("NOP should produce Nop, got %v", s.Kind())
	}
}

func TestStmtConstants_ACONST_NULL(t *testing.T) {
	stack := NewStackSim()
	s, ok, err := stmtConstants(bytecode.ACONST_NULL, instrOf(bytecode.ACONST_NULL, nil), stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Error("ACONST_NULL should push one value")
	}
	_ = s
}

func TestStmtConstants_ICONST_Values(t *testing.T) {
	cases := []struct {
		op  bytecode.Opcode
		val int64
	}{
		{bytecode.ICONST_M1, -1},
		{bytecode.ICONST_0, 0},
		{bytecode.ICONST_1, 1},
		{bytecode.ICONST_2, 2},
		{bytecode.ICONST_3, 3},
		{bytecode.ICONST_4, 4},
		{bytecode.ICONST_5, 5},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("ICONST_%d", tc.val), func(t *testing.T) {
			stack := NewStackSim()
			_, ok, err := stmtConstants(tc.op, instrOf(tc.op, nil), stack, nil, nil)
			if !ok || err != nil {
				t.Fatal(ok, err)
			}
			e, _ := stack.Pop()
			lit := e.Value.(*ast.Literal)
			if lit.IntVal != tc.val {
				t.Errorf("want %d, got %d", tc.val, lit.IntVal)
			}
		})
	}
}

func TestStmtConstants_LCONST(t *testing.T) {
	for _, op := range []bytecode.Opcode{bytecode.LCONST_0, bytecode.LCONST_1} {
		stack := NewStackSim()
		_, ok, err := stmtConstants(op, instrOf(op, nil), stack, nil, nil)
		if !ok || err != nil {
			t.Fatal(ok, err)
		}
		if stack.Depth() != 1 {
			t.Error("LCONST should push 1")
		}
	}
}

func TestStmtConstants_FCONST(t *testing.T) {
	for _, op := range []bytecode.Opcode{bytecode.FCONST_0, bytecode.FCONST_1, bytecode.FCONST_2} {
		stack := NewStackSim()
		_, ok, err := stmtConstants(op, instrOf(op, nil), stack, nil, nil)
		if !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
}

func TestStmtConstants_DCONST(t *testing.T) {
	for _, op := range []bytecode.Opcode{bytecode.DCONST_0, bytecode.DCONST_1} {
		stack := NewStackSim()
		_, ok, err := stmtConstants(op, instrOf(op, nil), stack, nil, nil)
		if !ok || err != nil {
			t.Fatal(ok, err)
		}
	}
}

func TestStmtConstants_BIPUSH(t *testing.T) {
	stack := NewStackSim()
	_, ok, err := stmtConstants(bytecode.BIPUSH, instrOf(bytecode.BIPUSH, []byte{42}), stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	e, _ := stack.Pop()
	lit := e.Value.(*ast.Literal)
	if lit.IntVal != 42 {
		t.Errorf("BIPUSH 42: want 42, got %d", lit.IntVal)
	}
}

func TestStmtConstants_SIPUSH(t *testing.T) {
	stack := NewStackSim()
	_, ok, err := stmtConstants(bytecode.SIPUSH, instrOf(bytecode.SIPUSH, []byte{0x01, 0x00}), stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	e, _ := stack.Pop()
	lit := e.Value.(*ast.Literal)
	if lit.IntVal != 256 {
		t.Errorf("SIPUSH 256: got %d", lit.IntVal)
	}
}

func TestStmtConstants_LDC(t *testing.T) {
	stack := NewStackSim()
	cp := &stubCP{}
	_, ok, err := stmtConstants(bytecode.LDC, instrOf(bytecode.LDC, []byte{0x01}), stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Error("LDC should push a value")
	}
}

func TestStmtConstants_LDC_Fail(t *testing.T) {
	stack := NewStackSim()
	cp := &stubCP{failLiteral: true}
	_, ok, err := stmtConstants(bytecode.LDC, instrOf(bytecode.LDC, []byte{0x01}), stack, nil, cp)
	if !ok || err == nil {
		t.Fatal("expected error on LDC resolve fail")
	}
}

func TestStmtConstants_UnknownOp(t *testing.T) {
	stack := NewStackSim()
	_, ok, _ := stmtConstants(bytecode.RETURN, instrOf(bytecode.RETURN, nil), stack, nil, nil)
	if ok {
		t.Error("RETURN is not a constant op, ok should be false")
	}
}

// ---------- stmtReturnsThrow ----------

func TestStmtReturnsThrow_RETURN(t *testing.T) {
	stack := NewStackSim()
	s, ok, err := stmtReturnsThrow(bytecode.RETURN, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindReturnVoid {
		t.Errorf("RETURN should produce ReturnVoid, got %v", s.Kind())
	}
}

func TestStmtReturnsThrow_IRETURN(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntOne)
	s, ok, err := stmtReturnsThrow(bytecode.IRETURN, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindReturn {
		t.Errorf("IRETURN should produce Return, got %v", s.Kind())
	}
}

func TestStmtReturnsThrow_IRETURN_Underflow(t *testing.T) {
	stack := NewStackSim()
	_, ok, err := stmtReturnsThrow(bytecode.IRETURN, nil, stack, nil, nil)
	if !ok || err == nil {
		t.Fatal("expected underflow error")
	}
}

func TestStmtReturnsThrow_ATHROW(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral())
	s, ok, err := stmtReturnsThrow(bytecode.ATHROW, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindThrow {
		t.Errorf("ATHROW should produce Throw, got %v", s.Kind())
	}
}

// ---------- stmtArithmetic ----------

func TestStmtArithmetic_IADD(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntZero)
	stack.Push(ast.LitIntOne)
	_, ok, err := stmtArithmetic(bytecode.IADD, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Errorf("IADD: want 1 on stack, got %d", stack.Depth())
	}
}

func TestStmtArithmetic_IADD_Underflow(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntZero) // only 1 value
	_, ok, err := stmtArithmetic(bytecode.IADD, nil, stack, nil, nil)
	if !ok || err == nil {
		t.Fatal("expected underflow error")
	}
}

func TestStmtArithmetic_INEG(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntOne)
	_, ok, err := stmtArithmetic(bytecode.INEG, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestStmtArithmetic_UnknownOp(t *testing.T) {
	stack := NewStackSim()
	_, ok, _ := stmtArithmetic(bytecode.RETURN, nil, stack, nil, nil)
	if ok {
		t.Error("RETURN is not arithmetic")
	}
}

// ---------- stmtConversions ----------

func TestStmtConversions_I2L(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntZero)
	_, ok, err := stmtConversions(bytecode.I2L, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestStmtConversions_UnknownOp(t *testing.T) {
	_, ok, _ := stmtConversions(bytecode.RETURN, nil, NewStackSim(), nil, nil)
	if ok {
		t.Error("RETURN is not a conversion")
	}
}

// ---------- stmtBranches ----------

func TestStmtBranches_GOTO(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.GOTO, []byte{0x00, 0x05}) // branch offset +5
	inst.Offset = 0
	s, ok, err := stmtBranches(bytecode.GOTO, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	g, ok2 := s.(*stmt.GotoStatement)
	if !ok2 {
		t.Fatalf("expected GotoStatement, got %T", s)
	}
	if g.TargetOffset != 5 {
		t.Errorf("goto target: want 5, got %d", g.TargetOffset)
	}
}

func TestStmtBranches_IFEQ(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntZero)
	inst := instrOf(bytecode.IFEQ, []byte{0x00, 0x0A})
	s, ok, err := stmtBranches(bytecode.IFEQ, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindIf {
		t.Errorf("IFEQ should produce If, got %v", s.Kind())
	}
}

func TestStmtBranches_IFNULL(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral())
	inst := instrOf(bytecode.IFNULL, []byte{0x00, 0x05})
	_, ok, err := stmtBranches(bytecode.IFNULL, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestStmtBranches_UnknownOp(t *testing.T) {
	_, ok, _ := stmtBranches(bytecode.RETURN, nil, NewStackSim(), nil, nil)
	if ok {
		t.Error("RETURN is not a branch")
	}
}

// ---------- stmtStackManip ----------

func TestStmtStackManip_POP(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntOne)
	s, ok, err := stmtStackManip(bytecode.POP, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindExpression {
		t.Errorf("POP should produce ExpressionStatement, got %v", s.Kind())
	}
	if stack.Depth() != 0 {
		t.Error("POP should leave empty stack")
	}
}

func TestStmtStackManip_POP_Underflow(t *testing.T) {
	_, ok, err := stmtStackManip(bytecode.POP, nil, NewStackSim(), nil, nil)
	if !ok || err == nil {
		t.Fatal("expected underflow")
	}
}

func TestStmtStackManip_POP2_Cat1(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntOne)
	stack.Push(ast.LitIntZero)
	s, ok, err := stmtStackManip(bytecode.POP2, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindCompound {
		t.Errorf("POP2 of two cat1 values should produce Compound, got %v", s.Kind())
	}
}

func TestStmtStackManip_DUP(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntOne)
	_, ok, err := stmtStackManip(bytecode.DUP, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 2 {
		t.Errorf("DUP: want 2, got %d", stack.Depth())
	}
}

func TestStmtStackManip_SWAP(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntZero)
	stack.Push(ast.LitIntOne)
	_, ok, err := stmtStackManip(bytecode.SWAP, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	top, _ := stack.Pop()
	if top.Value != ast.LitIntZero {
		t.Error("SWAP: top should be former second (LitIntZero)")
	}
}

func TestStmtStackManip_DUP_X1(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntZero) // second
	stack.Push(ast.LitIntOne)  // top
	_, ok, err := stmtStackManip(bytecode.DUP_X1, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	// ..., v2, v1 → ..., v1, v2, v1 → depth 3
	if stack.Depth() != 3 {
		t.Errorf("DUP_X1: want depth 3, got %d", stack.Depth())
	}
}

func TestStmtStackManip_UnknownOp(t *testing.T) {
	_, ok, _ := stmtStackManip(bytecode.RETURN, nil, NewStackSim(), nil, nil)
	if ok {
		t.Error("RETURN is not stack manip")
	}
}

// ---------- stmtMonitors ----------

func TestStmtMonitors_MONITORENTER(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral())
	s, ok, err := stmtMonitors(bytecode.MONITORENTER, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindMonitorEnter {
		t.Errorf("MONITORENTER: want MonitorEnter, got %v", s.Kind())
	}
}

func TestStmtMonitors_MONITOREXIT(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral())
	s, ok, err := stmtMonitors(bytecode.MONITOREXIT, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindMonitorExit {
		t.Errorf("MONITOREXIT: want MonitorExit, got %v", s.Kind())
	}
}

func TestStmtMonitors_UnknownOp(t *testing.T) {
	_, ok, _ := stmtMonitors(bytecode.RETURN, nil, NewStackSim(), nil, nil)
	if ok {
		t.Error("RETURN is not a monitor op")
	}
}

// ---------- stmtLoadsStores ----------

func TestStmtLoadsStores_ILOAD_0(t *testing.T) {
	method := &MethodInfo{IsStatic: true}
	stack := NewStackSim()
	_, ok, err := stmtLoadsStores(bytecode.ILOAD_0, instrOf(bytecode.ILOAD_0, nil), stack, method, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Errorf("ILOAD_0 should push 1, got depth %d", stack.Depth())
	}
}

func TestStmtLoadsStores_ISTORE_0(t *testing.T) {
	method := &MethodInfo{IsStatic: true}
	stack := NewStackSim()
	stack.Push(ast.LitIntOne)
	s, ok, err := stmtLoadsStores(bytecode.ISTORE_0, instrOf(bytecode.ISTORE_0, nil), stack, method, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindAssignment {
		t.Errorf("ISTORE_0 should produce Assignment, got %v", s.Kind())
	}
}

func TestStmtLoadsStores_ISTORE_Underflow(t *testing.T) {
	_, ok, err := stmtLoadsStores(bytecode.ISTORE_0, instrOf(bytecode.ISTORE_0, nil), NewStackSim(), nil, nil)
	if !ok || err == nil {
		t.Fatal("expected underflow error")
	}
}

func TestStmtLoadsStores_ALOAD_0_IsThis(t *testing.T) {
	// slot 0 of non-static = "this"
	method := &MethodInfo{IsStatic: false}
	stack := NewStackSim()
	_, ok, err := stmtLoadsStores(bytecode.ALOAD_0, instrOf(bytecode.ALOAD_0, nil), stack, method, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	e, _ := stack.Pop()
	varExpr, ok2 := e.Value.(*ast.VarExpression)
	if !ok2 {
		t.Fatalf("expected VarExpression, got %T", e.Value)
	}
	lv := varExpr.LVal.(*ast.LocalVariable)
	if lv.Name != "this" {
		t.Errorf("slot 0 in instance method should be 'this', got '%s'", lv.Name)
	}
}

func TestStmtLoadsStores_IINC(t *testing.T) {
	method := &MethodInfo{IsStatic: true, LocalVarNames: map[int]string{0: "i"}}
	inst := instrOf(bytecode.IINC, []byte{0x00, 0x01}) // slot 0, increment 1
	stack := NewStackSim()
	s, ok, err := stmtLoadsStores(bytecode.IINC, inst, stack, method, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindAssignment {
		t.Errorf("IINC should produce Assignment, got %v", s.Kind())
	}
}

func TestStmtLoadsStores_IINC_Negative(t *testing.T) {
	method := &MethodInfo{IsStatic: true}
	// slot 0, increment -1 (byte cast)
	inst := instrOf(bytecode.IINC, []byte{0x00, 0xFF}) // slot 0, increment -1 (as signed byte)
	stack := NewStackSim()
	s, ok, err := stmtLoadsStores(bytecode.IINC, inst, stack, method, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindAssignment {
		t.Errorf("IINC negative should produce Assignment")
	}
}

// ---------- stmtSubroutineSynthetic ----------

func TestStmtSubroutineSynthetic_JSR(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.JSR, []byte{0x00, 0x05})
	inst.Offset = 10
	s, ok, err := stmtSubroutineSynthetic(bytecode.JSR, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindGoto {
		t.Errorf("JSR should produce Goto, got %v", s.Kind())
	}
	if stack.Depth() != 1 {
		t.Error("JSR should push return address")
	}
}

func TestStmtSubroutineSynthetic_RET(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.RET, []byte{0x00})
	s, ok, err := stmtSubroutineSynthetic(bytecode.RET, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindGoto {
		t.Errorf("RET should produce Goto, got %v", s.Kind())
	}
}

func TestStmtSubroutineSynthetic_FAKE_TRY(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.FAKE_TRY, nil)
	s, ok, err := stmtSubroutineSynthetic(bytecode.FAKE_TRY, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindTry {
		t.Errorf("FAKE_TRY should produce Try, got %v", s.Kind())
	}
}

func TestStmtSubroutineSynthetic_FAKE_CATCH(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.FAKE_CATCH, nil)
	s, ok, err := stmtSubroutineSynthetic(bytecode.FAKE_CATCH, inst, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindCatch {
		t.Errorf("FAKE_CATCH should produce Catch, got %v", s.Kind())
	}
	if stack.Depth() != 1 {
		t.Error("FAKE_CATCH should push caught exception variable")
	}
}

// ---------- stmtFieldAccess ----------

func TestStmtFieldAccess_GETSTATIC(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.GETSTATIC, []byte{0x00, 0x01})
	cp := &stubCP{}
	s, ok, err := stmtFieldAccess(bytecode.GETSTATIC, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	_ = s
	if stack.Depth() != 1 {
		t.Error("GETSTATIC should push field value")
	}
}

func TestStmtFieldAccess_GETFIELD(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral()) // object ref
	inst := instrOf(bytecode.GETFIELD, []byte{0x00, 0x01})
	cp := &stubCP{}
	_, ok, err := stmtFieldAccess(bytecode.GETFIELD, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Error("GETFIELD should push field value")
	}
}

func TestStmtFieldAccess_PUTSTATIC(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.LitIntOne) // value to store
	inst := instrOf(bytecode.PUTSTATIC, []byte{0x00, 0x01})
	cp := &stubCP{}
	s, ok, err := stmtFieldAccess(bytecode.PUTSTATIC, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindAssignment {
		t.Errorf("PUTSTATIC should produce Assignment, got %v", s.Kind())
	}
}

func TestStmtFieldAccess_PUTFIELD(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral()) // object ref
	stack.Push(ast.LitIntOne)        // value
	inst := instrOf(bytecode.PUTFIELD, []byte{0x00, 0x01})
	cp := &stubCP{}
	s, ok, err := stmtFieldAccess(bytecode.PUTFIELD, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindAssignment {
		t.Errorf("PUTFIELD should produce Assignment, got %v", s.Kind())
	}
}

// ---------- stmtInvokes ----------

func TestStmtInvokes_INVOKESTATIC_Void(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.INVOKESTATIC, []byte{0x00, 0x01})
	cp := &stubCP{} // returns void method
	s, ok, err := stmtInvokes(bytecode.INVOKESTATIC, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindExpression {
		t.Errorf("INVOKESTATIC void should produce ExpressionStatement, got %v", s.Kind())
	}
}

func TestStmtInvokes_INVOKESTATIC_NonVoid(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.INVOKESTATIC, []byte{0x00, 0x01})
	cp := &stubCP{methodRef: &ast.MethodRef{
		ClassName:  "Foo",
		MethodName: "getValue",
		ReturnType: types.TypeInt,
	}}
	s, ok, err := stmtInvokes(bytecode.INVOKESTATIC, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindNop {
		t.Errorf("INVOKESTATIC non-void should push and return nop, got %v", s.Kind())
	}
	if stack.Depth() != 1 {
		t.Error("non-void invoke should push return value")
	}
}

func TestStmtInvokes_INVOKEVIRTUAL(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral()) // receiver
	inst := instrOf(bytecode.INVOKEVIRTUAL, []byte{0x00, 0x01})
	cp := &stubCP{} // void
	s, ok, err := stmtInvokes(bytecode.INVOKEVIRTUAL, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindExpression {
		t.Errorf("INVOKEVIRTUAL void: expected ExpressionStatement, got %v", s.Kind())
	}
}

func TestStmtInvokes_INVOKEDYNAMIC_Void(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.INVOKEDYNAMIC, []byte{0x00, 0x01})
	cp := &stubCP{} // returns void DynamicInvocation
	s, ok, err := stmtInvokes(bytecode.INVOKEDYNAMIC, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindExpression {
		t.Errorf("INVOKEDYNAMIC void should produce ExpressionStatement, got %v", s.Kind())
	}
}

// ---------- stmtObjectAlloc ----------

func TestStmtObjectAlloc_NEW(t *testing.T) {
	stack := NewStackSim()
	inst := instrOf(bytecode.NEW, []byte{0x00, 0x01})
	cp := &stubCP{}
	_, ok, err := stmtObjectAlloc(bytecode.NEW, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Error("NEW should push object ref")
	}
}

func TestStmtObjectAlloc_ARRAYLENGTH(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral()) // array ref
	_, ok, err := stmtObjectAlloc(bytecode.ARRAYLENGTH, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Error("ARRAYLENGTH should push length")
	}
}

func TestStmtObjectAlloc_INSTANCEOF(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral())
	inst := instrOf(bytecode.INSTANCEOF, []byte{0x00, 0x01})
	cp := &stubCP{}
	_, ok, err := stmtObjectAlloc(bytecode.INSTANCEOF, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
}

func TestStmtObjectAlloc_CHECKCAST(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral())
	inst := instrOf(bytecode.CHECKCAST, []byte{0x00, 0x01})
	cp := &stubCP{}
	_, ok, err := stmtObjectAlloc(bytecode.CHECKCAST, inst, stack, nil, cp)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
}

// ---------- stmtArrayOps ----------

func TestStmtArrayOps_IALOAD(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral()) // array
	stack.Push(ast.LitIntZero)       // index
	_, ok, err := stmtArrayOps(bytecode.IALOAD, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if stack.Depth() != 1 {
		t.Error("IALOAD should leave 1 value on stack")
	}
}

func TestStmtArrayOps_IASTORE(t *testing.T) {
	stack := NewStackSim()
	stack.Push(ast.NewNullLiteral()) // array
	stack.Push(ast.LitIntZero)       // index
	stack.Push(ast.LitIntOne)        // value
	s, ok, err := stmtArrayOps(bytecode.IASTORE, nil, stack, nil, nil)
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if s.Kind() != stmt.KindAssignment {
		t.Errorf("IASTORE should produce Assignment, got %v", s.Kind())
	}
}

// ---------- createStatement / guardCreateStatement ----------

func TestGuardCreateStatement_UnimplementedOp(t *testing.T) {
	node := nodeOf(bytecode.Opcode(0xFE), nil) // unknown
	stack := NewStackSim()
	_, err := guardCreateStatement(node, stack, nil, nil)
	if err == nil {
		t.Error("expected error for unimplemented opcode")
	}
}

// ---------- SimulateStack ----------

func TestSimulateStack_Empty(t *testing.T) {
	err := SimulateStack(nil, nil, nil)
	if err != nil {
		t.Fatal("nil nodes should return nil error")
	}
}

func TestSimulateStack_SingleNOP(t *testing.T) {
	instr := &bytecode.Instruction{Offset: 0, Op: bytecode.NOP}
	node := NewInstrNode(0, instr)
	err := SimulateStack([]*InstrNode{node}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if node.Statement == nil {
		t.Error("NOP node should have a statement")
	}
}

// ---------- localVarFor ----------

func TestLocalVarFor_NilMethod(t *testing.T) {
	lv := localVarFor(nil, 0, types.TypeInt)
	if lv == nil {
		t.Error("localVarFor with nil method should return valid var")
	}
}

func TestLocalVarFor_ThisSlot(t *testing.T) {
	m := &MethodInfo{IsStatic: false}
	lv := localVarFor(m, 0, types.ObjectType)
	if lv.Name != "this" {
		t.Errorf("slot 0 non-static: want 'this', got '%s'", lv.Name)
	}
}

func TestLocalVarFor_StaticSlot0(t *testing.T) {
	m := &MethodInfo{IsStatic: true}
	lv := localVarFor(m, 0, types.TypeInt)
	if lv.Name == "this" {
		t.Error("slot 0 static should not be 'this'")
	}
}

func TestLocalVarFor_NamedVar(t *testing.T) {
	m := &MethodInfo{IsStatic: true, LocalVarNames: map[int]string{2: "count"}}
	lv := localVarFor(m, 2, types.TypeInt)
	if lv.Name != "count" {
		t.Errorf("named var: want 'count', got '%s'", lv.Name)
	}
}

// ---------- stackCategory ----------

func TestStackCategory_NilType(t *testing.T) {
	if stackCategory(nil) != 1 {
		t.Error("nil type should have stack category 1")
	}
}

func TestStackCategory_LongType(t *testing.T) {
	if stackCategory(types.TypeLong) != 2 {
		t.Errorf("long should have stack category 2, got %d", stackCategory(types.TypeLong))
	}
}

func TestStackCategory_IntType(t *testing.T) {
	if stackCategory(types.TypeInt) != 1 {
		t.Errorf("int should have stack category 1, got %d", stackCategory(types.TypeInt))
	}
}

// ---------- newArrayElemType ----------

func TestNewArrayElemType(t *testing.T) {
	cases := []struct {
		nat      bytecode.NewArrayType
		expected types.JavaType
	}{
		{bytecode.ArrayTypeBoolean, types.TypeBoolean},
		{bytecode.ArrayTypeChar, types.TypeChar},
		{bytecode.ArrayTypeFloat, types.TypeFloat},
		{bytecode.ArrayTypeDouble, types.TypeDouble},
		{bytecode.ArrayTypeByte, types.TypeByte},
		{bytecode.ArrayTypeShort, types.TypeShort},
		{bytecode.ArrayTypeInt, types.TypeInt},
		{bytecode.ArrayTypeLong, types.TypeLong},
		{bytecode.NewArrayType(99), types.TypeInt}, // default
	}
	for _, tc := range cases {
		got := newArrayElemType(tc.nat)
		if got != tc.expected {
			t.Errorf("newArrayElemType(%d): want %v, got %v", tc.nat, tc.expected, got)
		}
	}
}
