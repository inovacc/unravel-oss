package ast

import (
	"math"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// helpers ---------------------------------------------------------------

func intType(t *testing.T) types.JavaType {
	t.Helper()
	jt, err := types.ParseFieldDescriptor("I")
	if err != nil {
		t.Fatalf("parse int type: %v", err)
	}
	return jt
}

func boolType(t *testing.T) types.JavaType {
	t.Helper()
	return types.TypeBoolean
}

func strType(t *testing.T) types.JavaType {
	t.Helper()
	return types.StringType
}

func longType(t *testing.T) types.JavaType {
	t.Helper()
	jt, err := types.ParseFieldDescriptor("J")
	if err != nil {
		t.Fatalf("parse long type: %v", err)
	}
	return jt
}

func floatType(t *testing.T) types.JavaType {
	t.Helper()
	jt, err := types.ParseFieldDescriptor("F")
	if err != nil {
		t.Fatalf("parse float type: %v", err)
	}
	return jt
}

func doubleType(t *testing.T) types.JavaType {
	t.Helper()
	jt, err := types.ParseFieldDescriptor("D")
	if err != nil {
		t.Fatalf("parse double type: %v", err)
	}
	return jt
}

// ---- Precedence constants -------------------------------------------------

func TestPrecedenceConstants(t *testing.T) {
	// Ensure ordering is correct — lower iota = higher actual precedence (lower number).
	cases := []struct {
		name string
		low  Precedence
		high Precedence
	}{
		{"Highest < Postfix", PrecHighest, PrecPostfix},
		{"Postfix < Unary", PrecPostfix, PrecUnary},
		{"Unary < Multiplicative", PrecUnary, PrecMultiplicative},
		{"Multiplicative < Additive", PrecMultiplicative, PrecAdditive},
		{"Additive < Shift", PrecAdditive, PrecShift},
		{"Shift < Relational", PrecShift, PrecRelational},
		{"Relational < Equality", PrecRelational, PrecEquality},
		{"Equality < BitwiseAnd", PrecEquality, PrecBitwiseAnd},
		{"BitwiseAnd < BitwiseXor", PrecBitwiseAnd, PrecBitwiseXor},
		{"BitwiseXor < BitwiseOr", PrecBitwiseXor, PrecBitwiseOr},
		{"BitwiseOr < LogicalAnd", PrecBitwiseOr, PrecLogicalAnd},
		{"LogicalAnd < LogicalOr", PrecLogicalAnd, PrecLogicalOr},
		{"LogicalOr < Ternary", PrecLogicalOr, PrecTernary},
		{"Ternary < Assignment", PrecTernary, PrecAssignment},
		{"Assignment < Lowest", PrecAssignment, PrecLowest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.low >= tc.high {
				t.Errorf("expected %d < %d", tc.low, tc.high)
			}
		})
	}
}

// ---- TypeSource constants -------------------------------------------------

func TestTypeSourceConstants(t *testing.T) {
	srcs := []TypeSource{
		TypeFromBytecode, TypeFromOperation, TypeFromExpression,
		TypeFromLiteral, TypeFromField, TypeFromMethod,
	}
	seen := map[TypeSource]bool{}
	for _, s := range srcs {
		if seen[s] {
			t.Errorf("duplicate TypeSource value %d", s)
		}
		seen[s] = true
	}
}

// ---- InferredType ---------------------------------------------------------

func TestNewInferredType(t *testing.T) {
	it := NewInferredType(types.TypeInt, TypeFromBytecode)
	if it == nil {
		t.Fatal("nil result")
	}
	if it.JType != types.TypeInt {
		t.Errorf("JType: got %v want %v", it.JType, types.TypeInt)
	}
	if it.Source != TypeFromBytecode {
		t.Errorf("Source: got %v want %v", it.Source, TypeFromBytecode)
	}
}

// ---- Literal constructors + String() branches ----------------------------

func TestLiteralInt(t *testing.T) {
	cases := []struct {
		name string
		v    int32
		want string
	}{
		{"zero", 0, "0"},
		{"one", 1, "1"},
		{"negative", -42, "-42"},
		{"large", 1000000, "1000000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewIntLiteral(tc.v)
			if l.Kind != LitInt {
				t.Errorf("Kind: got %d want %d", l.Kind, LitInt)
			}
			if l.String() != tc.want {
				t.Errorf("String: got %q want %q", l.String(), tc.want)
			}
			if l.Type() != types.TypeInt {
				t.Errorf("Type: want TypeInt")
			}
			if l.Precedence() != PrecHighest {
				t.Errorf("Precedence: want PrecHighest")
			}
			if !l.IsSimple() {
				t.Error("IsSimple: want true")
			}
			if l.Children() != nil {
				t.Error("Children: want nil")
			}
		})
	}
}

func TestLiteralLong(t *testing.T) {
	l := NewLongLiteral(9876543210)
	if !strings.HasSuffix(l.String(), "L") {
		t.Errorf("long literal should end with L, got %q", l.String())
	}
}

func TestLiteralFloat(t *testing.T) {
	cases := []struct {
		name string
		v    float32
		want string
	}{
		{"normal", 3.14, "3.14f"},
		{"posInf", float32(math.Inf(1)), "Float.POSITIVE_INFINITY"},
		{"negInf", float32(math.Inf(-1)), "Float.NEGATIVE_INFINITY"},
		{"nan", float32(math.NaN()), "Float.NaN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewFloatLiteral(tc.v)
			if l.String() != tc.want {
				t.Errorf("String: got %q want %q", l.String(), tc.want)
			}
		})
	}
}

func TestLiteralDouble(t *testing.T) {
	cases := []struct {
		name string
		v    float64
		want string
	}{
		{"normal", 2.718281828, "2.718281828d"},
		{"posInf", math.Inf(1), "Double.POSITIVE_INFINITY"},
		{"negInf", math.Inf(-1), "Double.NEGATIVE_INFINITY"},
		{"nan", math.NaN(), "Double.NaN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := NewDoubleLiteral(tc.v)
			if l.String() != tc.want {
				t.Errorf("String: got %q want %q", l.String(), tc.want)
			}
		})
	}
}

func TestLiteralString(t *testing.T) {
	l := NewStringLiteral("hello")
	if l.String() != `"hello"` {
		t.Errorf("String: got %q", l.String())
	}
	if l.Type() != types.StringType {
		t.Error("Type: want StringType")
	}
}

func TestLiteralNull(t *testing.T) {
	l := NewNullLiteral()
	if l.String() != "null" {
		t.Errorf("String: got %q", l.String())
	}
	if l.Type() != types.TypeNull {
		t.Error("Type: want TypeNull")
	}
}

func TestLiteralBool(t *testing.T) {
	tr := NewBoolLiteral(true)
	fa := NewBoolLiteral(false)
	if tr.String() != "true" {
		t.Errorf("true.String: got %q", tr.String())
	}
	if fa.String() != "false" {
		t.Errorf("false.String: got %q", fa.String())
	}
	if !tr.BoolValue() {
		t.Error("BoolValue: true literal should return true")
	}
	if fa.BoolValue() {
		t.Error("BoolValue: false literal should return false")
	}
}

func TestLiteralChar(t *testing.T) {
	l := NewCharLiteral(65) // 'A'
	if !strings.HasPrefix(l.String(), "'") {
		t.Errorf("char literal should start with quote, got %q", l.String())
	}
}

func TestLiteralByte(t *testing.T) {
	l := NewByteLiteral(127)
	if !strings.Contains(l.String(), "(byte)") {
		t.Errorf("byte literal should contain cast, got %q", l.String())
	}
}

func TestLiteralShort(t *testing.T) {
	l := NewShortLiteral(32767)
	if !strings.Contains(l.String(), "(short)") {
		t.Errorf("short literal should contain cast, got %q", l.String())
	}
}

func TestLiteralClass(t *testing.T) {
	l := NewClassLiteral(types.StringType)
	if !strings.HasSuffix(l.String(), ".class") {
		t.Errorf("class literal should end with .class, got %q", l.String())
	}
}

func TestIntLiteralFromOpcode(t *testing.T) {
	cases := []struct {
		val  int32
		want *Literal
	}{
		{0, LitIntZero},
		{1, LitIntOne},
		{-1, LitIntM1},
		{3, nil}, // non-cached
	}
	for _, tc := range cases {
		l := IntLiteralFromOpcode(tc.val)
		if tc.want != nil && l != tc.want {
			t.Errorf("val=%d: expected cached literal %p, got %p", tc.val, tc.want, l)
		}
		if tc.want == nil && l == nil {
			t.Errorf("val=%d: got nil literal", tc.val)
		}
	}
}

func TestPreDefinedLiterals(t *testing.T) {
	if LitIntZero.IntVal != 0 {
		t.Error("LitIntZero.IntVal != 0")
	}
	if LitIntOne.IntVal != 1 {
		t.Error("LitIntOne.IntVal != 1")
	}
	if LitIntM1.IntVal != -1 {
		t.Error("LitIntM1.IntVal != -1")
	}
	if LitLongZero.Kind != LitLong {
		t.Error("LitLongZero.Kind != LitLong")
	}
	if LitLongOne.IntVal != 1 {
		t.Error("LitLongOne.IntVal != 1")
	}
	if LitFloatZero.Kind != LitFloat {
		t.Error("LitFloatZero.Kind != LitFloat")
	}
	if LitDoubleZero.Kind != LitDouble {
		t.Error("LitDoubleZero.Kind != LitDouble")
	}
	if !LitTrue.BoolValue() {
		t.Error("LitTrue.BoolValue() should be true")
	}
	if LitFalse.BoolValue() {
		t.Error("LitFalse.BoolValue() should be false")
	}
	if LitNullVal.Kind != LitNull {
		t.Error("LitNullVal.Kind != LitNull")
	}
}

// ---- LocalVariable -------------------------------------------------------

func TestLocalVariable(t *testing.T) {
	t.Run("unnamed", func(t *testing.T) {
		lv := NewLocalVariable(2, types.TypeInt)
		if lv.Slot != 2 {
			t.Errorf("Slot: got %d want 2", lv.Slot)
		}
		if lv.Name != "var2" {
			t.Errorf("Name: got %q want var2", lv.Name)
		}
		if lv.String() != "var2" {
			t.Errorf("String: got %q want var2", lv.String())
		}
		if lv.LValueName() != "var2" {
			t.Errorf("LValueName: got %q want var2", lv.LValueName())
		}
		if !lv.IsSimple() {
			t.Error("IsSimple: want true")
		}
		if lv.Children() != nil {
			t.Error("Children: want nil")
		}
		if lv.Precedence() != PrecHighest {
			t.Error("Precedence: want PrecHighest")
		}
	})
	t.Run("named", func(t *testing.T) {
		lv := NewNamedLocalVariable(0, "myVar", types.TypeBoolean)
		if lv.Name != "myVar" {
			t.Errorf("Name: got %q want myVar", lv.Name)
		}
		if lv.String() != "myVar" {
			t.Errorf("String: got %q want myVar", lv.String())
		}
	})
	t.Run("versioned", func(t *testing.T) {
		lv := NewLocalVariable(1, types.TypeInt)
		lv.Version = 3
		s := lv.String()
		if !strings.Contains(s, "_3") {
			t.Errorf("versioned String: got %q, want suffix _3", s)
		}
	})
}

// ---- StackValue ----------------------------------------------------------

func TestStackValue(t *testing.T) {
	sv := NewStackValue(5, types.TypeInt)
	if sv.Idx != 5 {
		t.Errorf("Idx: got %d want 5", sv.Idx)
	}
	if sv.String() != "stack[5]" {
		t.Errorf("String: got %q want stack[5]", sv.String())
	}
	if sv.LValueName() != "stack_5" {
		t.Errorf("LValueName: got %q want stack_5", sv.LValueName())
	}
	if !sv.IsSimple() {
		t.Error("IsSimple: want true")
	}
	if sv.Children() != nil {
		t.Error("Children: want nil")
	}
	if sv.Precedence() != PrecHighest {
		t.Error("Precedence: want PrecHighest")
	}
}

// ---- VarExpression -------------------------------------------------------

func TestVarExpression(t *testing.T) {
	lv := NewLocalVariable(0, types.TypeInt)
	ve := NewVarExpression(lv)
	if ve.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if ve.String() != lv.String() {
		t.Errorf("String: got %q want %q", ve.String(), lv.String())
	}
	if ve.Precedence() != PrecHighest {
		t.Error("Precedence: want PrecHighest")
	}
	if !ve.IsSimple() {
		t.Error("IsSimple: want true")
	}
	ch := ve.Children()
	if len(ch) != 1 || ch[0] != lv {
		t.Error("Children: want [lv]")
	}
}

// ---- ArithOp -------------------------------------------------------------

func TestArithOpString(t *testing.T) {
	cases := []struct {
		op   ArithOp
		want string
	}{
		{OpAdd, "+"},
		{OpSub, "-"},
		{OpMul, "*"},
		{OpDiv, "/"},
		{OpRem, "%"},
		{OpAnd, "&"},
		{OpOr, "|"},
		{OpXor, "^"},
		{OpShl, "<<"},
		{OpShr, ">>"},
		{OpUShr, ">>>"},
		{OpLCmp, "lcmp"},
		{OpFCmpL, "fcmpl"},
		{OpFCmpG, "fcmpg"},
		{OpDCmpL, "dcmpl"},
		{OpDCmpG, "dcmpg"},
		{ArithOp(99), "ArithOp(99)"}, // out-of-range fallback
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if tc.op.String() != tc.want {
				t.Errorf("got %q want %q", tc.op.String(), tc.want)
			}
		})
	}
}

func TestArithOpPrecedence(t *testing.T) {
	cases := []struct {
		op   ArithOp
		want Precedence
	}{
		{OpMul, PrecMultiplicative},
		{OpDiv, PrecMultiplicative},
		{OpRem, PrecMultiplicative},
		{OpAdd, PrecAdditive},
		{OpSub, PrecAdditive},
		{OpShl, PrecShift},
		{OpShr, PrecShift},
		{OpUShr, PrecShift},
		{OpAnd, PrecBitwiseAnd},
		{OpXor, PrecBitwiseXor},
		{OpOr, PrecBitwiseOr},
		{OpLCmp, PrecHighest},  // default
		{OpFCmpL, PrecHighest}, // default
	}
	for _, tc := range cases {
		t.Run(tc.op.String(), func(t *testing.T) {
			if tc.op.Precedence() != tc.want {
				t.Errorf("op %v: got %v want %v", tc.op, tc.op.Precedence(), tc.want)
			}
		})
	}
}

func TestArithOpIsCmp(t *testing.T) {
	for _, op := range []ArithOp{OpLCmp, OpFCmpL, OpFCmpG, OpDCmpL, OpDCmpG} {
		if !op.IsCmp() {
			t.Errorf("%v should be a cmp op", op)
		}
	}
	for _, op := range []ArithOp{OpAdd, OpSub, OpMul, OpDiv, OpRem, OpAnd, OpOr, OpXor, OpShl, OpShr, OpUShr} {
		if op.IsCmp() {
			t.Errorf("%v should not be a cmp op", op)
		}
	}
}

// ---- ArithmeticOperation -------------------------------------------------

func TestArithmeticOperation(t *testing.T) {
	t.Run("add", func(t *testing.T) {
		lhs := NewIntLiteral(1)
		rhs := NewIntLiteral(2)
		op := NewArithmeticOperation(OpAdd, lhs, rhs, types.TypeInt)
		if op.IsSimple() {
			t.Error("IsSimple: want false")
		}
		if op.Precedence() != PrecAdditive {
			t.Errorf("Precedence: got %v want PrecAdditive", op.Precedence())
		}
		s := op.String()
		if !strings.Contains(s, "+") {
			t.Errorf("String should contain +, got %q", s)
		}
		ch := op.Children()
		if len(ch) != 2 {
			t.Errorf("Children: want 2, got %d", len(ch))
		}
		if op.Type() != types.TypeInt {
			t.Error("Type: want TypeInt")
		}
	})
}

// ---- CompOp --------------------------------------------------------------

func TestCompOpString(t *testing.T) {
	cases := []struct {
		op   CompOp
		want string
	}{
		{CmpEq, "=="},
		{CmpNe, "!="},
		{CmpLt, "<"},
		{CmpLe, "<="},
		{CmpGt, ">"},
		{CmpGe, ">="},
		{CompOp(99), "CompOp(99)"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if tc.op.String() != tc.want {
				t.Errorf("got %q want %q", tc.op.String(), tc.want)
			}
		})
	}
}

func TestCompOpNegate(t *testing.T) {
	pairs := [][2]CompOp{
		{CmpEq, CmpNe},
		{CmpNe, CmpEq},
		{CmpLt, CmpGe},
		{CmpLe, CmpGt},
		{CmpGt, CmpLe},
		{CmpGe, CmpLt},
	}
	for _, p := range pairs {
		got := p[0].Negate()
		if got != p[1] {
			t.Errorf("Negate(%v): got %v want %v", p[0], got, p[1])
		}
		// double negate returns original
		if p[0].Negate().Negate() != p[0] {
			t.Errorf("double Negate(%v) not identity", p[0])
		}
	}
	// out-of-range: returns self
	unknown := CompOp(99)
	if unknown.Negate() != unknown {
		t.Error("out-of-range Negate should return self")
	}
}

// ---- ComparisonOperation -------------------------------------------------

func TestComparisonOperation(t *testing.T) {
	lhs := NewIntLiteral(0)
	rhs := NewIntLiteral(1)
	t.Run("equality op", func(t *testing.T) {
		c := NewComparisonOperation(CmpEq, lhs, rhs)
		if c.Precedence() != PrecEquality {
			t.Errorf("CmpEq precedence: got %v want PrecEquality", c.Precedence())
		}
		if c.Type() != types.TypeBoolean {
			t.Error("Type: want TypeBoolean")
		}
		if c.IsSimple() {
			t.Error("IsSimple: want false")
		}
		ch := c.Children()
		if len(ch) != 2 {
			t.Errorf("Children: want 2, got %d", len(ch))
		}
	})
	t.Run("ne op", func(t *testing.T) {
		c := NewComparisonOperation(CmpNe, lhs, rhs)
		if c.Precedence() != PrecEquality {
			t.Errorf("CmpNe precedence: got %v want PrecEquality", c.Precedence())
		}
	})
	t.Run("relational op", func(t *testing.T) {
		c := NewComparisonOperation(CmpLt, lhs, rhs)
		if c.Precedence() != PrecRelational {
			t.Errorf("CmpLt precedence: got %v want PrecRelational", c.Precedence())
		}
	})
	t.Run("negate", func(t *testing.T) {
		c := NewComparisonOperation(CmpEq, lhs, rhs)
		neg := c.Negate()
		if neg.Op != CmpNe {
			t.Errorf("Negate: got %v want CmpNe", neg.Op)
		}
	})
	t.Run("string", func(t *testing.T) {
		c := NewComparisonOperation(CmpGt, lhs, rhs)
		if !strings.Contains(c.String(), ">") {
			t.Errorf("String: got %q, want >", c.String())
		}
	})
}

// ---- BoolOp --------------------------------------------------------------

func TestBoolOp(t *testing.T) {
	cases := []struct {
		op   BoolOp
		want string
	}{
		{BoolAnd, "&&"},
		{BoolOr, "||"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if tc.op.String() != tc.want {
				t.Errorf("got %q want %q", tc.op.String(), tc.want)
			}
		})
	}
}

// ---- BooleanOperation ----------------------------------------------------

func TestBooleanOperation(t *testing.T) {
	lhs := NewBoolLiteral(true)
	rhs := NewBoolLiteral(false)
	t.Run("and", func(t *testing.T) {
		b := NewBooleanOperation(BoolAnd, lhs, rhs)
		if b.Precedence() != PrecLogicalAnd {
			t.Errorf("And precedence: got %v want PrecLogicalAnd", b.Precedence())
		}
		if b.Type() != types.TypeBoolean {
			t.Error("Type: want TypeBoolean")
		}
		if b.IsSimple() {
			t.Error("IsSimple: want false")
		}
		if len(b.Children()) != 2 {
			t.Errorf("Children: want 2, got %d", len(b.Children()))
		}
		if !strings.Contains(b.String(), "&&") {
			t.Errorf("String: want &&, got %q", b.String())
		}
	})
	t.Run("or", func(t *testing.T) {
		b := NewBooleanOperation(BoolOr, lhs, rhs)
		if b.Precedence() != PrecLogicalOr {
			t.Errorf("Or precedence: got %v want PrecLogicalOr", b.Precedence())
		}
		if !strings.Contains(b.String(), "||") {
			t.Errorf("String: want ||, got %q", b.String())
		}
	})
}

// ---- NegationExpression --------------------------------------------------

func TestNegationExpression(t *testing.T) {
	t.Run("boolean negation", func(t *testing.T) {
		cond := NewBoolLiteral(true)
		n := NewNegationExpression(cond)
		if n.Type() != types.TypeBoolean {
			t.Error("Type: want TypeBoolean")
		}
		if !strings.HasPrefix(n.String(), "!") {
			t.Errorf("String: want ! prefix, got %q", n.String())
		}
		if n.Precedence() != PrecUnary {
			t.Error("Precedence: want PrecUnary")
		}
		if n.IsSimple() {
			t.Error("IsSimple: want false")
		}
		if len(n.Children()) != 1 {
			t.Errorf("Children: want 1, got %d", len(n.Children()))
		}
	})
	t.Run("bitwise negation", func(t *testing.T) {
		operand := NewIntLiteral(42)
		n := NewNegationExpression(operand)
		if !strings.HasPrefix(n.String(), "~") {
			t.Errorf("String: want ~ prefix, got %q", n.String())
		}
	})
}

// ---- ArithmeticNegation --------------------------------------------------

func TestArithmeticNegation(t *testing.T) {
	operand := NewIntLiteral(5)
	an := NewArithmeticNegation(operand, types.TypeInt)
	if !strings.HasPrefix(an.String(), "-") {
		t.Errorf("String: want - prefix, got %q", an.String())
	}
	if an.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if an.Precedence() != PrecUnary {
		t.Error("Precedence: want PrecUnary")
	}
	if an.IsSimple() {
		t.Error("IsSimple: want false")
	}
	if len(an.Children()) != 1 {
		t.Error("Children: want 1")
	}
}

// ---- CastExpression ------------------------------------------------------

func TestCastExpression(t *testing.T) {
	operand := NewIntLiteral(10)
	ce := NewCastExpression(operand, types.TypeFloat)
	if ce.Type() != types.TypeFloat {
		t.Error("Type: want TypeFloat")
	}
	if ce.Precedence() != PrecUnary {
		t.Error("Precedence: want PrecUnary")
	}
	if ce.IsSimple() {
		t.Error("IsSimple: want false")
	}
	s := ce.String()
	if !strings.Contains(s, "float") {
		t.Errorf("String: want 'float', got %q", s)
	}
	if len(ce.Children()) != 1 {
		t.Error("Children: want 1")
	}
	if !ce.Forced {
		t.Error("Forced: want true")
	}
}

// ---- InstanceOfExpression ------------------------------------------------

func TestInstanceOfExpression(t *testing.T) {
	operand := NewLocalVariable(0, types.ObjectType)
	ie := NewInstanceOfExpression(operand, types.StringType)
	if ie.Type() != types.TypeBoolean {
		t.Error("Type: want TypeBoolean")
	}
	if ie.Precedence() != PrecRelational {
		t.Error("Precedence: want PrecRelational")
	}
	if ie.IsSimple() {
		t.Error("IsSimple: want false")
	}
	s := ie.String()
	if !strings.Contains(s, "instanceof") {
		t.Errorf("String: want instanceof, got %q", s)
	}
	if len(ie.Children()) != 1 {
		t.Error("Children: want 1")
	}
}

// ---- AssignmentExpression ------------------------------------------------

func TestAssignmentExpression(t *testing.T) {
	target := NewLocalVariable(0, types.TypeInt)
	value := NewIntLiteral(42)
	ae := NewAssignmentExpression(target, value)
	if ae.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if ae.Precedence() != PrecAssignment {
		t.Error("Precedence: want PrecAssignment")
	}
	if ae.IsSimple() {
		t.Error("IsSimple: want false")
	}
	s := ae.String()
	if !strings.Contains(s, "=") {
		t.Errorf("String: want =, got %q", s)
	}
	ch := ae.Children()
	if len(ch) != 2 {
		t.Errorf("Children: want 2, got %d", len(ch))
	}
}

// ---- PreIncrement --------------------------------------------------------

func TestPreIncrement(t *testing.T) {
	target := NewLocalVariable(0, types.TypeInt)
	t.Run("increment", func(t *testing.T) {
		pi := NewPreIncrement(target, 1, types.TypeInt)
		s := pi.String()
		if !strings.HasPrefix(s, "++") {
			t.Errorf("String: want ++ prefix, got %q", s)
		}
		if pi.Precedence() != PrecUnary {
			t.Error("Precedence: want PrecUnary")
		}
		if pi.IsSimple() {
			t.Error("IsSimple: want false")
		}
		if len(pi.Children()) != 1 {
			t.Error("Children: want 1")
		}
	})
	t.Run("decrement", func(t *testing.T) {
		pi := NewPreIncrement(target, -1, types.TypeInt)
		s := pi.String()
		if !strings.HasPrefix(s, "--") {
			t.Errorf("String: want -- prefix, got %q", s)
		}
	})
}

// ---- InvokeKind ----------------------------------------------------------

func TestInvokeKindString(t *testing.T) {
	cases := []struct {
		k    InvokeKind
		want string
	}{
		{InvokeVirtual, "invokevirtual"},
		{InvokeSpecial, "invokespecial"},
		{InvokeStatic, "invokestatic"},
		{InvokeInterface, "invokeinterface"},
		{InvokeDynamic, "invokedynamic"},
		{InvokeKind(99), "InvokeKind(99)"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if tc.k.String() != tc.want {
				t.Errorf("got %q want %q", tc.k.String(), tc.want)
			}
		})
	}
}

// ---- MethodInvocation ----------------------------------------------------

func methodRef(className, methodName, descriptor string, ret types.JavaType) *MethodRef {
	return &MethodRef{
		ClassName:  className,
		MethodName: methodName,
		Descriptor: descriptor,
		ReturnType: ret,
	}
}

func TestMethodInvocationStatic(t *testing.T) {
	ref := methodRef("java.lang.Math", "abs", "(I)I", types.TypeInt)
	arg := NewIntLiteral(-5)
	m := NewStaticInvocation(ref, []Expression{arg})
	if m.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if m.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if m.IsSimple() {
		t.Error("IsSimple: want false")
	}
	if m.IsConstructor() {
		t.Error("IsConstructor: want false for abs")
	}
	s := m.String()
	if !strings.Contains(s, "abs") {
		t.Errorf("String: want abs, got %q", s)
	}
	ch := m.Children()
	if len(ch) != 1 {
		t.Errorf("Children: want 1 (arg), got %d", len(ch))
	}
}

func TestMethodInvocationVirtual(t *testing.T) {
	ref := methodRef("java.lang.String", "length", "()I", types.TypeInt)
	obj := NewLocalVariable(0, types.StringType)
	m := NewMethodInvocation(InvokeVirtual, obj, ref, nil)
	s := m.String()
	if !strings.Contains(s, "length") {
		t.Errorf("String: want length, got %q", s)
	}
	ch := m.Children()
	if len(ch) != 1 {
		t.Errorf("Children: want 1 (object only), got %d", len(ch))
	}
}

func TestMethodInvocationConstructor(t *testing.T) {
	ref := methodRef("com.example.Foo", "<init>", "()V", types.TypeVoid)
	t.Run("this-init", func(t *testing.T) {
		obj := NewNamedLocalVariable(0, "this", types.ObjectType)
		m := NewMethodInvocation(InvokeSpecial, obj, ref, nil)
		if !m.IsConstructor() {
			t.Error("IsConstructor: want true for <init>")
		}
		s := m.String()
		if !strings.Contains(s, "super") {
			t.Errorf("String: want super for this.<init>, got %q", s)
		}
	})
	t.Run("other-object-init", func(t *testing.T) {
		obj := NewNamedLocalVariable(0, "obj", types.ObjectType)
		m := NewMethodInvocation(InvokeSpecial, obj, ref, nil)
		s := m.String()
		if !strings.Contains(s, "<init>") {
			t.Errorf("String: want <init>, got %q", s)
		}
	})
	t.Run("no-object-init", func(t *testing.T) {
		m := NewMethodInvocation(InvokeSpecial, nil, ref, nil)
		s := m.String()
		if !strings.Contains(s, "new") {
			t.Errorf("String: want new, got %q", s)
		}
	})
}

func TestMethodInvocationSpecialNonInit(t *testing.T) {
	ref := methodRef("com.example.Base", "doSomething", "()V", types.TypeVoid)
	t.Run("with-object", func(t *testing.T) {
		obj := NewLocalVariable(0, types.ObjectType)
		m := NewMethodInvocation(InvokeSpecial, obj, ref, nil)
		s := m.String()
		if !strings.Contains(s, "doSomething") {
			t.Errorf("String: want doSomething, got %q", s)
		}
	})
	t.Run("no-object", func(t *testing.T) {
		m := NewMethodInvocation(InvokeSpecial, nil, ref, nil)
		s := m.String()
		if !strings.HasPrefix(s, "super") {
			t.Errorf("String: want super prefix, got %q", s)
		}
	})
}

func TestMethodInvocationMultipleArgs(t *testing.T) {
	ref := methodRef("java.lang.String", "valueOf", "(II)Ljava/lang/String;", types.StringType)
	args := []Expression{NewIntLiteral(1), NewIntLiteral(2)}
	m := NewStaticInvocation(ref, args)
	s := m.String()
	if !strings.Contains(s, ", ") {
		t.Errorf("String: want comma-separated args, got %q", s)
	}
}

// ---- DynamicInvocation ---------------------------------------------------

func TestDynamicInvocation(t *testing.T) {
	d := NewDynamicInvocation(0, "lambda$0", "()V", nil, types.TypeVoid)
	if d.Type() != types.TypeVoid {
		t.Error("Type: want TypeVoid")
	}
	if d.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if d.IsSimple() {
		t.Error("IsSimple: want false")
	}
	s := d.String()
	if !strings.HasPrefix(s, "invokedynamic:") {
		t.Errorf("String: want invokedynamic: prefix, got %q", s)
	}
	if len(d.Children()) != 0 {
		t.Errorf("Children: want 0 (no args), got %d", len(d.Children()))
	}

	// with args
	arg := NewIntLiteral(1)
	d2 := NewDynamicInvocation(1, "lambda$1", "(I)V", []Expression{arg}, types.TypeVoid)
	ch := d2.Children()
	if len(ch) != 1 {
		t.Errorf("Children: want 1, got %d", len(ch))
	}
	if !strings.Contains(d2.String(), "1") {
		t.Errorf("String: want arg 1, got %q", d2.String())
	}
}

// ---- ArrayAccess ---------------------------------------------------------

func TestArrayAccess(t *testing.T) {
	arr := NewLocalVariable(0, types.StringType)
	idx := NewIntLiteral(3)
	aa := NewArrayAccess(arr, idx, types.TypeInt)
	if aa.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if aa.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if aa.IsSimple() {
		t.Error("IsSimple: want false")
	}
	s := aa.String()
	if !strings.Contains(s, "[") {
		t.Errorf("String: want [, got %q", s)
	}
	lv := aa.LValueName()
	if !strings.Contains(lv, "[") {
		t.Errorf("LValueName: want [, got %q", lv)
	}
	ch := aa.Children()
	if len(ch) != 2 {
		t.Errorf("Children: want 2, got %d", len(ch))
	}
}

// ---- ArrayLength ---------------------------------------------------------

func TestArrayLength(t *testing.T) {
	arr := NewLocalVariable(0, types.StringType)
	al := NewArrayLength(arr)
	if al.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if al.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if al.IsSimple() {
		t.Error("IsSimple: want false")
	}
	if !strings.HasSuffix(al.String(), ".length") {
		t.Errorf("String: want .length suffix, got %q", al.String())
	}
	ch := al.Children()
	if len(ch) != 1 {
		t.Errorf("Children: want 1, got %d", len(ch))
	}
}

// ---- NewArray / NewObjectArray -------------------------------------------

func TestNewArray(t *testing.T) {
	size := NewIntLiteral(10)
	na := NewNewArray(types.TypeInt, size)
	s := na.String()
	if !strings.Contains(s, "new") || !strings.Contains(s, "[") {
		t.Errorf("String: want new T[n], got %q", s)
	}
	if na.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if na.IsSimple() {
		t.Error("IsSimple: want false")
	}
	ch := na.Children()
	if len(ch) != 1 || ch[0] != size {
		t.Error("Children: want [size]")
	}
	tp := na.Type()
	if tp == nil {
		t.Error("Type: want non-nil ArrayType")
	}
}

func TestNewObjectArray(t *testing.T) {
	size := NewIntLiteral(5)
	noa := NewNewObjectArray(types.StringType, size)
	s := noa.String()
	if !strings.Contains(s, "new") {
		t.Errorf("String: want new, got %q", s)
	}
	if noa.IsSimple() {
		t.Error("IsSimple: want false")
	}
}

// ---- MultiNewArray -------------------------------------------------------

func TestMultiNewArray(t *testing.T) {
	arrType := types.NewArrayType(2, types.TypeInt)
	d1 := NewIntLiteral(3)
	d2 := NewIntLiteral(4)
	mna := NewMultiNewArray(arrType, []Expression{d1, d2})
	if mna.Type() != arrType {
		t.Errorf("Type: got %v want %v", mna.Type(), arrType)
	}
	if mna.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if mna.IsSimple() {
		t.Error("IsSimple: want false")
	}
	ch := mna.Children()
	if len(ch) != 2 {
		t.Errorf("Children: want 2, got %d", len(ch))
	}
	s := mna.String()
	if !strings.Contains(s, "new") {
		t.Errorf("String: want new, got %q", s)
	}
}

func TestMultiNewArrayNonArrayType(t *testing.T) {
	// ElementType is not an *ArrayType — covers the else branch in String()
	d1 := NewIntLiteral(3)
	mna := NewMultiNewArray(types.TypeInt, []Expression{d1})
	s := mna.String()
	if !strings.Contains(s, "int") {
		t.Errorf("String: want int, got %q", s)
	}
}

// ---- FieldAccess ---------------------------------------------------------

func TestFieldAccess(t *testing.T) {
	obj := NewLocalVariable(0, types.ObjectType)
	field := &FieldRef{
		ClassName: "com.example.Foo",
		FieldName: "bar",
		FieldType: types.TypeInt,
	}
	fa := NewFieldAccess(obj, field)
	if fa.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if fa.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if fa.IsSimple() {
		t.Error("IsSimple: want false")
	}
	s := fa.String()
	if !strings.Contains(s, "bar") {
		t.Errorf("String: want bar, got %q", s)
	}
	if fa.LValueName() != "bar" {
		t.Errorf("LValueName: got %q want bar", fa.LValueName())
	}
	ch := fa.Children()
	if len(ch) != 1 {
		t.Errorf("Children: want 1, got %d", len(ch))
	}
}

// ---- StaticFieldAccess ---------------------------------------------------

func TestStaticFieldAccess(t *testing.T) {
	field := &FieldRef{
		ClassName: "java.lang.System",
		FieldName: "out",
		FieldType: types.ObjectType,
	}
	sfa := NewStaticFieldAccess(field)
	if sfa.Type() != types.ObjectType {
		t.Error("Type: want ObjectType")
	}
	if sfa.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if !sfa.IsSimple() {
		t.Error("IsSimple: want true for StaticFieldAccess")
	}
	if sfa.Children() != nil {
		t.Error("Children: want nil")
	}
	s := sfa.String()
	if !strings.Contains(s, "out") {
		t.Errorf("String: want out, got %q", s)
	}
	if sfa.LValueName() != "out" {
		t.Errorf("LValueName: got %q want out", sfa.LValueName())
	}
}

// ---- NewObject -----------------------------------------------------------

func TestNewObject(t *testing.T) {
	no := NewNewObject(types.StringType)
	if no.Type() != types.StringType {
		t.Error("Type: want StringType")
	}
	if no.Precedence() != PrecPostfix {
		t.Error("Precedence: want PrecPostfix")
	}
	if no.IsSimple() {
		t.Error("IsSimple: want false")
	}
	if no.Children() != nil {
		t.Error("Children: want nil")
	}
	s := no.String()
	if !strings.HasPrefix(s, "new ") {
		t.Errorf("String: want 'new ' prefix, got %q", s)
	}
}

// ---- TernaryExpression ---------------------------------------------------

func TestTernaryExpression(t *testing.T) {
	cond := NewBoolLiteral(true)
	tr := NewIntLiteral(1)
	fa := NewIntLiteral(0)
	te := NewTernaryExpression(cond, tr, fa, types.TypeInt)
	if te.Type() != types.TypeInt {
		t.Error("Type: want TypeInt")
	}
	if te.Precedence() != PrecTernary {
		t.Error("Precedence: want PrecTernary")
	}
	if te.IsSimple() {
		t.Error("IsSimple: want false")
	}
	ch := te.Children()
	if len(ch) != 3 {
		t.Errorf("Children: want 3, got %d", len(ch))
	}
	s := te.String()
	if !strings.Contains(s, "?") || !strings.Contains(s, ":") {
		t.Errorf("String: want ternary format, got %q", s)
	}
}

// ---- LambdaExpression ----------------------------------------------------

func TestLambdaExpression(t *testing.T) {
	t.Run("single param with body", func(t *testing.T) {
		param := NewNamedLocalVariable(0, "x", types.TypeInt)
		body := NewIntLiteral(42)
		le := NewLambdaExpression([]*LocalVariable{param}, body, types.ObjectType)
		if le.Type() != types.ObjectType {
			t.Error("Type: want ObjectType")
		}
		if le.Precedence() != PrecAssignment {
			t.Error("Precedence: want PrecAssignment")
		}
		if le.IsSimple() {
			t.Error("IsSimple: want false")
		}
		ch := le.Children()
		if len(ch) != 1 {
			t.Errorf("Children: want 1, got %d", len(ch))
		}
		s := le.String()
		if !strings.Contains(s, "->") {
			t.Errorf("String: want ->, got %q", s)
		}
		// single param: no parens
		if strings.HasPrefix(s, "(") {
			t.Errorf("single param lambda should not start with (, got %q", s)
		}
	})
	t.Run("multiple params", func(t *testing.T) {
		p1 := NewNamedLocalVariable(0, "a", types.TypeInt)
		p2 := NewNamedLocalVariable(1, "b", types.TypeInt)
		le := NewLambdaExpression([]*LocalVariable{p1, p2}, nil, types.ObjectType)
		s := le.String()
		if !strings.HasPrefix(s, "(") {
			t.Errorf("multi-param lambda should start with (, got %q", s)
		}
		// nil body
		ch := le.Children()
		if ch != nil {
			t.Errorf("nil body: Children should be nil, got %v", ch)
		}
		if !strings.Contains(s, "{ ... }") {
			t.Errorf("nil body: want { ... }, got %q", s)
		}
	})
	t.Run("zero params", func(t *testing.T) {
		le := NewLambdaExpression(nil, NewIntLiteral(0), types.ObjectType)
		s := le.String()
		if !strings.Contains(s, "->") {
			t.Errorf("String: want ->, got %q", s)
		}
	})
}

// ---- MethodReferenceExpression -------------------------------------------

func TestMethodReference(t *testing.T) {
	t.Run("instance ref", func(t *testing.T) {
		obj := NewLocalVariable(0, types.StringType)
		mr := NewMethodReference(obj, "length", types.ObjectType)
		if mr.Type() != types.ObjectType {
			t.Error("Type: want ObjectType")
		}
		if mr.Precedence() != PrecPostfix {
			t.Error("Precedence: want PrecPostfix")
		}
		if !mr.IsSimple() {
			t.Error("IsSimple: want true")
		}
		ch := mr.Children()
		if len(ch) != 1 {
			t.Errorf("Children: want 1, got %d", len(ch))
		}
		s := mr.String()
		if !strings.Contains(s, "::") {
			t.Errorf("String: want ::, got %q", s)
		}
	})
	t.Run("static ref", func(t *testing.T) {
		mr := NewStaticMethodReference("java.lang.String", "valueOf", types.ObjectType)
		if mr.Object != nil {
			t.Error("Object: want nil for static ref")
		}
		if mr.Children() != nil {
			t.Error("Children: want nil for static ref")
		}
		s := mr.String()
		if !strings.Contains(s, "::") {
			t.Errorf("String: want ::, got %q", s)
		}
	})
	t.Run("constructor ref", func(t *testing.T) {
		mr := NewConstructorReference("com.example.Foo", types.ObjectType)
		if mr.MethodName != "new" {
			t.Errorf("MethodName: got %q want new", mr.MethodName)
		}
		s := mr.String()
		if !strings.Contains(s, "new") {
			t.Errorf("String: want new, got %q", s)
		}
	})
}
