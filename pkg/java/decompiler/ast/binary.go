package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ArithOp represents an arithmetic or bitwise operation.
type ArithOp int

const (
	OpAdd   ArithOp = iota // +
	OpSub                  // -
	OpMul                  // *
	OpDiv                  // /
	OpRem                  // %
	OpAnd                  // &
	OpOr                   // |
	OpXor                  // ^
	OpShl                  // <<
	OpShr                  // >>
	OpUShr                 // >>>
	OpLCmp                 // lcmp
	OpFCmpL                // fcmpl
	OpFCmpG                // fcmpg
	OpDCmpL                // dcmpl
	OpDCmpG                // dcmpg
)

var arithOpSymbol = [...]string{
	OpAdd: "+", OpSub: "-", OpMul: "*", OpDiv: "/", OpRem: "%",
	OpAnd: "&", OpOr: "|", OpXor: "^",
	OpShl: "<<", OpShr: ">>", OpUShr: ">>>",
	OpLCmp: "lcmp", OpFCmpL: "fcmpl", OpFCmpG: "fcmpg",
	OpDCmpL: "dcmpl", OpDCmpG: "dcmpg",
}

func (op ArithOp) String() string {
	if int(op) < len(arithOpSymbol) {
		return arithOpSymbol[op]
	}

	return fmt.Sprintf("ArithOp(%d)", int(op))
}

// Precedence returns the operator precedence for this arithmetic operation.
func (op ArithOp) Precedence() Precedence {
	switch op {
	case OpMul, OpDiv, OpRem:
		return PrecMultiplicative
	case OpAdd, OpSub:
		return PrecAdditive
	case OpShl, OpShr, OpUShr:
		return PrecShift
	case OpAnd:
		return PrecBitwiseAnd
	case OpXor:
		return PrecBitwiseXor
	case OpOr:
		return PrecBitwiseOr
	default:
		return PrecHighest
	}
}

// IsCmp returns true if this is a comparison operation (lcmp, fcmpX, dcmpX).
func (op ArithOp) IsCmp() bool {
	return op >= OpLCmp && op <= OpDCmpG
}

// ArithmeticOperation represents a binary arithmetic or bitwise expression.
type ArithmeticOperation struct {
	LHS   Expression
	RHS   Expression
	Op    ArithOp
	JType types.JavaType
}

func NewArithmeticOperation(op ArithOp, lhs, rhs Expression, jtype types.JavaType) *ArithmeticOperation {
	return &ArithmeticOperation{LHS: lhs, RHS: rhs, Op: op, JType: jtype}
}

func (a *ArithmeticOperation) Type() types.JavaType   { return a.JType }
func (a *ArithmeticOperation) Precedence() Precedence { return a.Op.Precedence() }
func (a *ArithmeticOperation) IsSimple() bool         { return false }
func (a *ArithmeticOperation) Children() []Expression { return []Expression{a.LHS, a.RHS} }

func (a *ArithmeticOperation) String() string {
	return fmt.Sprintf("(%s %s %s)", a.LHS, a.Op, a.RHS)
}

// CompOp represents a comparison operator.
type CompOp int

const (
	CmpEq CompOp = iota // ==
	CmpNe               // !=
	CmpLt               // <
	CmpLe               // <=
	CmpGt               // >
	CmpGe               // >=
)

var compOpSymbol = [...]string{
	CmpEq: "==", CmpNe: "!=", CmpLt: "<", CmpLe: "<=", CmpGt: ">", CmpGe: ">=",
}

func (op CompOp) String() string {
	if int(op) < len(compOpSymbol) {
		return compOpSymbol[op]
	}

	return fmt.Sprintf("CompOp(%d)", int(op))
}

// Negate returns the logical negation of this comparison.
func (op CompOp) Negate() CompOp {
	switch op {
	case CmpEq:
		return CmpNe
	case CmpNe:
		return CmpEq
	case CmpLt:
		return CmpGe
	case CmpLe:
		return CmpGt
	case CmpGt:
		return CmpLe
	case CmpGe:
		return CmpLt
	default:
		return op
	}
}

// ComparisonOperation represents a binary comparison expression.
type ComparisonOperation struct {
	LHS Expression
	RHS Expression
	Op  CompOp
}

func NewComparisonOperation(op CompOp, lhs, rhs Expression) *ComparisonOperation {
	return &ComparisonOperation{LHS: lhs, RHS: rhs, Op: op}
}

func (c *ComparisonOperation) Type() types.JavaType { return types.TypeBoolean }
func (c *ComparisonOperation) Precedence() Precedence {
	if c.Op == CmpEq || c.Op == CmpNe {
		return PrecEquality
	}

	return PrecRelational
}
func (c *ComparisonOperation) IsSimple() bool         { return false }
func (c *ComparisonOperation) Children() []Expression { return []Expression{c.LHS, c.RHS} }

func (c *ComparisonOperation) String() string {
	return fmt.Sprintf("(%s %s %s)", c.LHS, c.Op, c.RHS)
}

// Negate returns a new ComparisonOperation with the negated operator.
func (c *ComparisonOperation) Negate() *ComparisonOperation {
	return NewComparisonOperation(c.Op.Negate(), c.LHS, c.RHS)
}

// BoolOp represents a boolean logical operator.
type BoolOp int

const (
	BoolAnd BoolOp = iota // &&
	BoolOr                // ||
)

func (op BoolOp) String() string {
	if op == BoolAnd {
		return "&&"
	}

	return "||"
}

// BooleanOperation represents a logical AND/OR expression.
type BooleanOperation struct {
	LHS Expression // must be a conditional expression
	RHS Expression // must be a conditional expression
	Op  BoolOp
}

func NewBooleanOperation(op BoolOp, lhs, rhs Expression) *BooleanOperation {
	return &BooleanOperation{LHS: lhs, RHS: rhs, Op: op}
}

func (b *BooleanOperation) Type() types.JavaType { return types.TypeBoolean }
func (b *BooleanOperation) Precedence() Precedence {
	if b.Op == BoolAnd {
		return PrecLogicalAnd
	}

	return PrecLogicalOr
}
func (b *BooleanOperation) IsSimple() bool         { return false }
func (b *BooleanOperation) Children() []Expression { return []Expression{b.LHS, b.RHS} }

func (b *BooleanOperation) String() string {
	return fmt.Sprintf("(%s %s %s)", b.LHS, b.Op, b.RHS)
}

// NegationExpression represents boolean/bitwise NOT.
type NegationExpression struct {
	Operand Expression
	JType   types.JavaType
}

func NewNegationExpression(operand Expression) *NegationExpression {
	jtype := operand.Type()
	if jtype == types.TypeBoolean {
		return &NegationExpression{Operand: operand, JType: types.TypeBoolean}
	}

	return &NegationExpression{Operand: operand, JType: jtype}
}

func (n *NegationExpression) Type() types.JavaType   { return n.JType }
func (n *NegationExpression) Precedence() Precedence { return PrecUnary }
func (n *NegationExpression) IsSimple() bool         { return false }
func (n *NegationExpression) Children() []Expression { return []Expression{n.Operand} }

func (n *NegationExpression) String() string {
	if n.JType == types.TypeBoolean {
		return fmt.Sprintf("!%s", n.Operand)
	}

	return fmt.Sprintf("~%s", n.Operand)
}

// ArithmeticNegation represents unary arithmetic negation (-x).
type ArithmeticNegation struct {
	Operand Expression
	JType   types.JavaType
}

func NewArithmeticNegation(operand Expression, jtype types.JavaType) *ArithmeticNegation {
	return &ArithmeticNegation{Operand: operand, JType: jtype}
}

func (an *ArithmeticNegation) Type() types.JavaType   { return an.JType }
func (an *ArithmeticNegation) Precedence() Precedence { return PrecUnary }
func (an *ArithmeticNegation) IsSimple() bool         { return false }
func (an *ArithmeticNegation) Children() []Expression { return []Expression{an.Operand} }

func (an *ArithmeticNegation) String() string {
	return fmt.Sprintf("-%s", an.Operand)
}
