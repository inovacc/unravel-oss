package ast

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// Precedence controls parenthesization when rendering expressions.
type Precedence int

const (
	PrecHighest        Precedence = iota // Literals, variables
	PrecPostfix                          // a++, a--, a.b, a[i], f()
	PrecUnary                            // -a, ~a, !a, (T)a
	PrecMultiplicative                   // *, /, %
	PrecAdditive                         // +, -
	PrecShift                            // <<, >>, >>>
	PrecRelational                       // <, <=, >, >=, instanceof
	PrecEquality                         // ==, !=
	PrecBitwiseAnd                       // &
	PrecBitwiseXor                       // ^
	PrecBitwiseOr                        // |
	PrecLogicalAnd                       // &&
	PrecLogicalOr                        // ||
	PrecTernary                          // ?:
	PrecAssignment                       // =, +=, -=, ...
	PrecLowest                           // comma
)

// Expression represents a Java expression in the decompiled AST.
type Expression interface {
	// Type returns the inferred Java type of this expression.
	Type() types.JavaType

	// Precedence returns the operator precedence for parenthesization.
	Precedence() Precedence

	// IsSimple returns true for simple expressions (literals, variables)
	// that don't need parentheses and have no side effects.
	IsSimple() bool

	// Children returns sub-expressions (for tree traversal).
	Children() []Expression

	// String returns a human-readable representation.
	String() string
}

// LValue represents an assignable location (left-hand side of assignment).
type LValue interface {
	Expression

	// LValueName returns the name of this l-value for debugging.
	LValueName() string
}

// InferredType wraps a JavaType with inference metadata.
type InferredType struct {
	JType  types.JavaType
	Source TypeSource
}

// TypeSource indicates where a type inference came from.
type TypeSource int

const (
	TypeFromBytecode   TypeSource = iota // Directly from bytecode instruction
	TypeFromOperation                    // Inferred from operation context
	TypeFromExpression                   // Inferred from sub-expression
	TypeFromLiteral                      // From literal value
	TypeFromField                        // From field declaration
	TypeFromMethod                       // From method signature
)

// NewInferredType creates a new InferredType.
func NewInferredType(jtype types.JavaType, source TypeSource) *InferredType {
	return &InferredType{JType: jtype, Source: source}
}
