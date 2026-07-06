package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// CastExpression represents a type cast: (Type)expr.
type CastExpression struct {
	Operand    Expression
	TargetType types.JavaType
	Forced     bool // explicit cast in bytecode vs. inferred
}

func NewCastExpression(operand Expression, targetType types.JavaType) *CastExpression {
	return &CastExpression{Operand: operand, TargetType: targetType, Forced: true}
}

func (c *CastExpression) Type() types.JavaType   { return c.TargetType }
func (c *CastExpression) Precedence() Precedence { return PrecUnary }
func (c *CastExpression) IsSimple() bool         { return false }
func (c *CastExpression) Children() []Expression { return []Expression{c.Operand} }

func (c *CastExpression) String() string {
	return fmt.Sprintf("(%s)%s", c.TargetType.Name(), c.Operand)
}

// InstanceOfExpression represents: expr instanceof Type.
type InstanceOfExpression struct {
	Operand   Expression
	CheckType types.JavaType
}

func NewInstanceOfExpression(operand Expression, checkType types.JavaType) *InstanceOfExpression {
	return &InstanceOfExpression{Operand: operand, CheckType: checkType}
}

func (i *InstanceOfExpression) Type() types.JavaType   { return types.TypeBoolean }
func (i *InstanceOfExpression) Precedence() Precedence { return PrecRelational }
func (i *InstanceOfExpression) IsSimple() bool         { return false }
func (i *InstanceOfExpression) Children() []Expression { return []Expression{i.Operand} }

func (i *InstanceOfExpression) String() string {
	return fmt.Sprintf("%s instanceof %s", i.Operand, i.CheckType.Name())
}
