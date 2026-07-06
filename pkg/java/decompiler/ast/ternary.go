package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// TernaryExpression represents: condition ? trueExpr : falseExpr.
type TernaryExpression struct {
	Condition Expression
	TrueExpr  Expression
	FalseExpr Expression
	JType     types.JavaType
}

func NewTernaryExpression(condition, trueExpr, falseExpr Expression, jtype types.JavaType) *TernaryExpression {
	return &TernaryExpression{
		Condition: condition,
		TrueExpr:  trueExpr,
		FalseExpr: falseExpr,
		JType:     jtype,
	}
}

func (t *TernaryExpression) Type() types.JavaType   { return t.JType }
func (t *TernaryExpression) Precedence() Precedence { return PrecTernary }
func (t *TernaryExpression) IsSimple() bool         { return false }
func (t *TernaryExpression) Children() []Expression {
	return []Expression{t.Condition, t.TrueExpr, t.FalseExpr}
}

func (t *TernaryExpression) String() string {
	return fmt.Sprintf("(%s ? %s : %s)", t.Condition, t.TrueExpr, t.FalseExpr)
}
