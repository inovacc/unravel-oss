package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// AssignmentExpression represents: lvalue = rvalue.
type AssignmentExpression struct {
	Target LValue
	Value  Expression
}

func NewAssignmentExpression(target LValue, value Expression) *AssignmentExpression {
	return &AssignmentExpression{Target: target, Value: value}
}

func (a *AssignmentExpression) Type() types.JavaType   { return a.Target.Type() }
func (a *AssignmentExpression) Precedence() Precedence { return PrecAssignment }
func (a *AssignmentExpression) IsSimple() bool         { return false }
func (a *AssignmentExpression) Children() []Expression { return []Expression{a.Target, a.Value} }

func (a *AssignmentExpression) String() string {
	return fmt.Sprintf("%s = %s", a.Target, a.Value)
}

// PreIncrement represents ++var / --var.
type PreIncrement struct {
	Target    LValue
	Increment int // +1 or -1
	JType     types.JavaType
}

func NewPreIncrement(target LValue, increment int, jtype types.JavaType) *PreIncrement {
	return &PreIncrement{Target: target, Increment: increment, JType: jtype}
}

func (p *PreIncrement) Type() types.JavaType   { return p.JType }
func (p *PreIncrement) Precedence() Precedence { return PrecUnary }
func (p *PreIncrement) IsSimple() bool         { return false }
func (p *PreIncrement) Children() []Expression { return []Expression{p.Target} }

func (p *PreIncrement) String() string {
	if p.Increment > 0 {
		return fmt.Sprintf("++%s", p.Target)
	}

	return fmt.Sprintf("--%s", p.Target)
}
