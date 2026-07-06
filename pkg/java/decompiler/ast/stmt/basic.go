package stmt

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
)

// Nop represents a no-operation statement.
type Nop struct{}

func NewNop() *Nop                           { return &Nop{} }
func (n *Nop) Kind() StmtKind                { return KindNop }
func (n *Nop) Children() []Statement         { return nil }
func (n *Nop) Expressions() []ast.Expression { return nil }
func (n *Nop) String() string                { return "nop" }

// AssignmentStatement represents: lvalue = rvalue;
type AssignmentStatement struct {
	Target ast.LValue
	Value  ast.Expression
}

func NewAssignment(target ast.LValue, value ast.Expression) *AssignmentStatement {
	return &AssignmentStatement{Target: target, Value: value}
}

func (a *AssignmentStatement) Kind() StmtKind        { return KindAssignment }
func (a *AssignmentStatement) Children() []Statement { return nil }
func (a *AssignmentStatement) Expressions() []ast.Expression {
	return []ast.Expression{a.Target, a.Value}
}

func (a *AssignmentStatement) String() string {
	return fmt.Sprintf("%s = %s;", a.Target, a.Value)
}

// ExpressionStatement wraps a standalone expression (method call, assignment).
type ExpressionStatement struct {
	Expr ast.Expression
}

func NewExpressionStatement(expr ast.Expression) *ExpressionStatement {
	return &ExpressionStatement{Expr: expr}
}

func (e *ExpressionStatement) Kind() StmtKind        { return KindExpression }
func (e *ExpressionStatement) Children() []Statement { return nil }
func (e *ExpressionStatement) Expressions() []ast.Expression {
	return []ast.Expression{e.Expr}
}

func (e *ExpressionStatement) String() string {
	return fmt.Sprintf("%s;", e.Expr)
}

// ReturnStatement represents: return expr;
type ReturnStatement struct {
	Value ast.Expression
}

func NewReturn(value ast.Expression) *ReturnStatement {
	return &ReturnStatement{Value: value}
}

func (r *ReturnStatement) Kind() StmtKind        { return KindReturn }
func (r *ReturnStatement) Children() []Statement { return nil }
func (r *ReturnStatement) Expressions() []ast.Expression {
	return []ast.Expression{r.Value}
}

func (r *ReturnStatement) String() string {
	return fmt.Sprintf("return %s;", r.Value)
}

// ReturnVoidStatement represents: return;
type ReturnVoidStatement struct{}

func NewReturnVoid() *ReturnVoidStatement                    { return &ReturnVoidStatement{} }
func (r *ReturnVoidStatement) Kind() StmtKind                { return KindReturnVoid }
func (r *ReturnVoidStatement) Children() []Statement         { return nil }
func (r *ReturnVoidStatement) Expressions() []ast.Expression { return nil }
func (r *ReturnVoidStatement) String() string                { return "return;" }

// ThrowStatement represents: throw expr;
type ThrowStatement struct {
	Value ast.Expression
}

func NewThrow(value ast.Expression) *ThrowStatement {
	return &ThrowStatement{Value: value}
}

func (t *ThrowStatement) Kind() StmtKind        { return KindThrow }
func (t *ThrowStatement) Children() []Statement { return nil }
func (t *ThrowStatement) Expressions() []ast.Expression {
	return []ast.Expression{t.Value}
}

func (t *ThrowStatement) String() string {
	return fmt.Sprintf("throw %s;", t.Value)
}
