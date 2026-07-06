package ast

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// LambdaExpression represents a Java lambda: (params) -> body
type LambdaExpression struct {
	Parameters []*LocalVariable // lambda parameters
	Body       Expression       // single-expression body (nil if block body)
	JType      types.JavaType   // functional interface type
}

func NewLambdaExpression(params []*LocalVariable, body Expression, jtype types.JavaType) *LambdaExpression {
	return &LambdaExpression{Parameters: params, Body: body, JType: jtype}
}

func (l *LambdaExpression) Type() types.JavaType   { return l.JType }
func (l *LambdaExpression) Precedence() Precedence { return PrecAssignment }
func (l *LambdaExpression) IsSimple() bool         { return false }

func (l *LambdaExpression) Children() []Expression {
	if l.Body != nil {
		return []Expression{l.Body}
	}

	return nil
}

func (l *LambdaExpression) String() string {
	var b strings.Builder
	if len(l.Parameters) == 1 {
		b.WriteString(l.Parameters[0].Name)
	} else {
		b.WriteByte('(')

		for i, p := range l.Parameters {
			if i > 0 {
				b.WriteString(", ")
			}

			b.WriteString(p.Name)
		}

		b.WriteByte(')')
	}

	b.WriteString(" -> ")

	if l.Body != nil {
		b.WriteString(l.Body.String())
	} else {
		b.WriteString("{ ... }")
	}

	return b.String()
}

// MethodReferenceExpression represents: Object::methodName or ClassName::methodName
type MethodReferenceExpression struct {
	Object     Expression     // nil for static (use ClassName instead)
	ClassName  string         // for static method refs or constructor refs
	MethodName string         // method name, or "new" for constructor ref
	JType      types.JavaType // functional interface type
}

func NewMethodReference(object Expression, methodName string, jtype types.JavaType) *MethodReferenceExpression {
	return &MethodReferenceExpression{Object: object, MethodName: methodName, JType: jtype}
}

func NewStaticMethodReference(className, methodName string, jtype types.JavaType) *MethodReferenceExpression {
	return &MethodReferenceExpression{ClassName: className, MethodName: methodName, JType: jtype}
}

func NewConstructorReference(className string, jtype types.JavaType) *MethodReferenceExpression {
	return &MethodReferenceExpression{ClassName: className, MethodName: "new", JType: jtype}
}

func (m *MethodReferenceExpression) Type() types.JavaType   { return m.JType }
func (m *MethodReferenceExpression) Precedence() Precedence { return PrecPostfix }
func (m *MethodReferenceExpression) IsSimple() bool         { return true }

func (m *MethodReferenceExpression) Children() []Expression {
	if m.Object != nil {
		return []Expression{m.Object}
	}

	return nil
}

func (m *MethodReferenceExpression) String() string {
	if m.Object != nil {
		return fmt.Sprintf("%s::%s", m.Object, m.MethodName)
	}

	return fmt.Sprintf("%s::%s", m.ClassName, m.MethodName)
}
