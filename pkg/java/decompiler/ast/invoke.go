package ast

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// InvokeKind indicates the type of method invocation.
type InvokeKind int

const (
	InvokeVirtual   InvokeKind = iota // invokevirtual
	InvokeSpecial                     // invokespecial (constructors, super, private)
	InvokeStatic                      // invokestatic
	InvokeInterface                   // invokeinterface
	InvokeDynamic                     // invokedynamic
)

func (k InvokeKind) String() string {
	switch k {
	case InvokeVirtual:
		return "invokevirtual"
	case InvokeSpecial:
		return "invokespecial"
	case InvokeStatic:
		return "invokestatic"
	case InvokeInterface:
		return "invokeinterface"
	case InvokeDynamic:
		return "invokedynamic"
	default:
		return fmt.Sprintf("InvokeKind(%d)", int(k))
	}
}

// MethodRef describes a method reference from the constant pool.
type MethodRef struct {
	ClassName  string
	MethodName string
	Descriptor string
	ParamTypes []types.JavaType
	ReturnType types.JavaType
}

// MethodInvocation represents a method call expression.
type MethodInvocation struct {
	Kind   InvokeKind
	Object Expression // nil for static/dynamic
	Method *MethodRef
	Args   []Expression
	JType  types.JavaType
}

func NewMethodInvocation(kind InvokeKind, object Expression, method *MethodRef, args []Expression) *MethodInvocation {
	return &MethodInvocation{
		Kind:   kind,
		Object: object,
		Method: method,
		Args:   args,
		JType:  method.ReturnType,
	}
}

func NewStaticInvocation(method *MethodRef, args []Expression) *MethodInvocation {
	return NewMethodInvocation(InvokeStatic, nil, method, args)
}

func (m *MethodInvocation) Type() types.JavaType   { return m.JType }
func (m *MethodInvocation) Precedence() Precedence { return PrecPostfix }
func (m *MethodInvocation) IsSimple() bool         { return false }

func (m *MethodInvocation) Children() []Expression {
	children := make([]Expression, 0, 1+len(m.Args))
	if m.Object != nil {
		children = append(children, m.Object)
	}

	children = append(children, m.Args...)

	return children
}

func (m *MethodInvocation) IsConstructor() bool {
	return m.Method.MethodName == "<init>"
}

func (m *MethodInvocation) String() string {
	var b strings.Builder

	switch m.Kind {
	case InvokeStatic:
		b.WriteString(types.SimplifyJavaLang(m.Method.ClassName))
		b.WriteByte('.')
		b.WriteString(m.Method.MethodName)
	case InvokeSpecial:
		if m.IsConstructor() {
			if m.Object != nil {
				// this.<init>() = super() or this() constructor delegation
				objStr := m.Object.String()
				if objStr == "this" {
					b.WriteString("super")
				} else {
					b.WriteString(objStr)
					b.WriteString(".<init>")
				}
			} else {
				b.WriteString("new ")
				b.WriteString(types.SimplifyJavaLang(m.Method.ClassName))
			}
		} else {
			if m.Object != nil {
				b.WriteString(m.Object.String())
			} else {
				b.WriteString("super")
			}

			b.WriteByte('.')
			b.WriteString(m.Method.MethodName)
		}
	default:
		if m.Object != nil {
			b.WriteString(m.Object.String())
			b.WriteByte('.')
		}

		b.WriteString(m.Method.MethodName)
	}

	b.WriteByte('(')

	for i, arg := range m.Args {
		if i > 0 {
			b.WriteString(", ")
		}

		b.WriteString(arg.String())
	}

	b.WriteByte(')')

	return b.String()
}

// DynamicInvocation represents an invokedynamic call.
type DynamicInvocation struct {
	BootstrapIdx int
	Name         string
	Descriptor   string
	Args         []Expression
	JType        types.JavaType
}

func NewDynamicInvocation(bootstrapIdx int, name, descriptor string, args []Expression, jtype types.JavaType) *DynamicInvocation {
	return &DynamicInvocation{
		BootstrapIdx: bootstrapIdx,
		Name:         name,
		Descriptor:   descriptor,
		Args:         args,
		JType:        jtype,
	}
}

func (d *DynamicInvocation) Type() types.JavaType   { return d.JType }
func (d *DynamicInvocation) Precedence() Precedence { return PrecPostfix }
func (d *DynamicInvocation) IsSimple() bool         { return false }

func (d *DynamicInvocation) Children() []Expression {
	children := make([]Expression, len(d.Args))
	copy(children, d.Args)

	return children
}

func (d *DynamicInvocation) String() string {
	var b strings.Builder
	b.WriteString("invokedynamic:")
	b.WriteString(d.Name)
	b.WriteByte('(')

	for i, arg := range d.Args {
		if i > 0 {
			b.WriteString(", ")
		}

		b.WriteString(arg.String())
	}

	b.WriteByte(')')

	return b.String()
}
