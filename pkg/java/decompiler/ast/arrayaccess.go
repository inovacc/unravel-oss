package ast

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ArrayAccess represents array element access: arr[index].
type ArrayAccess struct {
	Array Expression
	Index Expression
	JType types.JavaType
}

func NewArrayAccess(array, index Expression, elemType types.JavaType) *ArrayAccess {
	return &ArrayAccess{Array: array, Index: index, JType: elemType}
}

func (a *ArrayAccess) Type() types.JavaType   { return a.JType }
func (a *ArrayAccess) Precedence() Precedence { return PrecPostfix }
func (a *ArrayAccess) IsSimple() bool         { return false }
func (a *ArrayAccess) Children() []Expression { return []Expression{a.Array, a.Index} }
func (a *ArrayAccess) LValueName() string     { return fmt.Sprintf("%s[%s]", a.Array, a.Index) }

func (a *ArrayAccess) String() string {
	return fmt.Sprintf("%s[%s]", a.Array, a.Index)
}

// ArrayLength represents arr.length.
type ArrayLength struct {
	Array Expression
}

func NewArrayLength(array Expression) *ArrayLength {
	return &ArrayLength{Array: array}
}

func (al *ArrayLength) Type() types.JavaType   { return types.TypeInt }
func (al *ArrayLength) Precedence() Precedence { return PrecPostfix }
func (al *ArrayLength) IsSimple() bool         { return false }
func (al *ArrayLength) Children() []Expression { return []Expression{al.Array} }

func (al *ArrayLength) String() string {
	return fmt.Sprintf("%s.length", al.Array)
}

// NewArray represents new T[size] for primitive arrays.
type NewArray struct {
	ElementType types.JavaType
	Size        Expression
}

func NewNewArray(elemType types.JavaType, size Expression) *NewArray {
	return &NewArray{ElementType: elemType, Size: size}
}

func (na *NewArray) Type() types.JavaType {
	return types.NewArrayType(1, na.ElementType)
}
func (na *NewArray) Precedence() Precedence { return PrecPostfix }
func (na *NewArray) IsSimple() bool         { return false }
func (na *NewArray) Children() []Expression { return []Expression{na.Size} }

func (na *NewArray) String() string {
	return fmt.Sprintf("new %s[%s]", na.ElementType.Name(), na.Size)
}

// NewObjectArray represents new ClassName[size] for reference type arrays.
type NewObjectArray struct {
	ElementType types.JavaType
	Size        Expression
}

func NewNewObjectArray(elemType types.JavaType, size Expression) *NewObjectArray {
	return &NewObjectArray{ElementType: elemType, Size: size}
}

func (noa *NewObjectArray) Type() types.JavaType {
	return types.NewArrayType(1, noa.ElementType)
}
func (noa *NewObjectArray) Precedence() Precedence { return PrecPostfix }
func (noa *NewObjectArray) IsSimple() bool         { return false }
func (noa *NewObjectArray) Children() []Expression { return []Expression{noa.Size} }

func (noa *NewObjectArray) String() string {
	return fmt.Sprintf("new %s[%s]", noa.ElementType.Name(), noa.Size)
}

// MultiNewArray represents multidimensional array creation:
// new Type[d1][d2]...
type MultiNewArray struct {
	ArrayType  types.JavaType
	Dimensions []Expression
}

func NewMultiNewArray(arrayType types.JavaType, dimensions []Expression) *MultiNewArray {
	return &MultiNewArray{ArrayType: arrayType, Dimensions: dimensions}
}

func (m *MultiNewArray) Type() types.JavaType   { return m.ArrayType }
func (m *MultiNewArray) Precedence() Precedence { return PrecPostfix }
func (m *MultiNewArray) IsSimple() bool         { return false }
func (m *MultiNewArray) Children() []Expression { return m.Dimensions }

func (m *MultiNewArray) String() string {
	var b strings.Builder
	// Get element type name from ArrayType
	elemType := m.ArrayType
	if at, ok := elemType.(*types.ArrayType); ok {
		elemType = at.UnderlyingType
	}

	b.WriteString("new ")
	b.WriteString(elemType.Name())

	for _, d := range m.Dimensions {
		_, _ = fmt.Fprintf(&b, "[%s]", d)
	}

	return b.String()
}
