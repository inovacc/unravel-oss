package types

import (
	"fmt"
	"strings"
)

// GenericType represents a parameterized type like List<String> or Map<String, Integer>.
type GenericType struct {
	Base       JavaType   // The raw class type (e.g. java.util.List)
	TypeParams []JavaType // The type arguments (e.g. [String])
}

// NewGenericType creates a parameterized type.
func NewGenericType(base JavaType, typeParams ...JavaType) *GenericType {
	return &GenericType{Base: base, TypeParams: typeParams}
}

func (gt *GenericType) Name() string {
	var b strings.Builder
	b.WriteString(gt.Base.Name())
	b.WriteByte('<')

	for i, tp := range gt.TypeParams {
		if i > 0 {
			b.WriteString(", ")
		}

		b.WriteString(tp.Name())
	}

	b.WriteByte('>')

	return b.String()
}

func (gt *GenericType) RawName() string         { return gt.Base.RawName() }
func (gt *GenericType) Descriptor() string      { return gt.Base.Descriptor() }
func (gt *GenericType) IsObject() bool          { return true }
func (gt *GenericType) IsPrimitive() bool       { return false }
func (gt *GenericType) IsArray() bool           { return false }
func (gt *GenericType) ArrayDimensions() int    { return 0 }
func (gt *GenericType) ElementType() JavaType   { return gt }
func (gt *GenericType) ComponentType() JavaType { return nil }
func (gt *GenericType) StackCategory() int      { return 1 }
func (gt *GenericType) String() string          { return gt.Name() }

// WildcardKind represents the bound direction of a wildcard type.
type WildcardKind int

const (
	WildcardNone    WildcardKind = iota // ? (unbounded)
	WildcardExtends                     // ? extends T
	WildcardSuper                       // ? super T
)

func (wk WildcardKind) String() string {
	switch wk {
	case WildcardNone:
		return ""
	case WildcardExtends:
		return "extends"
	case WildcardSuper:
		return "super"
	default:
		return fmt.Sprintf("WildcardKind(%d)", wk)
	}
}

// WildcardType represents a wildcard type argument (?, ? extends T, ? super T).
type WildcardType struct {
	Kind  WildcardKind
	Bound JavaType // nil for unbounded wildcard
}

func NewWildcard() *WildcardType {
	return &WildcardType{Kind: WildcardNone}
}

func NewWildcardExtends(bound JavaType) *WildcardType {
	return &WildcardType{Kind: WildcardExtends, Bound: bound}
}

func NewWildcardSuper(bound JavaType) *WildcardType {
	return &WildcardType{Kind: WildcardSuper, Bound: bound}
}

func (wt *WildcardType) Name() string {
	switch wt.Kind {
	case WildcardExtends:
		return "? extends " + wt.Bound.Name()
	case WildcardSuper:
		return "? super " + wt.Bound.Name()
	default:
		return "?"
	}
}

func (wt *WildcardType) RawName() string         { return "?" }
func (wt *WildcardType) Descriptor() string      { return "" }
func (wt *WildcardType) IsObject() bool          { return true }
func (wt *WildcardType) IsPrimitive() bool       { return false }
func (wt *WildcardType) IsArray() bool           { return false }
func (wt *WildcardType) ArrayDimensions() int    { return 0 }
func (wt *WildcardType) ElementType() JavaType   { return wt }
func (wt *WildcardType) ComponentType() JavaType { return nil }
func (wt *WildcardType) StackCategory() int      { return 1 }
func (wt *WildcardType) String() string          { return wt.Name() }

// TypeVariable represents a formal type parameter (e.g. T, K, V).
type TypeVariable struct {
	VarName string
}

func NewTypeVariable(name string) *TypeVariable {
	return &TypeVariable{VarName: name}
}

func (tv *TypeVariable) Name() string            { return tv.VarName }
func (tv *TypeVariable) RawName() string         { return tv.VarName }
func (tv *TypeVariable) Descriptor() string      { return "" }
func (tv *TypeVariable) IsObject() bool          { return true }
func (tv *TypeVariable) IsPrimitive() bool       { return false }
func (tv *TypeVariable) IsArray() bool           { return false }
func (tv *TypeVariable) ArrayDimensions() int    { return 0 }
func (tv *TypeVariable) ElementType() JavaType   { return tv }
func (tv *TypeVariable) ComponentType() JavaType { return nil }
func (tv *TypeVariable) StackCategory() int      { return 1 }
func (tv *TypeVariable) String() string          { return tv.VarName }

// IntersectionType represents the intersection of multiple types
// (used in generic bounds like <T extends A & B & C>).
type IntersectionType struct {
	Types []JavaType
}

func NewIntersectionType(types ...JavaType) *IntersectionType {
	return &IntersectionType{Types: types}
}

func (it *IntersectionType) Name() string {
	var b strings.Builder

	for i, t := range it.Types {
		if i > 0 {
			b.WriteString(" & ")
		}

		b.WriteString(t.Name())
	}

	return b.String()
}

func (it *IntersectionType) RawName() string {
	if len(it.Types) > 0 {
		return it.Types[0].RawName()
	}

	return ""
}

func (it *IntersectionType) Descriptor() string {
	if len(it.Types) > 0 {
		return it.Types[0].Descriptor()
	}

	return ""
}

func (it *IntersectionType) IsObject() bool          { return true }
func (it *IntersectionType) IsPrimitive() bool       { return false }
func (it *IntersectionType) IsArray() bool           { return false }
func (it *IntersectionType) ArrayDimensions() int    { return 0 }
func (it *IntersectionType) ElementType() JavaType   { return it }
func (it *IntersectionType) ComponentType() JavaType { return nil }
func (it *IntersectionType) StackCategory() int      { return 1 }
func (it *IntersectionType) String() string          { return it.Name() }

// FormalTypeParam represents a formal type parameter declaration.
// e.g. <T extends Comparable<T>> has Name="T", ClassBound=Comparable<T>.
type FormalTypeParam struct {
	ParamName       string
	ClassBound      JavaType   // Class bound (may be nil if only interface bounds)
	InterfaceBounds []JavaType // Interface bounds
}

// Bound returns the effective bound (class bound, or first interface bound, or Object).
func (ftp *FormalTypeParam) Bound() JavaType {
	if ftp.ClassBound != nil {
		return ftp.ClassBound
	}

	if len(ftp.InterfaceBounds) > 0 {
		return ftp.InterfaceBounds[0]
	}

	return NewRefType("java.lang.Object")
}

func (ftp *FormalTypeParam) String() string {
	bound := ftp.Bound()
	if bound.RawName() == "java.lang.Object" {
		return ftp.ParamName
	}

	return ftp.ParamName + " extends " + bound.Name()
}

// ClassSignature holds the generic signature of a class declaration.
type ClassSignature struct {
	FormalParams []FormalTypeParam
	SuperClass   JavaType
	Interfaces   []JavaType
}

// MethodSignature holds the generic signature of a method declaration.
type MethodSignature struct {
	FormalParams []FormalTypeParam
	ParamTypes   []JavaType
	ReturnType   JavaType
	Exceptions   []JavaType
}
