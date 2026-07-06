package ast

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// FieldRef describes a field reference from the constant pool.
type FieldRef struct {
	ClassName  string
	FieldName  string
	Descriptor string
	FieldType  types.JavaType
}

// FieldAccess represents reading or writing an instance field.
type FieldAccess struct {
	Object Expression
	Field  *FieldRef
}

func NewFieldAccess(object Expression, field *FieldRef) *FieldAccess {
	return &FieldAccess{Object: object, Field: field}
}

func (f *FieldAccess) Type() types.JavaType   { return f.Field.FieldType }
func (f *FieldAccess) Precedence() Precedence { return PrecPostfix }
func (f *FieldAccess) IsSimple() bool         { return false }
func (f *FieldAccess) Children() []Expression { return []Expression{f.Object} }
func (f *FieldAccess) LValueName() string     { return f.Field.FieldName }

func (f *FieldAccess) String() string {
	return fmt.Sprintf("%s.%s", f.Object, f.Field.FieldName)
}

// StaticFieldAccess represents reading or writing a static field.
type StaticFieldAccess struct {
	Field *FieldRef
}

func NewStaticFieldAccess(field *FieldRef) *StaticFieldAccess {
	return &StaticFieldAccess{Field: field}
}

func (s *StaticFieldAccess) Type() types.JavaType   { return s.Field.FieldType }
func (s *StaticFieldAccess) Precedence() Precedence { return PrecPostfix }
func (s *StaticFieldAccess) IsSimple() bool         { return true }
func (s *StaticFieldAccess) Children() []Expression { return nil }
func (s *StaticFieldAccess) LValueName() string     { return s.Field.FieldName }

func (s *StaticFieldAccess) String() string {
	return fmt.Sprintf("%s.%s", types.SimplifyJavaLang(s.Field.ClassName), s.Field.FieldName)
}
