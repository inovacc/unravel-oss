package classfile

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/attr"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Field represents a field in a Java class file.
type Field struct {
	AccessFlags     AccessFlags
	Name            string
	Descriptor      string
	Attributes      *attr.Map
	NameIndex       uint16
	DescriptorIndex uint16
}

// ReadField reads a single field_info structure.
func ReadField(r *reader.Reader, cp *constantpool.Pool) (*Field, error) {
	flags, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read field access_flags: %w", err)
	}

	nameIdx, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read field name_index: %w", err)
	}

	descIdx, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read field descriptor_index: %w", err)
	}

	attrCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read field attributes_count: %w", err)
	}

	attrs, err := attr.ReadAttributes(r, cp, attrCount)
	if err != nil {
		return nil, fmt.Errorf("read field attributes: %w", err)
	}

	return &Field{
		AccessFlags:     AccessFlags(flags),
		Name:            cp.UTF8(nameIdx),
		Descriptor:      cp.UTF8(descIdx),
		Attributes:      attrs,
		NameIndex:       nameIdx,
		DescriptorIndex: descIdx,
	}, nil
}

// IsStatic returns true if this field is static.
func (f *Field) IsStatic() bool { return f.AccessFlags.Has(AccStatic) }

// IsFinal returns true if this field is final.
func (f *Field) IsFinal() bool { return f.AccessFlags.Has(AccFinal) }

// Signature returns the generic signature if present, otherwise the descriptor.
func (f *Field) Signature() string {
	if sig := f.Attributes.Get("Signature"); sig != nil {
		if s, ok := sig.(*attr.Signature); ok {
			return s.SignatureValue
		}
	}

	return f.Descriptor
}

// ConstantValueIndex returns the constant pool index of the ConstantValue attribute,
// or 0 if not present.
func (f *Field) ConstantValueIndex() uint16 {
	if cv := f.Attributes.Get("ConstantValue"); cv != nil {
		if c, ok := cv.(*attr.ConstantValue); ok {
			return c.ValueIndex
		}
	}

	return 0
}
