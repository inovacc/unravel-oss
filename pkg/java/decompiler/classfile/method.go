package classfile

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/attr"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Method represents a method in a Java class file.
type Method struct {
	AccessFlags     AccessFlags
	Name            string
	Descriptor      string
	Attributes      *attr.Map
	NameIndex       uint16
	DescriptorIndex uint16
}

// ReadMethod reads a single method_info structure.
func ReadMethod(r *reader.Reader, cp *constantpool.Pool) (*Method, error) {
	flags, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read method access_flags: %w", err)
	}

	nameIdx, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read method name_index: %w", err)
	}

	descIdx, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read method descriptor_index: %w", err)
	}

	attrCount, err := r.ReadU2()
	if err != nil {
		return nil, fmt.Errorf("read method attributes_count: %w", err)
	}

	attrs, err := attr.ReadAttributes(r, cp, attrCount)
	if err != nil {
		return nil, fmt.Errorf("read method attributes: %w", err)
	}

	return &Method{
		AccessFlags:     AccessFlags(flags),
		Name:            cp.UTF8(nameIdx),
		Descriptor:      cp.UTF8(descIdx),
		Attributes:      attrs,
		NameIndex:       nameIdx,
		DescriptorIndex: descIdx,
	}, nil
}

// IsConstructor returns true if this is a constructor (<init>).
func (m *Method) IsConstructor() bool { return m.Name == "<init>" }

// IsStaticInitializer returns true if this is a static initializer (<clinit>).
func (m *Method) IsStaticInitializer() bool { return m.Name == "<clinit>" }

// IsStatic returns true if this method is static.
func (m *Method) IsStatic() bool { return m.AccessFlags.Has(AccStatic) }

// IsAbstract returns true if this method is abstract.
func (m *Method) IsAbstract() bool { return m.AccessFlags.Has(AccAbstract) }

// IsNative returns true if this method is native.
func (m *Method) IsNative() bool { return m.AccessFlags.Has(AccNative) }

// IsSynthetic returns true if this method is synthetic.
func (m *Method) IsSynthetic() bool { return m.AccessFlags.Has(AccSynthetic) }

// IsBridge returns true if this method is a bridge method.
func (m *Method) IsBridge() bool { return m.AccessFlags.Has(AccBridge) }

// IsVarargs returns true if this method takes variable arguments.
func (m *Method) IsVarargs() bool { return m.AccessFlags.Has(AccVarargs) }

// Code returns the Code attribute, or nil if the method has no code (abstract/native).
func (m *Method) Code() *attr.Code {
	if c := m.Attributes.Get("Code"); c != nil {
		if code, ok := c.(*attr.Code); ok {
			return code
		}
	}

	return nil
}

// Signature returns the generic signature if present, otherwise the descriptor.
func (m *Method) Signature() string {
	if sig := m.Attributes.Get("Signature"); sig != nil {
		if s, ok := sig.(*attr.Signature); ok {
			return s.SignatureValue
		}
	}

	return m.Descriptor
}

// ExceptionTypes returns the list of checked exception class indices.
func (m *Method) ExceptionTypes() []uint16 {
	if ex := m.Attributes.Get("Exceptions"); ex != nil {
		if e, ok := ex.(*attr.Exceptions); ok {
			return e.ExceptionIndexTable
		}
	}

	return nil
}
