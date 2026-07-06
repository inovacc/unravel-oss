package attr

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Attribute represents a class file attribute.
type Attribute interface {
	Name() string
}

// Raw is an unrecognized attribute stored as raw bytes.
type Raw struct {
	AttrName string
	Data     []byte
}

func (a *Raw) Name() string { return a.AttrName }

// Map holds attributes keyed by name.
type Map struct {
	attrs map[string][]Attribute
}

// NewMap creates an empty attribute map.
func NewMap() *Map {
	return &Map{attrs: make(map[string][]Attribute)}
}

// Add adds an attribute to the map.
func (m *Map) Add(a Attribute) {
	m.attrs[a.Name()] = append(m.attrs[a.Name()], a)
}

// Get returns the first attribute with the given name, or nil.
func (m *Map) Get(name string) Attribute {
	if as, ok := m.attrs[name]; ok && len(as) > 0 {
		return as[0]
	}

	return nil
}

// GetAll returns all attributes with the given name.
func (m *Map) GetAll(name string) []Attribute {
	return m.attrs[name]
}

// Has returns true if an attribute with the given name exists.
func (m *Map) Has(name string) bool {
	return len(m.attrs[name]) > 0
}

// All returns all attributes in the map.
func (m *Map) All() []Attribute {
	var result []Attribute
	for _, as := range m.attrs {
		result = append(result, as...)
	}

	return result
}

// ReadAttributes reads count attributes from the reader.
func ReadAttributes(r *reader.Reader, cp *constantpool.Pool, count uint16) (*Map, error) {
	m := NewMap()

	for range count {
		nameIdx, err := r.ReadU2()
		if err != nil {
			return nil, fmt.Errorf("read attribute name index: %w", err)
		}

		length, err := r.ReadU4()
		if err != nil {
			return nil, fmt.Errorf("read attribute length: %w", err)
		}

		// SEC: cap attribute body size before slicing to prevent OOM from a
		// crafted Code attribute with length=0xFFFFFFFF (~4 GiB).
		// 64 MiB is generous; no legitimate class file attribute approaches this.
		const maxAttributeBytes = 64 << 20
		if length > maxAttributeBytes {
			return nil, fmt.Errorf("attribute too large: %d bytes (max %d)", length, maxAttributeBytes)
		}

		name := cp.UTF8(nameIdx)

		attrReader, err := r.Slice(int(length))
		if err != nil {
			return nil, fmt.Errorf("read attribute %q data (%d bytes): %w", name, length, err)
		}

		a, err := parseAttribute(name, attrReader, cp)
		if err != nil {
			// Store as raw on parse failure
			a = &Raw{AttrName: name, Data: attrReader.Bytes()}
		}

		m.Add(a)
	}

	return m, nil
}

func parseAttribute(name string, r *reader.Reader, cp *constantpool.Pool) (Attribute, error) {
	switch name {
	case "Code":
		return readCode(r, cp)
	case "ConstantValue":
		return readConstantValue(r)
	case "Exceptions":
		return readExceptions(r)
	case "SourceFile":
		return readSourceFile(r, cp)
	case "LineNumberTable":
		return readLineNumberTable(r)
	case "LocalVariableTable":
		return readLocalVariableTable(r)
	case "LocalVariableTypeTable":
		return readLocalVariableTypeTable(r)
	case "InnerClasses":
		return readInnerClasses(r)
	case "Signature":
		return readSignature(r, cp)
	case "BootstrapMethods":
		return readBootstrapMethods(r)
	case "EnclosingMethod":
		return readEnclosingMethod(r)
	case "NestHost":
		return readNestHost(r)
	case "NestMembers":
		return readNestMembers(r)
	case "PermittedSubclasses":
		return readPermittedSubclasses(r)
	case "Record":
		return readRecord(r, cp)
	case "MethodParameters":
		return readMethodParameters(r)
	case "RuntimeVisibleAnnotations", "RuntimeInvisibleAnnotations":
		return readAnnotations(name, r, cp)
	case "RuntimeVisibleTypeAnnotations", "RuntimeInvisibleTypeAnnotations":
		return readTypeAnnotations(name, r, cp)
	case "RuntimeVisibleParameterAnnotations", "RuntimeInvisibleParameterAnnotations":
		return readParameterAnnotations(name, r, cp)
	case "AnnotationDefault":
		return readAnnotationDefault(r, cp)
	case "Synthetic":
		return &Synthetic{}, nil
	case "Deprecated":
		return &Deprecated{}, nil
	case "StackMapTable":
		// Skip for now - needed for verification but not decompilation
		return &Raw{AttrName: name, Data: r.RemainingBytes()}, nil
	default:
		return &Raw{AttrName: name, Data: r.RemainingBytes()}, nil
	}
}
