package attr

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Annotations holds runtime annotations.
type Annotations struct {
	AttrName string
	Annots   []AnnotationEntry
}

func (a *Annotations) Name() string { return a.AttrName }

// AnnotationEntry represents a single annotation.
type AnnotationEntry struct {
	TypeIndex uint16
	Pairs     []ElementValuePair
}

// ElementValuePair is a name-value pair in an annotation.
type ElementValuePair struct {
	NameIndex uint16
	Value     ElementValue
}

// ElementValue represents an annotation element value.
type ElementValue struct {
	Tag           byte
	ConstValueIdx uint16           // for B,C,D,F,I,J,S,Z,s
	EnumTypeIdx   uint16           // for e
	EnumConstIdx  uint16           // for e
	ClassInfoIdx  uint16           // for c
	AnnotationVal *AnnotationEntry // for @
	ArrayValues   []ElementValue   // for [
}

func readAnnotations(name string, r *reader.Reader, cp *constantpool.Pool) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	annots := make([]AnnotationEntry, count)
	for i := range annots {
		if annots[i], err = readAnnotationEntry(r); err != nil {
			return nil, fmt.Errorf("read annotation %d: %w", i, err)
		}
	}

	return &Annotations{AttrName: name, Annots: annots}, nil
}

func readAnnotationEntry(r *reader.Reader) (AnnotationEntry, error) {
	var (
		ae  AnnotationEntry
		err error
	)

	if ae.TypeIndex, err = r.ReadU2(); err != nil {
		return ae, err
	}

	numPairs, err := r.ReadU2()
	if err != nil {
		return ae, err
	}

	ae.Pairs = make([]ElementValuePair, numPairs)
	for i := range ae.Pairs {
		if ae.Pairs[i].NameIndex, err = r.ReadU2(); err != nil {
			return ae, err
		}

		if ae.Pairs[i].Value, err = readElementValue(r); err != nil {
			return ae, err
		}
	}

	return ae, nil
}

func readElementValue(r *reader.Reader) (ElementValue, error) {
	var ev ElementValue

	tag, err := r.ReadU1()
	if err != nil {
		return ev, err
	}

	ev.Tag = tag

	switch tag {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z', 's':
		if ev.ConstValueIdx, err = r.ReadU2(); err != nil {
			return ev, err
		}
	case 'e':
		if ev.EnumTypeIdx, err = r.ReadU2(); err != nil {
			return ev, err
		}

		if ev.EnumConstIdx, err = r.ReadU2(); err != nil {
			return ev, err
		}
	case 'c':
		if ev.ClassInfoIdx, err = r.ReadU2(); err != nil {
			return ev, err
		}
	case '@':
		ae, err := readAnnotationEntry(r)
		if err != nil {
			return ev, err
		}

		ev.AnnotationVal = &ae
	case '[':
		count, err := r.ReadU2()
		if err != nil {
			return ev, err
		}

		ev.ArrayValues = make([]ElementValue, count)
		for i := range ev.ArrayValues {
			if ev.ArrayValues[i], err = readElementValue(r); err != nil {
				return ev, err
			}
		}
	default:
		return ev, fmt.Errorf("unknown annotation element value tag: %c", tag)
	}

	return ev, nil
}

// TypeAnnotations holds type annotations.
type TypeAnnotations struct {
	AttrName string
	Annots   []TypeAnnotationEntry
}

func (a *TypeAnnotations) Name() string { return a.AttrName }

// TypeAnnotationEntry is a type annotation with target info and type path.
type TypeAnnotationEntry struct {
	TargetType byte
	TargetInfo []byte // raw target_info bytes
	TypePath   []TypePathEntry
	TypeIndex  uint16
	Pairs      []ElementValuePair
}

// TypePathEntry is a single type_path entry.
type TypePathEntry struct {
	Kind     uint8
	ArgIndex uint8
}

func readTypeAnnotations(name string, r *reader.Reader, _ *constantpool.Pool) (Attribute, error) {
	count, err := r.ReadU2()
	if err != nil {
		return nil, err
	}

	annots := make([]TypeAnnotationEntry, count)
	for i := range annots {
		if annots[i], err = readTypeAnnotationEntry(r); err != nil {
			return nil, fmt.Errorf("read type annotation %d: %w", i, err)
		}
	}

	return &TypeAnnotations{AttrName: name, Annots: annots}, nil
}

func readTypeAnnotationEntry(r *reader.Reader) (TypeAnnotationEntry, error) {
	var (
		tae TypeAnnotationEntry
		err error
	)

	if tae.TargetType, err = r.ReadU1(); err != nil {
		return tae, err
	}

	// Read target_info based on target_type
	tae.TargetInfo, err = readTargetInfo(r, tae.TargetType)
	if err != nil {
		return tae, fmt.Errorf("read target_info for type %#x: %w", tae.TargetType, err)
	}

	// Read type_path
	pathLen, err := r.ReadU1()
	if err != nil {
		return tae, err
	}

	tae.TypePath = make([]TypePathEntry, pathLen)
	for i := range tae.TypePath {
		if tae.TypePath[i].Kind, err = r.ReadU1(); err != nil {
			return tae, err
		}

		if tae.TypePath[i].ArgIndex, err = r.ReadU1(); err != nil {
			return tae, err
		}
	}

	// Read annotation itself
	if tae.TypeIndex, err = r.ReadU2(); err != nil {
		return tae, err
	}

	numPairs, err := r.ReadU2()
	if err != nil {
		return tae, err
	}

	tae.Pairs = make([]ElementValuePair, numPairs)
	for i := range tae.Pairs {
		if tae.Pairs[i].NameIndex, err = r.ReadU2(); err != nil {
			return tae, err
		}

		if tae.Pairs[i].Value, err = readElementValue(r); err != nil {
			return tae, err
		}
	}

	return tae, nil
}

func readTargetInfo(r *reader.Reader, targetType byte) ([]byte, error) {
	switch targetType {
	case 0x00, 0x01: // type_parameter_target
		b, err := r.ReadBytes(1)
		return b, err
	case 0x10: // supertype_target
		b, err := r.ReadBytes(2)
		return b, err
	case 0x11, 0x12: // type_parameter_bound_target
		b, err := r.ReadBytes(2)
		return b, err
	case 0x13, 0x14, 0x15: // empty_target
		return nil, nil
	case 0x16: // formal_parameter_target
		b, err := r.ReadBytes(1)
		return b, err
	case 0x17: // throws_target
		b, err := r.ReadBytes(2)
		return b, err
	case 0x40, 0x41: // localvar_target
		tableLen, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		// SEC: cap tableLen before multiplication to prevent ~25 GiB allocation
		// from a crafted class with 65535 annotations each with tableLen=65535.
		const maxLocalVarTargetEntries = 512
		if tableLen > maxLocalVarTargetEntries {
			return nil, fmt.Errorf("localvar_target: unreasonable table_length %d (max %d)", tableLen, maxLocalVarTargetEntries)
		}

		data := make([]byte, 2+tableLen*6)
		data[0] = byte(tableLen >> 8)

		data[1] = byte(tableLen)
		for i := range tableLen {
			entry, err := r.ReadBytes(6)
			if err != nil {
				return nil, err
			}

			copy(data[2+i*6:], entry)
		}

		return data, nil
	case 0x42: // catch_target
		b, err := r.ReadBytes(2)
		return b, err
	case 0x43, 0x44, 0x45, 0x46: // offset_target
		b, err := r.ReadBytes(2)
		return b, err
	case 0x47, 0x48, 0x49, 0x4A, 0x4B: // type_argument_target
		b, err := r.ReadBytes(3)
		return b, err
	default:
		return nil, fmt.Errorf("unknown target_type: %#x", targetType)
	}
}

// ParameterAnnotations holds parameter annotations.
type ParameterAnnotations struct {
	AttrName   string
	Parameters [][]AnnotationEntry
}

func (a *ParameterAnnotations) Name() string { return a.AttrName }

func readParameterAnnotations(name string, r *reader.Reader, _ *constantpool.Pool) (Attribute, error) {
	numParams, err := r.ReadU1()
	if err != nil {
		return nil, err
	}

	params := make([][]AnnotationEntry, numParams)
	for i := range params {
		count, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		params[i] = make([]AnnotationEntry, count)
		for j := range params[i] {
			if params[i][j], err = readAnnotationEntry(r); err != nil {
				return nil, err
			}
		}
	}

	return &ParameterAnnotations{AttrName: name, Parameters: params}, nil
}

// AnnotationDefault holds the default value for an annotation element.
type AnnotationDefault struct {
	DefaultValue ElementValue
}

func (*AnnotationDefault) Name() string { return "AnnotationDefault" }

func readAnnotationDefault(r *reader.Reader, _ *constantpool.Pool) (Attribute, error) {
	ev, err := readElementValue(r)
	if err != nil {
		return nil, err
	}

	return &AnnotationDefault{DefaultValue: ev}, nil
}
