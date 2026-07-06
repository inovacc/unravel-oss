package constantpool

import (
	"fmt"
	"io"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// Pool holds all constant pool entries for a class file.
// Indices are 1-based. Index 0 is unused. Long/Double entries occupy two slots.
type Pool struct {
	entries []*Entry // 0-indexed; entry at [i] corresponds to CP index i+1
	count   uint16   // constant_pool_count from class file (max index + 1)
}

// maxCPBytes is the aggregate byte budget for constant pool UTF-8 entries.
// A class with 65534 UTF-8 entries each 65535 bytes long would cost ~4.3 GiB;
// 32 MiB is generous for any real class file.
const maxCPBytes = 32 << 20

// Read parses the constant pool from the reader.
// count is the constant_pool_count value from the class file header.
func Read(r *reader.Reader, count uint16) (*Pool, error) {
	// SEC: the JVM spec requires constant_pool_count >= 1 (index 0 is reserved).
	// A crafted count==0 underflows count-1 (uint16) to 65535 and allocates a
	// 65535-element slice; reject it explicitly.
	if count == 0 {
		return nil, fmt.Errorf("constant_pool_count must be >= 1")
	}
	p := &Pool{
		entries: make([]*Entry, count-1),
		count:   count,
	}

	var totalCPBytes int

	for i := uint16(1); i < count; i++ {
		tag, err := r.ReadU1()
		if err != nil {
			return nil, fmt.Errorf("read cp tag at index %d: %w", i, err)
		}

		entry, err := readEntry(r, Tag(tag))
		if err != nil {
			return nil, fmt.Errorf("read cp entry %d (tag %d): %w", i, tag, err)
		}

		// SEC: track cumulative UTF-8 bytes to prevent ~4 GiB total allocation from
		// a crafted class with 65534 TagUTF8 entries each claiming 65535 bytes.
		if entry.Tag == TagUTF8 {
			totalCPBytes += len(entry.UTF8Value)
			if totalCPBytes > maxCPBytes {
				return nil, fmt.Errorf("constant pool exceeds aggregate size limit (%d bytes)", maxCPBytes)
			}
		}

		p.entries[i-1] = entry

		// Long and Double take two slots
		if entry.IsWide() {
			i++ // skip next slot
			if i < count {
				p.entries[i-1] = nil // placeholder
			}
		}
	}

	return p, nil
}

func readEntry(r *reader.Reader, tag Tag) (*Entry, error) {
	e := &Entry{Tag: tag}

	switch tag {
	case TagUTF8:
		length, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		data, err := r.ReadBytes(int(length))
		if err != nil {
			return nil, err
		}

		e.UTF8Value = reader.ReadModifiedUTF8(data)

	case TagInteger:
		v, err := r.ReadS4()
		if err != nil {
			return nil, err
		}

		e.IntValue = v

	case TagFloat:
		v, err := r.ReadFloat32()
		if err != nil {
			return nil, err
		}

		e.FloatValue = v

	case TagLong:
		v, err := r.ReadU8()
		if err != nil {
			return nil, err
		}

		e.LongValue = int64(v)

	case TagDouble:
		v, err := r.ReadFloat64()
		if err != nil {
			return nil, err
		}

		e.DoubleValue = v

	case TagClass, TagModule, TagPackage:
		idx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		e.NameIndex = idx

	case TagString, TagMethodType:
		idx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		e.NameIndex = idx

	case TagFieldRef, TagMethodRef, TagInterfaceMethodRef:
		classIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		natIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		e.ClassIndex = classIdx
		e.NameAndTypeIndex = natIdx

	case TagNameAndType:
		nameIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		descIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		e.NameIndex = nameIdx
		e.DescriptorIndex = descIdx

	case TagMethodHandle:
		kind, err := r.ReadU1()
		if err != nil {
			return nil, err
		}

		refIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		e.ReferenceKind = kind
		e.ReferenceIndex = refIdx

	case TagDynamic, TagInvokeDynamic:
		bsmIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		natIdx, err := r.ReadU2()
		if err != nil {
			return nil, err
		}

		e.BootstrapMethodAttrIndex = bsmIdx
		e.NameAndTypeIndex = natIdx

	default:
		return nil, fmt.Errorf("unknown constant pool tag: %d", tag)
	}

	return e, nil
}

// Count returns the constant_pool_count (one more than the max index).
func (p *Pool) Count() uint16 { return p.count }

// Get returns the entry at index i (1-based). Returns nil for unused slots.
func (p *Pool) Get(i uint16) *Entry {
	if i == 0 || i >= p.count {
		return nil
	}

	return p.entries[i-1]
}

// UTF8 returns the UTF8 string at index i. Returns "" if not a UTF8 entry.
func (p *Pool) UTF8(i uint16) string {
	e := p.Get(i)
	if e == nil || e.Tag != TagUTF8 {
		return ""
	}

	return e.UTF8Value
}

// ClassName returns the class name at index i, resolving Class -> UTF8.
// Returns the internal form (e.g. "java/lang/Object").
func (p *Pool) ClassName(i uint16) string {
	e := p.Get(i)
	if e == nil || e.Tag != TagClass {
		return ""
	}

	return p.UTF8(e.NameIndex)
}

// ClassNameDotted returns the class name in dotted form (e.g. "java.lang.Object").
func (p *Pool) ClassNameDotted(i uint16) string {
	return strings.ReplaceAll(p.ClassName(i), "/", ".")
}

// NameAndType returns the name and descriptor strings for a NameAndType entry.
func (p *Pool) NameAndType(i uint16) (name, descriptor string) {
	e := p.Get(i)
	if e == nil || e.Tag != TagNameAndType {
		return "", ""
	}

	return p.UTF8(e.NameIndex), p.UTF8(e.DescriptorIndex)
}

// FieldRefInfo returns class name, field name, and field descriptor for a FieldRef.
func (p *Pool) FieldRefInfo(i uint16) (className, fieldName, fieldDesc string) {
	e := p.Get(i)
	if e == nil || e.Tag != TagFieldRef {
		return "", "", ""
	}

	className = p.ClassName(e.ClassIndex)
	fieldName, fieldDesc = p.NameAndType(e.NameAndTypeIndex)

	return
}

// MethodRefInfo returns class name, method name, and method descriptor.
// Works for both MethodRef and InterfaceMethodRef.
func (p *Pool) MethodRefInfo(i uint16) (className, methodName, methodDesc string) {
	e := p.Get(i)
	if e == nil || (e.Tag != TagMethodRef && e.Tag != TagInterfaceMethodRef) {
		return "", "", ""
	}

	className = p.ClassName(e.ClassIndex)
	methodName, methodDesc = p.NameAndType(e.NameAndTypeIndex)

	return
}

// StringValue returns the string value for a String constant.
func (p *Pool) StringValue(i uint16) string {
	e := p.Get(i)
	if e == nil || e.Tag != TagString {
		return ""
	}

	return p.UTF8(e.NameIndex)
}

// ModuleName returns the module name for a Module constant.
func (p *Pool) ModuleName(i uint16) string {
	e := p.Get(i)
	if e == nil || e.Tag != TagModule {
		return ""
	}

	return p.UTF8(e.NameIndex)
}

// PackageName returns the package name for a Package constant.
func (p *Pool) PackageName(i uint16) string {
	e := p.Get(i)
	if e == nil || e.Tag != TagPackage {
		return ""
	}

	return p.UTF8(e.NameIndex)
}

// Validate checks that all cross-references are valid.
func (p *Pool) Validate() error {
	for i := uint16(1); i < p.count; i++ {
		e := p.Get(i)
		if e == nil {
			continue
		}

		switch e.Tag {
		case TagClass, TagModule, TagPackage:
			if p.Get(e.NameIndex) == nil {
				return fmt.Errorf("cp[%d] %s: name_index %d not found", i, e.Tag, e.NameIndex)
			}
		case TagString, TagMethodType:
			if p.Get(e.NameIndex) == nil {
				return fmt.Errorf("cp[%d] %s: index %d not found", i, e.Tag, e.NameIndex)
			}
		case TagFieldRef, TagMethodRef, TagInterfaceMethodRef:
			if p.Get(e.ClassIndex) == nil {
				return fmt.Errorf("cp[%d] %s: class_index %d not found", i, e.Tag, e.ClassIndex)
			}

			if p.Get(e.NameAndTypeIndex) == nil {
				return fmt.Errorf("cp[%d] %s: name_and_type_index %d not found", i, e.Tag, e.NameAndTypeIndex)
			}
		case TagNameAndType:
			if p.Get(e.NameIndex) == nil {
				return fmt.Errorf("cp[%d] NameAndType: name_index %d not found", i, e.NameIndex)
			}

			if p.Get(e.DescriptorIndex) == nil {
				return fmt.Errorf("cp[%d] NameAndType: descriptor_index %d not found", i, e.DescriptorIndex)
			}
		case TagMethodHandle:
			if p.Get(e.ReferenceIndex) == nil {
				return fmt.Errorf("cp[%d] MethodHandle: reference_index %d not found", i, e.ReferenceIndex)
			}
		case TagDynamic, TagInvokeDynamic:
			if p.Get(e.NameAndTypeIndex) == nil {
				return fmt.Errorf("cp[%d] %s: name_and_type_index %d not found", i, e.Tag, e.NameAndTypeIndex)
			}
		}
	}

	return nil
}

// Dump returns a human-readable listing of the constant pool.
func (p *Pool) Dump(w io.Writer) {
	for i := uint16(1); i < p.count; i++ {
		e := p.Get(i)
		if e == nil {
			_, _ = fmt.Fprintf(w, "  #%d = (wide continuation)\n", i)
			continue
		}

		switch e.Tag {
		case TagUTF8:
			_, _ = fmt.Fprintf(w, "  #%d = Utf8\t%s\n", i, e.UTF8Value)
		case TagInteger:
			_, _ = fmt.Fprintf(w, "  #%d = Integer\t%d\n", i, e.IntValue)
		case TagFloat:
			_, _ = fmt.Fprintf(w, "  #%d = Float\t%f\n", i, e.FloatValue)
		case TagLong:
			_, _ = fmt.Fprintf(w, "  #%d = Long\t%d\n", i, e.LongValue)
		case TagDouble:
			_, _ = fmt.Fprintf(w, "  #%d = Double\t%f\n", i, e.DoubleValue)
		case TagClass:
			_, _ = fmt.Fprintf(w, "  #%d = Class\t#%d\t// %s\n", i, e.NameIndex, p.UTF8(e.NameIndex))
		case TagString:
			_, _ = fmt.Fprintf(w, "  #%d = String\t#%d\t// %s\n", i, e.NameIndex, p.UTF8(e.NameIndex))
		case TagFieldRef:
			n, d := p.NameAndType(e.NameAndTypeIndex)
			_, _ = fmt.Fprintf(w, "  #%d = Fieldref\t#%d.#%d\t// %s.%s:%s\n", i, e.ClassIndex, e.NameAndTypeIndex, p.ClassName(e.ClassIndex), n, d)
		case TagMethodRef:
			n, d := p.NameAndType(e.NameAndTypeIndex)
			_, _ = fmt.Fprintf(w, "  #%d = Methodref\t#%d.#%d\t// %s.%s:%s\n", i, e.ClassIndex, e.NameAndTypeIndex, p.ClassName(e.ClassIndex), n, d)
		case TagInterfaceMethodRef:
			n, d := p.NameAndType(e.NameAndTypeIndex)
			_, _ = fmt.Fprintf(w, "  #%d = InterfaceMethodref\t#%d.#%d\t// %s.%s:%s\n", i, e.ClassIndex, e.NameAndTypeIndex, p.ClassName(e.ClassIndex), n, d)
		case TagNameAndType:
			_, _ = fmt.Fprintf(w, "  #%d = NameAndType\t#%d:#%d\t// %s:%s\n", i, e.NameIndex, e.DescriptorIndex, p.UTF8(e.NameIndex), p.UTF8(e.DescriptorIndex))
		case TagMethodHandle:
			_, _ = fmt.Fprintf(w, "  #%d = MethodHandle\tkind=%d #%d\n", i, e.ReferenceKind, e.ReferenceIndex)
		case TagMethodType:
			_, _ = fmt.Fprintf(w, "  #%d = MethodType\t#%d\t// %s\n", i, e.NameIndex, p.UTF8(e.NameIndex))
		case TagDynamic:
			_, _ = fmt.Fprintf(w, "  #%d = Dynamic\t#%d:#%d\n", i, e.BootstrapMethodAttrIndex, e.NameAndTypeIndex)
		case TagInvokeDynamic:
			_, _ = fmt.Fprintf(w, "  #%d = InvokeDynamic\t#%d:#%d\n", i, e.BootstrapMethodAttrIndex, e.NameAndTypeIndex)
		case TagModule:
			_, _ = fmt.Fprintf(w, "  #%d = Module\t#%d\t// %s\n", i, e.NameIndex, p.UTF8(e.NameIndex))
		case TagPackage:
			_, _ = fmt.Fprintf(w, "  #%d = Package\t#%d\t// %s\n", i, e.NameIndex, p.UTF8(e.NameIndex))
		}
	}
}
