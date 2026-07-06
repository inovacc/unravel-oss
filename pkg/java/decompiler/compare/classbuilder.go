/*
Copyright (c) 2026 Security Research
*/
package compare

import (
	"encoding/binary"
)

// ClassBuilder constructs valid .class file bytes programmatically.
// It provides a higher-level API than raw byte manipulation, making it
// easy to create test fixtures with methods, fields, and bytecode.
type ClassBuilder struct {
	majorVersion uint16
	accessFlags  uint16
	thisClass    string // internal form: "com/example/Hello"
	superClass   string // internal form: "java/lang/Object"
	interfaces   []string
	fields       []fieldEntry
	methods      []methodEntry
	sourceFile   string
	cpEntries    []cpEntry
	cpMap        map[string]uint16 // key → CP index
	nextCP       uint16
}

type cpEntry struct {
	tag  byte
	data []byte
}

type fieldEntry struct {
	accessFlags uint16
	name        string
	descriptor  string
}

type methodEntry struct {
	accessFlags uint16
	name        string
	descriptor  string
	maxStack    uint16
	maxLocals   uint16
	code        []byte
	exceptions  []exceptionEntry
}

type exceptionEntry struct {
	startPC   uint16
	endPC     uint16
	handlerPC uint16
	catchType uint16
}

// NewClassBuilder creates a builder for a Java class with the given name and version.
func NewClassBuilder(className string, majorVersion uint16) *ClassBuilder {
	b := &ClassBuilder{
		majorVersion: majorVersion,
		accessFlags:  0x0021, // ACC_PUBLIC | ACC_SUPER
		thisClass:    className,
		superClass:   "java/lang/Object",
		cpMap:        make(map[string]uint16),
		nextCP:       1,
	}
	return b
}

// SetAccessFlags sets the class access flags.
func (b *ClassBuilder) SetAccessFlags(flags uint16) *ClassBuilder {
	b.accessFlags = flags
	return b
}

// SetSuper sets the superclass.
func (b *ClassBuilder) SetSuper(superClass string) *ClassBuilder {
	b.superClass = superClass
	return b
}

// AddInterface adds an implemented interface.
func (b *ClassBuilder) AddInterface(iface string) *ClassBuilder {
	b.interfaces = append(b.interfaces, iface)
	return b
}

// SetSourceFile sets the SourceFile attribute.
func (b *ClassBuilder) SetSourceFile(name string) *ClassBuilder {
	b.sourceFile = name
	return b
}

// AddField adds a field to the class.
func (b *ClassBuilder) AddField(accessFlags uint16, name, descriptor string) *ClassBuilder {
	b.fields = append(b.fields, fieldEntry{accessFlags, name, descriptor})
	return b
}

// AddMethod adds a method with bytecode.
func (b *ClassBuilder) AddMethod(accessFlags uint16, name, descriptor string, maxStack, maxLocals uint16, code []byte) *ClassBuilder {
	b.methods = append(b.methods, methodEntry{
		accessFlags: accessFlags,
		name:        name,
		descriptor:  descriptor,
		maxStack:    maxStack,
		maxLocals:   maxLocals,
		code:        code,
	})
	return b
}

// AddMethodWithExceptions adds a method with bytecode and exception handlers.
func (b *ClassBuilder) AddMethodWithExceptions(accessFlags uint16, name, descriptor string, maxStack, maxLocals uint16, code []byte, exceptions []exceptionEntry) *ClassBuilder {
	b.methods = append(b.methods, methodEntry{
		accessFlags: accessFlags,
		name:        name,
		descriptor:  descriptor,
		maxStack:    maxStack,
		maxLocals:   maxLocals,
		code:        code,
		exceptions:  exceptions,
	})
	return b
}

// Build constructs the complete .class file bytes.
func (b *ClassBuilder) Build() []byte {
	// First pass: allocate all constant pool entries
	thisClassIdx := b.addClass(b.thisClass)
	superClassIdx := b.addClass(b.superClass)

	var ifaceIdxs []uint16
	for _, iface := range b.interfaces {
		ifaceIdxs = append(ifaceIdxs, b.addClass(iface))
	}

	// Pre-allocate field/method CP entries
	type fieldRef struct {
		nameIdx uint16
		descIdx uint16
	}
	var fieldRefs []fieldRef
	for _, f := range b.fields {
		fieldRefs = append(fieldRefs, fieldRef{b.addUTF8(f.name), b.addUTF8(f.descriptor)})
	}

	type methodRef struct {
		nameIdx uint16
		descIdx uint16
	}
	var methodRefs []methodRef
	for _, m := range b.methods {
		methodRefs = append(methodRefs, methodRef{b.addUTF8(m.name), b.addUTF8(m.descriptor)})
	}

	codeIdx := b.addUTF8("Code")

	var sourceFileIdx, sourceFileNameIdx uint16
	var sourceFileAttrIdx uint16
	if b.sourceFile != "" {
		sourceFileAttrIdx = b.addUTF8("SourceFile")
		sourceFileNameIdx = b.addUTF8(b.sourceFile)
		_ = sourceFileIdx
	}

	// Build the .class file
	var buf []byte

	// Magic
	buf = binary.BigEndian.AppendUint32(buf, 0xCAFEBABE)
	// Version
	buf = binary.BigEndian.AppendUint16(buf, 0) // minor
	buf = binary.BigEndian.AppendUint16(buf, b.majorVersion)

	// Constant pool
	buf = binary.BigEndian.AppendUint16(buf, b.nextCP)
	for _, e := range b.cpEntries {
		buf = append(buf, e.tag)
		buf = append(buf, e.data...)
	}

	// Access flags
	buf = binary.BigEndian.AppendUint16(buf, b.accessFlags)
	// this_class
	buf = binary.BigEndian.AppendUint16(buf, thisClassIdx)
	// super_class
	buf = binary.BigEndian.AppendUint16(buf, superClassIdx)

	// Interfaces
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(ifaceIdxs)))
	for _, idx := range ifaceIdxs {
		buf = binary.BigEndian.AppendUint16(buf, idx)
	}

	// Fields
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b.fields)))
	for i, f := range b.fields {
		buf = binary.BigEndian.AppendUint16(buf, f.accessFlags)
		buf = binary.BigEndian.AppendUint16(buf, fieldRefs[i].nameIdx)
		buf = binary.BigEndian.AppendUint16(buf, fieldRefs[i].descIdx)
		buf = binary.BigEndian.AppendUint16(buf, 0) // attributes_count
	}

	// Methods
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b.methods)))
	for i, m := range b.methods {
		buf = binary.BigEndian.AppendUint16(buf, m.accessFlags)
		buf = binary.BigEndian.AppendUint16(buf, methodRefs[i].nameIdx)
		buf = binary.BigEndian.AppendUint16(buf, methodRefs[i].descIdx)

		if len(m.code) > 0 {
			// One attribute: Code
			buf = binary.BigEndian.AppendUint16(buf, 1) // attributes_count

			// Code attribute
			buf = binary.BigEndian.AppendUint16(buf, codeIdx)
			excTableLen := len(m.exceptions) * 8
			codeAttrLen := uint32(2 + 2 + 4 + len(m.code) + 2 + excTableLen + 2) // maxStack + maxLocals + codeLen + code + excCount + excTable + attrCount
			buf = binary.BigEndian.AppendUint32(buf, codeAttrLen)
			buf = binary.BigEndian.AppendUint16(buf, m.maxStack)
			buf = binary.BigEndian.AppendUint16(buf, m.maxLocals)
			buf = binary.BigEndian.AppendUint32(buf, uint32(len(m.code)))
			buf = append(buf, m.code...)

			// Exception table
			buf = binary.BigEndian.AppendUint16(buf, uint16(len(m.exceptions)))
			for _, exc := range m.exceptions {
				buf = binary.BigEndian.AppendUint16(buf, exc.startPC)
				buf = binary.BigEndian.AppendUint16(buf, exc.endPC)
				buf = binary.BigEndian.AppendUint16(buf, exc.handlerPC)
				buf = binary.BigEndian.AppendUint16(buf, exc.catchType)
			}

			// Code attributes (none)
			buf = binary.BigEndian.AppendUint16(buf, 0)
		} else {
			buf = binary.BigEndian.AppendUint16(buf, 0) // no attributes
		}
	}

	// Class attributes
	if b.sourceFile != "" {
		buf = binary.BigEndian.AppendUint16(buf, 1) // attributes_count
		buf = binary.BigEndian.AppendUint16(buf, sourceFileAttrIdx)
		buf = binary.BigEndian.AppendUint32(buf, 2) // length
		buf = binary.BigEndian.AppendUint16(buf, sourceFileNameIdx)
	} else {
		buf = binary.BigEndian.AppendUint16(buf, 0) // no class attributes
	}

	return buf
}

func (b *ClassBuilder) addUTF8(s string) uint16 {
	key := "utf8:" + s
	if idx, ok := b.cpMap[key]; ok {
		return idx
	}
	idx := b.nextCP
	b.nextCP++

	data := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(data, uint16(len(s)))
	copy(data[2:], s)
	b.cpEntries = append(b.cpEntries, cpEntry{tag: 1, data: data})
	b.cpMap[key] = idx
	return idx
}

func (b *ClassBuilder) addClass(name string) uint16 {
	key := "class:" + name
	if idx, ok := b.cpMap[key]; ok {
		return idx
	}
	nameIdx := b.addUTF8(name)
	idx := b.nextCP
	b.nextCP++

	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, nameIdx)
	b.cpEntries = append(b.cpEntries, cpEntry{tag: 7, data: data})
	b.cpMap[key] = idx
	return idx
}

// AddMethodRef adds a CONSTANT_Methodref entry and returns its CP index.
func (b *ClassBuilder) AddMethodRef(className, methodName, descriptor string) uint16 {
	key := "methodref:" + className + "." + methodName + descriptor
	if idx, ok := b.cpMap[key]; ok {
		return idx
	}

	classIdx := b.addClass(className)
	natIdx := b.addNameAndType(methodName, descriptor)

	idx := b.nextCP
	b.nextCP++

	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], classIdx)
	binary.BigEndian.PutUint16(data[2:4], natIdx)
	b.cpEntries = append(b.cpEntries, cpEntry{tag: 10, data: data}) // CONSTANT_Methodref
	b.cpMap[key] = idx
	return idx
}

// AddFieldRef adds a CONSTANT_Fieldref entry and returns its CP index.
func (b *ClassBuilder) AddFieldRef(className, fieldName, descriptor string) uint16 {
	key := "fieldref:" + className + "." + fieldName + descriptor
	if idx, ok := b.cpMap[key]; ok {
		return idx
	}

	classIdx := b.addClass(className)
	natIdx := b.addNameAndType(fieldName, descriptor)

	idx := b.nextCP
	b.nextCP++

	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], classIdx)
	binary.BigEndian.PutUint16(data[2:4], natIdx)
	b.cpEntries = append(b.cpEntries, cpEntry{tag: 9, data: data}) // CONSTANT_Fieldref
	b.cpMap[key] = idx
	return idx
}

// AddStringConst adds a CONSTANT_String entry and returns its CP index.
func (b *ClassBuilder) AddStringConst(s string) uint16 {
	key := "string:" + s
	if idx, ok := b.cpMap[key]; ok {
		return idx
	}

	utf8Idx := b.addUTF8(s)
	idx := b.nextCP
	b.nextCP++

	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, utf8Idx)
	b.cpEntries = append(b.cpEntries, cpEntry{tag: 8, data: data}) // CONSTANT_String
	b.cpMap[key] = idx
	return idx
}

func (b *ClassBuilder) addNameAndType(name, descriptor string) uint16 {
	key := "nat:" + name + ":" + descriptor
	if idx, ok := b.cpMap[key]; ok {
		return idx
	}

	nameIdx := b.addUTF8(name)
	descIdx := b.addUTF8(descriptor)
	idx := b.nextCP
	b.nextCP++

	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:2], nameIdx)
	binary.BigEndian.PutUint16(data[2:4], descIdx)
	b.cpEntries = append(b.cpEntries, cpEntry{tag: 12, data: data}) // CONSTANT_NameAndType
	b.cpMap[key] = idx
	return idx
}
