/*
Copyright (c) 2026 Security Research
*/
package dex2class

import (
	"encoding/binary"
	"fmt"
)

// JVM constant pool tag values.
const (
	cpUTF8       = 1
	cpInteger    = 3
	cpFloat      = 4
	cpLong       = 5
	cpDouble     = 6
	cpClass      = 7
	cpString     = 8
	cpFieldRef   = 9
	cpMethodRef  = 10
	cpIfaceRef   = 11
	cpNameType   = 12
	cpMethodType = 16
)

// JVM bytecode opcodes used in translation.
const (
	jvmNop           = 0x00
	jvmAConstNull    = 0x01
	jvmIConstM1      = 0x02
	jvmIConst0       = 0x03
	jvmIConst1       = 0x04
	jvmIConst2       = 0x05
	jvmIConst3       = 0x06
	jvmIConst4       = 0x07
	jvmIConst5       = 0x08
	jvmLConst0       = 0x09
	jvmLConst1       = 0x0A
	jvmFConst0       = 0x0B
	jvmDConst0       = 0x0E
	jvmBiPush        = 0x10
	jvmSiPush        = 0x11
	jvmLdc           = 0x12
	jvmLdcW          = 0x13
	jvmLdc2W         = 0x14
	jvmILoad         = 0x15
	jvmLLoad         = 0x16
	jvmFLoad         = 0x17
	jvmDLoad         = 0x18
	jvmALoad         = 0x19
	jvmIStore        = 0x36
	jvmLStore        = 0x37
	jvmFStore        = 0x38
	jvmDStore        = 0x39
	jvmAStore        = 0x3A
	jvmDup           = 0x59
	jvmIReturn       = 0xAC
	jvmLReturn       = 0xAD
	jvmFReturn       = 0xAE
	jvmDReturn       = 0xAF
	jvmAReturn       = 0xB0
	jvmReturn        = 0xB1
	jvmGetStatic     = 0xB2
	jvmPutStatic     = 0xB3
	jvmGetField      = 0xB4
	jvmPutField      = 0xB5
	jvmInvokeVirtual = 0xB6
	jvmInvokeSpecial = 0xB7
	jvmInvokeStatic  = 0xB8
	jvmInvokeIface   = 0xB9
	jvmNew           = 0xBB
	jvmNewArray      = 0xBC
	jvmCheckCast     = 0xC0
	jvmInstanceOf    = 0xC1
	jvmMonitorEnter  = 0xC2
	jvmMonitorExit   = 0xC3
	jvmAThrow        = 0xBF
	jvmIfICmpEq      = 0x9F
	jvmIfICmpNe      = 0xA0
	jvmIfICmpLt      = 0xA1
	jvmIfICmpGe      = 0xA2
	jvmIfICmpGt      = 0xA3
	jvmIfICmpLe      = 0xA4
	jvmIfEq          = 0x99
	jvmIfNe          = 0x9A
	jvmIfLt          = 0x9B
	jvmIfGe          = 0x9C
	jvmIfGt          = 0x9D
	jvmIfLe          = 0x9E
	jvmGoto          = 0xA7
	jvmIAdd          = 0x60
	jvmISub          = 0x64
	jvmIMul          = 0x68
	jvmIDiv          = 0x6C
	jvmIRem          = 0x70
	jvmIAnd          = 0x7E
	jvmIOr           = 0x80
	jvmIXor          = 0x82
	jvmIShl          = 0x78
	jvmIShr          = 0x7A
	jvmIUShr         = 0x7C
	jvmINeg          = 0x74
	jvmI2L           = 0x85
	jvmI2F           = 0x86
	jvmI2D           = 0x87
	jvmL2I           = 0x88
	jvmI2B           = 0x91
	jvmI2C           = 0x92
	jvmI2S           = 0x93
	jvmArrayLength   = 0xBE
)

// cpEntry is a constant pool entry.
type cpEntry struct {
	tag  byte
	data []byte
}

// classWriter builds a JVM .class file from scratch.
type classWriter struct {
	pool       []cpEntry
	utf8Cache  map[string]uint16
	classCache map[string]uint16
	ntCache    map[string]uint16
}

// newClassWriter creates a classWriter with the mandatory 0th entry placeholder.
func newClassWriter() *classWriter {
	return &classWriter{
		pool:       []cpEntry{{}}, // index 0 is unused
		utf8Cache:  make(map[string]uint16),
		classCache: make(map[string]uint16),
		ntCache:    make(map[string]uint16),
	}
}

// maxPoolEntries is the JVM constant pool hard limit (indices are u16, index 0 unused).
const maxPoolEntries = 65535

// addUTF8 adds (or deduplicates) a CONSTANT_Utf8_info entry, returns its 1-based index.
// Returns 0 if the pool is already full (SEC: prevents uint16 index wrap on crafted DEX).
func (cw *classWriter) addUTF8(s string) uint16 {
	if idx, ok := cw.utf8Cache[s]; ok {
		return idx
	}
	// SEC: guard against uint16 pool index overflow wrapping to 0 on DEX files with
	// >65535 string literals, which would produce an invalid / corrupt .class file.
	if len(cw.pool) >= maxPoolEntries {
		return 0
	}
	data := make([]byte, 2+len(s))
	binary.BigEndian.PutUint16(data, uint16(len(s)))
	copy(data[2:], s)
	cw.pool = append(cw.pool, cpEntry{tag: cpUTF8, data: data})
	idx := uint16(len(cw.pool) - 1)
	cw.utf8Cache[s] = idx
	return idx
}

// addClass adds a CONSTANT_Class_info entry, returns its 1-based index.
func (cw *classWriter) addClass(name string) uint16 {
	if idx, ok := cw.classCache[name]; ok {
		return idx
	}
	nameIdx := cw.addUTF8(name)
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, nameIdx)
	cw.pool = append(cw.pool, cpEntry{tag: cpClass, data: data})
	idx := uint16(len(cw.pool) - 1)
	cw.classCache[name] = idx
	return idx
}

// addNameAndType adds a CONSTANT_NameAndType_info entry.
func (cw *classWriter) addNameAndType(name, descriptor string) uint16 {
	key := name + ":" + descriptor
	if idx, ok := cw.ntCache[key]; ok {
		return idx
	}
	nameIdx := cw.addUTF8(name)
	descIdx := cw.addUTF8(descriptor)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:], nameIdx)
	binary.BigEndian.PutUint16(data[2:], descIdx)
	cw.pool = append(cw.pool, cpEntry{tag: cpNameType, data: data})
	idx := uint16(len(cw.pool) - 1)
	cw.ntCache[key] = idx
	return idx
}

// addMethodRef adds a CONSTANT_Methodref_info entry.
func (cw *classWriter) addMethodRef(className, name, descriptor string) uint16 {
	classIdx := cw.addClass(className)
	ntIdx := cw.addNameAndType(name, descriptor)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:], classIdx)
	binary.BigEndian.PutUint16(data[2:], ntIdx)
	cw.pool = append(cw.pool, cpEntry{tag: cpMethodRef, data: data})
	return uint16(len(cw.pool) - 1)
}

// addFieldRef adds a CONSTANT_Fieldref_info entry.
func (cw *classWriter) addFieldRef(className, name, descriptor string) uint16 {
	classIdx := cw.addClass(className)
	ntIdx := cw.addNameAndType(name, descriptor)
	data := make([]byte, 4)
	binary.BigEndian.PutUint16(data[0:], classIdx)
	binary.BigEndian.PutUint16(data[2:], ntIdx)
	cw.pool = append(cw.pool, cpEntry{tag: cpFieldRef, data: data})
	return uint16(len(cw.pool) - 1)
}

// addString adds a CONSTANT_String_info entry.
func (cw *classWriter) addString(s string) uint16 {
	utf8Idx := cw.addUTF8(s)
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, utf8Idx)
	cw.pool = append(cw.pool, cpEntry{tag: cpString, data: data})
	return uint16(len(cw.pool) - 1)
}

// addInteger adds a CONSTANT_Integer_info entry.
func (cw *classWriter) addInteger(val int32) uint16 {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, uint32(val))
	cw.pool = append(cw.pool, cpEntry{tag: cpInteger, data: data})
	return uint16(len(cw.pool) - 1)
}

// methodInfo is a translated method ready for writing.
type methodInfo struct {
	accessFlags uint16
	nameIdx     uint16
	descIdx     uint16
	code        []byte // JVM bytecode
	maxStack    uint16
	maxLocals   uint16
}

// fieldInfo is a translated field ready for writing.
type fieldInfo struct {
	accessFlags uint16
	nameIdx     uint16
	descIdx     uint16
	descriptor  string // field type descriptor (e.g., "Ljava/lang/String;")
	cvAttrName  uint16 // ConstantValue attribute name CP index (0 = none)
	cvValueIdx  uint16 // ConstantValue value CP index
}

// buildClassFile assembles the final .class bytes.
func (cw *classWriter) buildClassFile(
	accessFlags uint16,
	thisClass uint16,
	superClass uint16,
	fields []fieldInfo,
	methods []methodInfo,
) []byte {
	// Pre-allocate "Code" attribute name before serializing the constant pool
	codeAttrName := cw.addUTF8("Code")

	var buf []byte

	// Magic number
	buf = appendU4(buf, 0xCAFEBABE)
	// Minor version
	buf = appendU2(buf, 0)
	// Major version (52 = Java 8)
	buf = appendU2(buf, 52)

	// Constant pool count (pool size includes unused entry 0)
	buf = appendU2(buf, uint16(len(cw.pool)))

	// Constant pool entries (skip index 0)
	for i := 1; i < len(cw.pool); i++ {
		e := cw.pool[i]
		buf = append(buf, e.tag)
		buf = append(buf, e.data...)
	}

	// Access flags, this_class, super_class
	buf = appendU2(buf, accessFlags)
	buf = appendU2(buf, thisClass)
	buf = appendU2(buf, superClass)

	// Interfaces count
	buf = appendU2(buf, 0)

	// Fields
	_ = codeAttrName
	buf = appendU2(buf, uint16(len(fields)))
	for _, f := range fields {
		buf = appendU2(buf, f.accessFlags)
		buf = appendU2(buf, f.nameIdx)
		buf = appendU2(buf, f.descIdx)
		if f.cvAttrName != 0 {
			// ConstantValue attribute: name(u2) + length(u4=2) + value_index(u2)
			buf = appendU2(buf, 1) // attributes_count = 1
			buf = appendU2(buf, f.cvAttrName)
			buf = appendU4(buf, 2) // attribute length
			buf = appendU2(buf, f.cvValueIdx)
		} else {
			buf = appendU2(buf, 0) // attributes_count = 0
		}
	}

	// Methods
	buf = appendU2(buf, uint16(len(methods)))
	for _, m := range methods {
		buf = appendU2(buf, m.accessFlags)
		buf = appendU2(buf, m.nameIdx)
		buf = appendU2(buf, m.descIdx)

		if len(m.code) == 0 {
			// abstract/native methods: no Code attribute
			buf = appendU2(buf, 0)
			continue
		}

		// One attribute: Code
		buf = appendU2(buf, 1)
		buf = appendU2(buf, codeAttrName)

		// Code attribute: max_stack(2) + max_locals(2) + code_length(4) + code + exception_table_length(2) + attributes_count(2)
		codeAttrLen := uint32(2 + 2 + 4 + len(m.code) + 2 + 2)
		buf = appendU4(buf, codeAttrLen)
		buf = appendU2(buf, m.maxStack)
		buf = appendU2(buf, m.maxLocals)
		buf = appendU4(buf, uint32(len(m.code)))
		buf = append(buf, m.code...)
		buf = appendU2(buf, 0) // exception_table_length
		buf = appendU2(buf, 0) // code attributes_count
	}

	// Class attributes
	buf = appendU2(buf, 0)

	return buf
}

func appendU2(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendU4(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// dexTypeToInternal converts a DEX type descriptor like "Lcom/example/Foo;" to
// JVM internal class name "com/example/Foo". Returns the input unchanged if
// not an object type.
func dexTypeToInternal(dexType string) string {
	if len(dexType) >= 3 && dexType[0] == 'L' && dexType[len(dexType)-1] == ';' {
		return dexType[1 : len(dexType)-1]
	}
	return dexType
}

// dexTypeToDescriptor converts a DEX type descriptor to a JVM field descriptor.
// DEX uses the same format as JVM for primitives and object types, so for object
// types we keep "Lcom/example/Foo;" as-is (it's already a valid JVM descriptor).
// For primitives (I, Z, B, etc.) it's also the same.
func dexTypeToDescriptor(dexType string) string {
	if dexType == "" {
		return "Ljava/lang/Object;"
	}
	return dexType
}

// syntheticDescriptor generates a synthetic method descriptor when the real
// prototype is unavailable. It produces "()V" as a safe fallback.
func syntheticDescriptor() string {
	return "()V"
}

// resolveMethodDescriptor tries to build a JVM descriptor from DEX proto info.
// Since the current DEX parser doesn't parse proto_ids, we return a fallback.
func resolveMethodDescriptor(methodName string) string {
	if methodName == "<init>" || methodName == "<clinit>" {
		return "()V"
	}
	return syntheticDescriptor()
}

// validClassName validates and fixes a class name for JVM.
func validClassName(name string) string {
	if name == "" {
		return "UnknownClass"
	}
	internal := dexTypeToInternal(name)
	if internal == "" {
		return "UnknownClass"
	}
	return internal
}

// formatClassFileError returns a formatted error for class file building.
func formatClassFileError(className string, msg string, args ...any) error {
	return fmt.Errorf("dex2class: %s: %s", className, fmt.Sprintf(msg, args...))
}
