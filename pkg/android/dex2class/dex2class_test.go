/*
Copyright (c) 2026 Security Research
*/
package dex2class

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"
)

const (
	headerSize  = 0x70
	endianConst = 0x12345678
	noIndex     = 0xFFFFFFFF
)

// buildMinimalDEX creates a bare-minimum DEX with just a header (no classes).
func buildMinimalDEX() []byte {
	buf := make([]byte, headerSize)
	copy(buf[0:], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(buf[32:], headerSize)
	binary.LittleEndian.PutUint32(buf[36:], headerSize)
	binary.LittleEndian.PutUint32(buf[40:], endianConst)
	return buf
}

// buildDEXWithClass creates a DEX file with one class that has:
// - class name "Lcom/example/Hello;"
// - superclass "Ljava/lang/Object;"
// - one direct method (constructor): return-void
// - one instance field
func buildDEXWithClass() []byte {
	// Strings:
	//  0: "Lcom/example/Hello;"
	//  1: "Ljava/lang/Object;"
	//  2: "<init>"
	//  3: "value"
	//  4: "I"    (int type)
	//  5: "Hello.java"

	strings := []string{
		"Lcom/example/Hello;",
		"Ljava/lang/Object;",
		"<init>",
		"value",
		"I",
		"Hello.java",
	}

	// Layout plan:
	// [0x00..0x70)   header
	// [0x70..0x88)   string_id offsets: 6 x uint32 = 24 bytes
	// [0x88..0x98)   type_id indices: 4 x uint32 = 16 bytes  (types 0-3: Lcom/example/Hello;, Ljava/lang/Object;, <init>, I)
	//   Actually type_ids should reference string indices for descriptors
	//   We need types: 0 -> string 0 (Lcom/example/Hello;), 1 -> string 1 (Ljava/lang/Object;), 2 -> string 4 (I)
	// [0x98..0xA4)   proto_id: 1 x 12 bytes (shortyIdx, returnTypeIdx, parametersOff)
	// [0xA4..0xAC)   method_id: 1 x 8 bytes
	// [0xAC..0xB4)   field_id: 1 x 8 bytes
	// [0xB4..0xD4)   class_def: 1 x 32 bytes
	// [0xD4..0xE8)   class_data_item (~20 bytes, ULEB128 encoded)
	// [0xE8..0xFC)   code_item: 16-byte header + 2-byte insns (return-void = 0x0E00)
	// [0xFC..)       string data

	classDataOff := uint32(0xD4)
	codeItemOff := uint32(0xE8)
	stringDataOff := uint32(0xFC)

	// Build string data
	var strData []byte
	strOffsets := make([]uint32, len(strings))
	for i, s := range strings {
		strOffsets[i] = stringDataOff + uint32(len(strData))
		strData = append(strData, byte(len(s))) // ULEB128 length (all < 128)
		strData = append(strData, []byte(s)...)
		strData = append(strData, 0) // null terminator
	}

	totalSize := int(stringDataOff) + len(strData)
	buf := make([]byte, totalSize)

	// Header
	copy(buf[0:], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(buf[32:], uint32(totalSize))
	binary.LittleEndian.PutUint32(buf[36:], headerSize)
	binary.LittleEndian.PutUint32(buf[40:], endianConst)

	// StringIDsSize=6, StringIDsOff=0x70
	binary.LittleEndian.PutUint32(buf[56:], uint32(len(strings)))
	binary.LittleEndian.PutUint32(buf[60:], 0x70)

	// TypeIDsSize=3, TypeIDsOff=0x88
	binary.LittleEndian.PutUint32(buf[64:], 3)
	binary.LittleEndian.PutUint32(buf[68:], 0x88)

	// ProtoIDsSize=1, ProtoIDsOff=0x98
	binary.LittleEndian.PutUint32(buf[72:], 1)
	binary.LittleEndian.PutUint32(buf[76:], 0x98)

	// FieldIDsSize=1, FieldIDsOff=0xAC
	binary.LittleEndian.PutUint32(buf[80:], 1)
	binary.LittleEndian.PutUint32(buf[84:], 0xAC)

	// MethodIDsSize=1, MethodIDsOff=0xA4
	binary.LittleEndian.PutUint32(buf[88:], 1)
	binary.LittleEndian.PutUint32(buf[92:], 0xA4)

	// ClassDefsSize=1, ClassDefsOff=0xB4
	binary.LittleEndian.PutUint32(buf[96:], 1)
	binary.LittleEndian.PutUint32(buf[100:], 0xB4)

	// String ID offsets at 0x70
	for i, off := range strOffsets {
		binary.LittleEndian.PutUint32(buf[0x70+i*4:], off)
	}

	// Type IDs at 0x88: [0=str0(Lcom/example/Hello;), 1=str1(Ljava/lang/Object;), 2=str4(I)]
	binary.LittleEndian.PutUint32(buf[0x88:], 0) // type 0 -> string 0
	binary.LittleEndian.PutUint32(buf[0x8C:], 1) // type 1 -> string 1
	binary.LittleEndian.PutUint32(buf[0x90:], 4) // type 2 -> string 4 ("I")

	// Proto ID at 0x98: shortyIdx=4("I"->actually we need "V" for void), returnTypeIdx=2(I type), parametersOff=0
	// For simplicity, use shortyIdx=4, returnTypeIdx for void is not available, so just use type 2
	binary.LittleEndian.PutUint32(buf[0x98:], 4) // shorty_idx (reuse string "I")
	binary.LittleEndian.PutUint32(buf[0x9C:], 2) // return_type_idx (type 2 = "I", but really should be V)
	binary.LittleEndian.PutUint32(buf[0xA0:], 0) // parameters_off = 0 (no params)

	// Method ID at 0xA4: classIdx=0(Hello), protoIdx=0, nameIdx=2("<init>")
	binary.LittleEndian.PutUint16(buf[0xA4:], 0)
	binary.LittleEndian.PutUint16(buf[0xA6:], 0)
	binary.LittleEndian.PutUint32(buf[0xA8:], 2)

	// Field ID at 0xAC: classIdx=0(Hello), typeIdx=2(I), nameIdx=3("value")
	binary.LittleEndian.PutUint16(buf[0xAC:], 0)
	binary.LittleEndian.PutUint16(buf[0xAE:], 2)
	binary.LittleEndian.PutUint32(buf[0xB0:], 3)

	// Class def at 0xB4
	binary.LittleEndian.PutUint32(buf[0xB4:], 0)            // typeIdx = 0 (Hello)
	binary.LittleEndian.PutUint32(buf[0xB8:], 0x0001)       // accessFlags = PUBLIC
	binary.LittleEndian.PutUint32(buf[0xBC:], 1)            // superclassIdx = 1 (Object)
	binary.LittleEndian.PutUint32(buf[0xC0:], 0)            // interfacesOff
	binary.LittleEndian.PutUint32(buf[0xC4:], 5)            // sourceFileIdx = 5 (Hello.java)
	binary.LittleEndian.PutUint32(buf[0xC8:], 0)            // annotationsOff
	binary.LittleEndian.PutUint32(buf[0xCC:], classDataOff) // classDataOff
	binary.LittleEndian.PutUint32(buf[0xD0:], 0)            // staticValuesOff

	// Class data item at 0xD4 (ULEB128 encoded)
	// static_fields_size=0, instance_fields_size=1, direct_methods_size=1, virtual_methods_size=0
	cdPos := int(classDataOff)
	buf[cdPos] = 0 // static_fields_size = 0
	cdPos++
	buf[cdPos] = 1 // instance_fields_size = 1
	cdPos++
	buf[cdPos] = 1 // direct_methods_size = 1
	cdPos++
	buf[cdPos] = 0 // virtual_methods_size = 0
	cdPos++

	// instance field: field_idx_diff=0, access_flags=0 (default/package-private)
	buf[cdPos] = 0 // field_idx_diff = 0
	cdPos++
	buf[cdPos] = 0 // access_flags = 0
	cdPos++

	// direct method: method_idx_diff=0, access_flags=0x10001 (PUBLIC|CONSTRUCTOR)
	buf[cdPos] = 0 // method_idx_diff = 0
	cdPos++
	// access_flags = 0x10001 = PUBLIC|CONSTRUCTOR in ULEB128
	// 0x10001 = 10000000000000001 in binary
	// ULEB128: 0x01, 0x80, 0x04
	buf[cdPos] = 0x81 // 0000001 | continuation
	cdPos++
	buf[cdPos] = 0x80 // 0000000 | continuation
	cdPos++
	buf[cdPos] = 0x04 // 0000100 | no continuation
	cdPos++
	// code_off = codeItemOff (ULEB128)
	writeULEB128(buf, &cdPos, codeItemOff)

	// Code item at 0xE8
	ciPos := int(codeItemOff)
	binary.LittleEndian.PutUint16(buf[ciPos:], 1)    // registers_size = 1
	binary.LittleEndian.PutUint16(buf[ciPos+2:], 1)  // ins_size = 1
	binary.LittleEndian.PutUint16(buf[ciPos+4:], 0)  // outs_size = 0
	binary.LittleEndian.PutUint16(buf[ciPos+6:], 0)  // tries_size = 0
	binary.LittleEndian.PutUint32(buf[ciPos+8:], 0)  // debug_info_off = 0
	binary.LittleEndian.PutUint32(buf[ciPos+12:], 1) // insns_size = 1 (one 16-bit unit)
	// return-void = opcode 0x0e, format 10x
	binary.LittleEndian.PutUint16(buf[ciPos+16:], 0x000e) // return-void

	// String data
	copy(buf[stringDataOff:], strData)

	return buf
}

// writeULEB128 writes a ULEB128 value into buf at *pos and advances pos.
func writeULEB128(buf []byte, pos *int, val uint32) {
	for {
		b := byte(val & 0x7F)
		val >>= 7
		if val != 0 {
			b |= 0x80
		}
		buf[*pos] = b
		*pos++
		if val == 0 {
			break
		}
	}
}

func TestTranslateNoRaw_MinimalDEX(t *testing.T) {
	data := buildMinimalDEX()
	r := bytes.NewReader(data)

	dexFile, err := dex.Parse(r, int64(len(data)))
	if err != nil {
		t.Fatalf("dex.Parse failed: %v", err)
	}

	tr := &Translator{}
	result, err := tr.TranslateNoRaw(dexFile)
	if err != nil {
		t.Fatalf("Translate failed: %v", err)
	}

	if len(result.ClassFiles) != 0 {
		t.Errorf("expected 0 class files for minimal DEX, got %d", len(result.ClassFiles))
	}
}

func TestTranslateNoRaw_ClassWithNoCode(t *testing.T) {
	// Use the buildPopulatedDEX from dex package pattern:
	// create a DEX with a class that has ClassDataOff=0 (no methods/fields data)
	data := buildMinimalDEXWithClass()
	r := bytes.NewReader(data)

	dexFile, err := dex.Parse(r, int64(len(data)))
	if err != nil {
		t.Fatalf("dex.Parse failed: %v", err)
	}

	if len(dexFile.Classes) != 1 {
		t.Fatalf("expected 1 class, got %d", len(dexFile.Classes))
	}

	tr := &Translator{}
	result, err := tr.TranslateNoRaw(dexFile)
	if err != nil {
		t.Fatalf("Translate failed: %v", err)
	}

	if len(result.ClassFiles) != 1 {
		t.Fatalf("expected 1 class file, got %d", len(result.ClassFiles))
	}

	co := result.ClassFiles[0]
	if co.ClassName != "com/example/Test" {
		t.Errorf("class name = %q, want %q", co.ClassName, "com/example/Test")
	}

	// Verify CAFEBABE magic
	if len(co.Data) < 4 {
		t.Fatalf("class data too short: %d bytes", len(co.Data))
	}
	magic := binary.BigEndian.Uint32(co.Data[:4])
	if magic != 0xCAFEBABE {
		t.Errorf("magic = 0x%08X, want 0xCAFEBABE", magic)
	}

	// Parse with the Java classfile parser
	cf, err := classfile.Parse(co.Data)
	if err != nil {
		t.Fatalf("classfile.Parse failed: %v", err)
	}

	if cf.MajorVersion != 52 {
		t.Errorf("major version = %d, want 52 (Java 8)", cf.MajorVersion)
	}

	parsedName := cf.ClassName()
	if parsedName != "com/example/Test" {
		t.Errorf("parsed class name = %q, want %q", parsedName, "com/example/Test")
	}
}

func TestTranslate_WithBytecode(t *testing.T) {
	data := buildDEXWithClass()
	r := bytes.NewReader(data)

	dexFile, err := dex.Parse(r, int64(len(data)))
	if err != nil {
		t.Fatalf("dex.Parse failed: %v", err)
	}

	if len(dexFile.Classes) != 1 {
		t.Fatalf("expected 1 class, got %d", len(dexFile.Classes))
	}

	tr := &Translator{}
	result, err := tr.Translate(dexFile, data)
	if err != nil {
		t.Fatalf("Translate failed: %v", err)
	}

	if len(result.Errors) > 0 {
		t.Logf("translation errors: %v", result.Errors)
	}

	if len(result.ClassFiles) != 1 {
		t.Fatalf("expected 1 class file, got %d", len(result.ClassFiles))
	}

	co := result.ClassFiles[0]
	t.Logf("class: %s, methods: %d, fields: %d, bytes: %d", co.ClassName, co.Methods, co.Fields, len(co.Data))

	// Verify CAFEBABE magic
	if len(co.Data) < 4 {
		t.Fatalf("class data too short: %d bytes", len(co.Data))
	}
	magic := binary.BigEndian.Uint32(co.Data[:4])
	if magic != 0xCAFEBABE {
		t.Errorf("magic = 0x%08X, want 0xCAFEBABE", magic)
	}

	// Parse with Java classfile parser
	cf, err := classfile.Parse(co.Data)
	if err != nil {
		t.Fatalf("classfile.Parse failed: %v", err)
	}

	if cf.ClassName() != "com/example/Hello" {
		t.Errorf("parsed class name = %q, want %q", cf.ClassName(), "com/example/Hello")
	}

	if cf.SuperClassName() != "java/lang/Object" {
		t.Errorf("parsed super class = %q, want %q", cf.SuperClassName(), "java/lang/Object")
	}

	if co.Methods != 1 {
		t.Errorf("methods = %d, want 1", co.Methods)
	}

	if co.Fields != 1 {
		t.Errorf("fields = %d, want 1", co.Fields)
	}
}

func TestClassWriter_ConstantPoolDedup(t *testing.T) {
	cw := newClassWriter()

	idx1 := cw.addUTF8("hello")
	idx2 := cw.addUTF8("hello")
	idx3 := cw.addUTF8("world")

	if idx1 != idx2 {
		t.Errorf("UTF8 dedup failed: idx1=%d, idx2=%d", idx1, idx2)
	}
	if idx1 == idx3 {
		t.Errorf("different strings should have different indices")
	}

	cls1 := cw.addClass("com/example/Foo")
	cls2 := cw.addClass("com/example/Foo")
	cls3 := cw.addClass("com/example/Bar")

	if cls1 != cls2 {
		t.Errorf("Class dedup failed: cls1=%d, cls2=%d", cls1, cls2)
	}
	if cls1 == cls3 {
		t.Errorf("different classes should have different indices")
	}
}

func TestDexTypeToInternal(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Lcom/example/Foo;", "com/example/Foo"},
		{"Ljava/lang/Object;", "java/lang/Object"},
		{"I", "I"},
		{"", ""},
		{"L;", "L;"}, // invalid type, returned as-is
	}

	for _, tt := range tests {
		got := dexTypeToInternal(tt.input)
		if got != tt.want {
			t.Errorf("dexTypeToInternal(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEmitIntConst(t *testing.T) {
	tests := []struct {
		val      int32
		wantLen  int
		wantByte byte // first byte of emitted code
	}{
		{0, 1, jvmIConst0},
		{1, 1, jvmIConst0 + 1},
		{5, 1, jvmIConst0 + 5},
		{-1, 1, jvmIConst0 - 1}, // iconst_m1
		{10, 2, jvmBiPush},
		{127, 2, jvmBiPush},
		{-128, 2, jvmBiPush},
		{1000, 3, jvmSiPush},
	}

	for _, tt := range tests {
		cw := newClassWriter()
		conv := &converter{cw: cw}
		conv.emitIntConst(tt.val)

		if len(conv.code) < tt.wantLen {
			t.Errorf("emitIntConst(%d): code length = %d, want >= %d", tt.val, len(conv.code), tt.wantLen)
			continue
		}

		if conv.code[0] != tt.wantByte {
			t.Errorf("emitIntConst(%d): first byte = 0x%02X, want 0x%02X", tt.val, conv.code[0], tt.wantByte)
		}
	}
}

func TestConverter_ReturnVoid(t *testing.T) {
	cw := newClassWriter()
	dexFile := &dex.DexFile{}
	conv := newConverter(cw, dexFile)

	// return-void = 0x0E, format 10x
	insns := []byte{0x0E, 0x00}
	code := conv.translate(insns, 1)

	if len(code) != 1 || code[0] != jvmReturn {
		t.Errorf("return-void translation: got %v, want [0x%02X]", code, jvmReturn)
	}
}

func TestConverter_ConstAndReturn(t *testing.T) {
	cw := newClassWriter()
	dexFile := &dex.DexFile{}
	conv := newConverter(cw, dexFile)

	// const/4 v0, #3 (opcode 0x12, format 11n: vA=0, B=3)
	// return v0 (opcode 0x0F, format 11x: vAA=0)
	insns := []byte{
		0x12, 0x30, // const/4 v0, #3  (A=0, B=3 -> nibble layout: B=3<<4 | A=0 in high byte)
		0x0F, 0x00, // return v0
	}
	code := conv.translate(insns, 1)

	// Expected: iconst_3, istore 0, iload 0, ireturn
	if len(code) < 4 {
		t.Fatalf("expected >= 4 bytes, got %d: %v", len(code), code)
	}

	// First byte should be iconst_3 (0x06)
	if code[0] != jvmIConst0+3 {
		t.Errorf("expected iconst_3 (0x%02X), got 0x%02X", jvmIConst0+3, code[0])
	}
}

// buildMinimalDEXWithClass creates a DEX with one class that has no class_data
// (ClassDataOff=0), so it produces a class with no methods/fields.
func buildMinimalDEXWithClass() []byte {
	str0 := "Lcom/example/Test;"
	str1 := "Ljava/lang/Object;"

	stringDataOff := uint32(0xA0)

	var strData []byte
	str0Off := stringDataOff
	strData = append(strData, byte(len(str0)))
	strData = append(strData, []byte(str0)...)
	strData = append(strData, 0)

	str1Off := stringDataOff + uint32(len(strData))
	strData = append(strData, byte(len(str1)))
	strData = append(strData, []byte(str1)...)
	strData = append(strData, 0)

	totalSize := int(stringDataOff) + len(strData)
	buf := make([]byte, totalSize)

	// Header
	copy(buf[0:], []byte("dex\n035\x00"))
	binary.LittleEndian.PutUint32(buf[32:], uint32(totalSize))
	binary.LittleEndian.PutUint32(buf[36:], headerSize)
	binary.LittleEndian.PutUint32(buf[40:], endianConst)

	// StringIDsSize=2, StringIDsOff=0x70
	binary.LittleEndian.PutUint32(buf[56:], 2)
	binary.LittleEndian.PutUint32(buf[60:], 0x70)

	// TypeIDsSize=2, TypeIDsOff=0x78
	binary.LittleEndian.PutUint32(buf[64:], 2)
	binary.LittleEndian.PutUint32(buf[68:], 0x78)

	// ClassDefsSize=1, ClassDefsOff=0x80
	binary.LittleEndian.PutUint32(buf[96:], 1)
	binary.LittleEndian.PutUint32(buf[100:], 0x80)

	// String ID offsets at 0x70
	binary.LittleEndian.PutUint32(buf[0x70:], str0Off)
	binary.LittleEndian.PutUint32(buf[0x74:], str1Off)

	// Type IDs at 0x78
	binary.LittleEndian.PutUint32(buf[0x78:], 0) // type 0 -> string 0
	binary.LittleEndian.PutUint32(buf[0x7C:], 1) // type 1 -> string 1

	// Class def at 0x80
	binary.LittleEndian.PutUint32(buf[0x80:], 0)       // typeIdx = 0 (Test)
	binary.LittleEndian.PutUint32(buf[0x84:], 0x0001)  // accessFlags = PUBLIC
	binary.LittleEndian.PutUint32(buf[0x88:], 1)       // superclassIdx = 1 (Object)
	binary.LittleEndian.PutUint32(buf[0x8C:], 0)       // interfacesOff
	binary.LittleEndian.PutUint32(buf[0x90:], noIndex) // sourceFileIdx
	binary.LittleEndian.PutUint32(buf[0x94:], 0)       // annotationsOff
	binary.LittleEndian.PutUint32(buf[0x98:], 0)       // classDataOff = 0 (no code)
	binary.LittleEndian.PutUint32(buf[0x9C:], 0)       // staticValuesOff

	// String data
	copy(buf[stringDataOff:], strData)

	return buf
}
