package decompiler

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/bytecode"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// buildMinimalClassBytes constructs a valid .class file in-memory with the
// given class name and Java major version. The resulting class has no fields,
// no methods, and no attributes beyond what is required. The constant pool
// is hand-crafted to contain:
//
//	#1 = Class          -> #3
//	#2 = Class          -> #4
//	#3 = UTF8           -> className (internal form, e.g. "com/example/Hello")
//	#4 = UTF8           -> "java/lang/Object"
//
// This is the minimum needed for classfile.Parse to succeed.
func buildMinimalClassBytes(className string, majorVersion uint16) []byte {
	var buf []byte

	// Magic number: CAFEBABE
	buf = binary.BigEndian.AppendUint32(buf, 0xCAFEBABE)

	// Minor version: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)

	// Major version
	buf = binary.BigEndian.AppendUint16(buf, majorVersion)

	// Constant pool count: 5 (entries #1..#4, count = max_index + 1)
	buf = binary.BigEndian.AppendUint16(buf, 5)

	// #1: CONSTANT_Class -> name_index = 3
	buf = append(buf, 7) // tag: Class
	buf = binary.BigEndian.AppendUint16(buf, 3)

	// #2: CONSTANT_Class -> name_index = 4
	buf = append(buf, 7) // tag: Class
	buf = binary.BigEndian.AppendUint16(buf, 4)

	// #3: CONSTANT_Utf8 -> className
	buf = append(buf, 1) // tag: UTF8
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(className)))
	buf = append(buf, []byte(className)...)

	// #4: CONSTANT_Utf8 -> "java/lang/Object"
	superName := "java/lang/Object"
	buf = append(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(superName)))
	buf = append(buf, []byte(superName)...)

	// Access flags: ACC_PUBLIC (0x0001) | ACC_SUPER (0x0020)
	buf = binary.BigEndian.AppendUint16(buf, 0x0021)

	// this_class: #1
	buf = binary.BigEndian.AppendUint16(buf, 1)

	// super_class: #2
	buf = binary.BigEndian.AppendUint16(buf, 2)

	// interfaces_count: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)

	// fields_count: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)

	// methods_count: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)

	// attributes_count: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)

	return buf
}

// ---------------------------------------------------------------------------
// Test: invalid magic
// ---------------------------------------------------------------------------

func TestDecompileBytes_InvalidMagic(t *testing.T) {
	dec := &NativeDecompiler{}
	_, err := dec.DecompileBytes([]byte("not a class file at all!"))
	if err == nil {
		t.Fatal("expected error for invalid magic, got nil")
	}

	if !strings.Contains(err.Error(), "magic") {
		t.Errorf("error should mention 'magic', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test: truncated header
// ---------------------------------------------------------------------------

func TestDecompileBytes_TruncatedHeader(t *testing.T) {
	dec := &NativeDecompiler{}

	// Valid CAFEBABE magic but only 2 extra bytes (not enough for version fields).
	_, err := dec.DecompileBytes([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00})
	if err == nil {
		t.Fatal("expected error for truncated class data, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: parse a minimal valid class
// ---------------------------------------------------------------------------

func TestClassFileParse_ValidHeader(t *testing.T) {
	data := buildMinimalClassBytes("com/example/Hello", 52)

	cf, err := classfile.Parse(data)
	if err != nil {
		t.Fatalf("Parse failed on minimal class: %v", err)
	}

	if cf.ClassName() != "com/example/Hello" {
		t.Errorf("ClassName() = %q, want %q", cf.ClassName(), "com/example/Hello")
	}

	if cf.ClassNameDotted() != "com.example.Hello" {
		t.Errorf("ClassNameDotted() = %q, want %q", cf.ClassNameDotted(), "com.example.Hello")
	}

	if cf.SuperClassName() != "java/lang/Object" {
		t.Errorf("SuperClassName() = %q, want %q", cf.SuperClassName(), "java/lang/Object")
	}

	if cf.MajorVersion != 52 {
		t.Errorf("MajorVersion = %d, want 52", cf.MajorVersion)
	}

	if len(cf.Fields) != 0 {
		t.Errorf("Fields count = %d, want 0", len(cf.Fields))
	}

	if len(cf.Methods) != 0 {
		t.Errorf("Methods count = %d, want 0", len(cf.Methods))
	}
}

// ---------------------------------------------------------------------------
// Test: build minimal class and decompile
// ---------------------------------------------------------------------------

func TestBuildMinimalClass(t *testing.T) {
	tests := []struct {
		name         string
		className    string
		majorVersion uint16
		wantVersion  string
		wantClass    string
	}{
		{"Java8", "com/example/Hello", 52, "Java 8", "Hello"},
		{"Java11", "org/test/MyApp", 55, "Java 11", "MyApp"},
		{"Java17", "Hello", 61, "Java 17", "Hello"},
		{"Java21", "com/deep/pkg/Widget", 65, "Java 21", "Widget"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := buildMinimalClassBytes(tt.className, tt.majorVersion)

			cf, err := classfile.Parse(data)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}

			got := cf.JavaVersion()
			if got != tt.wantVersion {
				t.Errorf("JavaVersion() = %q, want %q", got, tt.wantVersion)
			}

			// Decompile the minimal class and check output contains key elements.
			dec := &NativeDecompiler{}
			source, err := dec.DecompileBytes(data)
			if err != nil {
				t.Fatalf("DecompileBytes failed: %v", err)
			}

			if !strings.Contains(source, tt.wantClass) {
				t.Errorf("output missing class name %q:\n%s", tt.wantClass, source)
			}

			if !strings.Contains(source, "Decompiled with unravel") {
				t.Errorf("output missing unravel header:\n%s", source)
			}

			if !strings.Contains(source, tt.wantVersion) {
				t.Errorf("output missing version %q:\n%s", tt.wantVersion, source)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: type descriptor parsing
// ---------------------------------------------------------------------------

func TestTypeDescriptorParsing(t *testing.T) {
	tests := []struct {
		desc       string
		wantParams int
		wantReturn string
	}{
		{"()V", 0, "void"},
		{"(I)I", 1, "int"},
		{"(Ljava/lang/String;)V", 1, "void"},
		{"([B)Ljava/lang/String;", 1, "String"},
		{"(IJ)D", 2, "double"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			params, ret, err := types.ParseMethodDescriptor(tt.desc)
			if err != nil {
				t.Fatalf("ParseMethodDescriptor(%q) error: %v", tt.desc, err)
			}

			if len(params) != tt.wantParams {
				t.Errorf("param count = %d, want %d", len(params), tt.wantParams)
			}

			gotRet := ret.Name()
			if gotRet != tt.wantReturn {
				t.Errorf("return type = %q, want %q", gotRet, tt.wantReturn)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: descriptor to Java source name
// ---------------------------------------------------------------------------

func TestTypeDescriptorToJava(t *testing.T) {
	tests := []struct {
		desc string
		want string
	}{
		{"I", "int"},
		{"Ljava/lang/String;", "String"},
		{"[I", "int[]"},
		{"[[Ljava/lang/Object;", "Object[][]"},
		{"Z", "boolean"},
		{"D", "double"},
		{"[B", "byte[]"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := types.DescriptorToJava(tt.desc)
			if got != tt.want {
				t.Errorf("DescriptorToJava(%q) = %q, want %q", tt.desc, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: opcode String() names
// ---------------------------------------------------------------------------

func TestOpcodeString(t *testing.T) {
	tests := []struct {
		op   bytecode.Opcode
		want string
	}{
		{bytecode.NOP, "nop"},
		{bytecode.ALOAD_0, "aload_0"},
		{bytecode.RETURN, "return"},
		{bytecode.INVOKEVIRTUAL, "invokevirtual"},
		{bytecode.INVOKESPECIAL, "invokespecial"},
		{bytecode.INVOKESTATIC, "invokestatic"},
		{bytecode.GETSTATIC, "getstatic"},
		{bytecode.LDC, "ldc"},
		{bytecode.ICONST_0, "iconst_0"},
		{bytecode.GOTO, "goto"},
		{bytecode.NEW, "new"},
		{bytecode.ATHROW, "athrow"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.op.String()
			if got != tt.want {
				t.Errorf("Opcode(%d).String() = %q, want %q", tt.op, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: opcode lookup
// ---------------------------------------------------------------------------

func TestOpcodeLookup(t *testing.T) {
	info, err := bytecode.LookupOpcode(0x00) // NOP
	if err != nil {
		t.Fatalf("LookupOpcode(0x00) error: %v", err)
	}

	if info.Name != "nop" {
		t.Errorf("LookupOpcode(0x00).Name = %q, want %q", info.Name, "nop")
	}

	// Unknown opcode should return error.
	_, err = bytecode.LookupOpcode(0xFE)
	if err == nil {
		t.Error("expected error for unknown opcode 0xFE, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test: OpcodeInfo helper methods
// ---------------------------------------------------------------------------

func TestOpcodeInfoHelpers(t *testing.T) {
	t.Run("IsJump", func(t *testing.T) {
		info := bytecode.LookupOp(bytecode.GOTO)
		if info == nil {
			t.Fatal("GOTO not found")
		}

		if !info.IsJump() {
			t.Error("GOTO should be a jump")
		}

		info2 := bytecode.LookupOp(bytecode.NOP)
		if info2.IsJump() {
			t.Error("NOP should not be a jump")
		}
	})

	t.Run("IsReturn", func(t *testing.T) {
		info := bytecode.LookupOp(bytecode.RETURN)
		if !info.IsReturn() {
			t.Error("RETURN should be a return")
		}

		info2 := bytecode.LookupOp(bytecode.ALOAD_0)
		if info2.IsReturn() {
			t.Error("ALOAD_0 should not be a return")
		}
	})

	t.Run("IsStore", func(t *testing.T) {
		info := bytecode.LookupOp(bytecode.ISTORE)
		if !info.IsStore() {
			t.Error("ISTORE should be a store")
		}
	})

	t.Run("IsLoad", func(t *testing.T) {
		info := bytecode.LookupOp(bytecode.ALOAD_0)
		if !info.IsLoad() {
			t.Error("ALOAD_0 should be a load")
		}
	})

	t.Run("IsInvoke", func(t *testing.T) {
		info := bytecode.LookupOp(bytecode.INVOKEVIRTUAL)
		if !info.IsInvoke() {
			t.Error("INVOKEVIRTUAL should be an invoke")
		}
	})
}

// ---------------------------------------------------------------------------
// Test: decompile empty class output structure
// ---------------------------------------------------------------------------

func TestDecompileBytes_EmptyClass(t *testing.T) {
	data := buildMinimalClassBytes("com/example/Empty", 52)
	dec := &NativeDecompiler{}

	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}

	// Should have package declaration.
	if !strings.Contains(source, "package com.example;") {
		t.Errorf("missing package declaration:\n%s", source)
	}

	// Should have class declaration.
	if !strings.Contains(source, "class Empty") {
		t.Errorf("missing class declaration:\n%s", source)
	}

	// Should end with closing brace.
	trimmed := strings.TrimSpace(source)
	if !strings.HasSuffix(trimmed, "}") {
		t.Errorf("output should end with '}', got:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// Test: class without package (default package)
// ---------------------------------------------------------------------------

func TestDecompileBytes_DefaultPackage(t *testing.T) {
	data := buildMinimalClassBytes("HelloWorld", 52)
	dec := &NativeDecompiler{}

	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}

	// Should NOT have a package declaration.
	if strings.Contains(source, "package ") {
		t.Errorf("default-package class should not have package declaration:\n%s", source)
	}

	if !strings.Contains(source, "class HelloWorld") {
		t.Errorf("missing class declaration:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// Test: ParseFieldDescriptor for various types
// ---------------------------------------------------------------------------

func TestParseFieldDescriptor(t *testing.T) {
	tests := []struct {
		desc      string
		wantName  string
		wantIsObj bool
	}{
		{"I", "int", false},
		{"J", "long", false},
		{"Z", "boolean", false},
		{"Ljava/lang/String;", "String", true},
		{"[I", "int[]", true},
		{"[[D", "double[][]", true},
		{"[Ljava/lang/Object;", "Object[]", true},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			jt, err := types.ParseFieldDescriptor(tt.desc)
			if err != nil {
				t.Fatalf("ParseFieldDescriptor(%q) error: %v", tt.desc, err)
			}

			if jt.Name() != tt.wantName {
				t.Errorf("Name() = %q, want %q", jt.Name(), tt.wantName)
			}

			if jt.IsObject() != tt.wantIsObj {
				t.Errorf("IsObject() = %v, want %v", jt.IsObject(), tt.wantIsObj)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test: StackCategory for primitives
// ---------------------------------------------------------------------------

func TestStackCategory(t *testing.T) {
	if types.TypeInt.StackCategory() != 1 {
		t.Error("int should be category 1")
	}

	if types.TypeLong.StackCategory() != 2 {
		t.Error("long should be category 2")
	}

	if types.TypeDouble.StackCategory() != 2 {
		t.Error("double should be category 2")
	}

	if types.TypeVoid.StackCategory() != 0 {
		t.Error("void should be category 0")
	}

	if types.TypeFloat.StackCategory() != 1 {
		t.Error("float should be category 1")
	}
}

// ---------------------------------------------------------------------------
// Test: indentBlock helper
// ---------------------------------------------------------------------------

func TestIndentBlock(t *testing.T) {
	input := "line1\nline2\n"
	got := indentBlock(input, 1)

	if !strings.Contains(got, "    line1") {
		t.Errorf("expected indented line1, got:\n%s", got)
	}

	if !strings.Contains(got, "    line2") {
		t.Errorf("expected indented line2, got:\n%s", got)
	}

	// Empty string should return empty.
	if indentBlock("", 2) != "" {
		t.Error("indentBlock of empty string should be empty")
	}
}

// ---------------------------------------------------------------------------
// Test: stripTrailingVoidReturn
// ---------------------------------------------------------------------------

func TestStripTrailingVoidReturn(t *testing.T) {
	t.Run("removes trailing void return", func(t *testing.T) {
		stmts := stripTrailingVoidReturn(nil)
		if stmts != nil {
			t.Error("nil input should return nil")
		}
	})
}

// ---------------------------------------------------------------------------
// Test: CountMethodParams
// ---------------------------------------------------------------------------

func TestCountMethodParams(t *testing.T) {
	count, slots := types.CountMethodParams("(IJ)V")
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	// int=1 slot, long=2 slots = 3 total
	if slots != 3 {
		t.Errorf("slots = %d, want 3", slots)
	}

	count2, slots2 := types.CountMethodParams("()V")
	if count2 != 0 || slots2 != 0 {
		t.Errorf("empty params: count=%d slots=%d, want 0,0", count2, slots2)
	}
}
