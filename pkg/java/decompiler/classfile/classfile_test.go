/*
Copyright (c) 2026 Security Research
*/
package classfile

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Minimal class-file builder
//
// Layout (big-endian):
//   magic(4) minor(2) major(2) cp_count(2) [cp entries] access(2) this(2)
//   super(2) iface_count(2) field_count(2) method_count(2) attr_count(2)
//
// Constant pool layout used in helpers below (1-based):
//   #1  UTF8  "java/lang/Object"      – used as superclass name
//   #2  Class #1                      – superclass class ref
//   #3  UTF8  "<class-name>"          – thisClass name (e.g. "com/example/Foo")
//   #4  Class #3                      – thisClass class ref
//   (extra entries appended as needed)
// ---------------------------------------------------------------------------

func u2(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }
func u4(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func utf8Entry(s string) []byte {
	b := []byte{0x01} // TagUTF8
	b = append(b, u2(uint16(len(s)))...)
	b = append(b, []byte(s)...)
	return b
}

func classEntry(nameIdx uint16) []byte {
	return append([]byte{0x07}, u2(nameIdx)...)
}

// buildClass constructs a minimal valid class file byte slice.
//
// className   – internal form, e.g. "com/example/Foo"
// superName   – internal form; "" means java/lang/Object (SuperClass=0)
// majorVer    – e.g. 52 for Java 8
// accessFlags – AccessFlags value for the class
// extraCP     – additional raw constant-pool bytes appended after the base 4 entries;
//
//	caller is responsible for updating cpCount accordingly
//
// ifaces      – CP indices of interface Class entries (in extra CP, 1-based)
func buildClass(
	className string,
	superName string,
	majorVer uint16,
	accessFlags AccessFlags,
	extraCP []byte,
	extraCPCount uint16, // number of *extra* CP entries
	ifaces []uint16,
	fields [][]byte,
	methods [][]byte,
) []byte {
	// Base CP:  #1=UTF8(superName or "java/lang/Object"), #2=Class(#1),
	//           #3=UTF8(className), #4=Class(#3)
	resolvedSuper := superName
	if resolvedSuper == "" {
		resolvedSuper = "java/lang/Object"
	}

	cp := utf8Entry(resolvedSuper)           // #1
	cp = append(cp, classEntry(1)...)        // #2
	cp = append(cp, utf8Entry(className)...) // #3
	cp = append(cp, classEntry(3)...)        // #4
	cp = append(cp, extraCP...)

	cpCount := uint16(4) + extraCPCount + 1 // +1 because cp_count = max_index+1

	var buf []byte
	buf = append(buf, u4(0xCAFEBABE)...)
	buf = append(buf, u2(0)...)        // minor
	buf = append(buf, u2(majorVer)...) // major
	buf = append(buf, u2(cpCount)...)
	buf = append(buf, cp...)
	buf = append(buf, u2(uint16(accessFlags))...)
	buf = append(buf, u2(4)...) // this_class = #4
	if superName == "" {
		buf = append(buf, u2(0)...) // super_class = 0 (java.lang.Object)
	} else {
		buf = append(buf, u2(2)...) // super_class = #2
	}

	// interfaces
	buf = append(buf, u2(uint16(len(ifaces)))...)
	for _, idx := range ifaces {
		buf = append(buf, u2(idx)...)
	}

	// fields
	buf = append(buf, u2(uint16(len(fields)))...)
	for _, f := range fields {
		buf = append(buf, f...)
	}

	// methods
	buf = append(buf, u2(uint16(len(methods)))...)
	for _, m := range methods {
		buf = append(buf, m...)
	}

	// class attributes
	buf = append(buf, u2(0)...)

	return buf
}

// buildMember builds a minimal field_info / method_info:
//
//	access(2) nameIdx(2) descIdx(2) attrCount(2)=0
func buildMember(access AccessFlags, nameIdx, descIdx uint16) []byte {
	b := u2(uint16(access))
	b = append(b, u2(nameIdx)...)
	b = append(b, u2(descIdx)...)
	b = append(b, u2(0)...) // 0 attributes
	return b
}

// ---------------------------------------------------------------------------
// Tests: Parse – error paths
// ---------------------------------------------------------------------------

func TestParse_ErrorPaths(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "nil input",
			data:    nil,
			wantErr: "read magic",
		},
		{
			name:    "too short for magic",
			data:    []byte{0xCA, 0xFE},
			wantErr: "read magic",
		},
		{
			name:    "bad magic",
			data:    append(u4(0xDEADBEEF), make([]byte, 20)...),
			wantErr: "invalid class file magic",
		},
		{
			name:    "truncated after magic",
			data:    u4(0xCAFEBABE),
			wantErr: "read minor_version",
		},
		{
			name:    "truncated after minor",
			data:    append(u4(0xCAFEBABE), u2(0)...),
			wantErr: "read major_version",
		},
		{
			name:    "truncated after major (no cp_count)",
			data:    append(append(u4(0xCAFEBABE), u2(0)...), u2(52)...),
			wantErr: "read constant_pool_count",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Parse – happy path + method inspection
// ---------------------------------------------------------------------------

func TestParse_MinimalClass(t *testing.T) {
	// Simplest possible class: no super, no interfaces, no fields, no methods.
	data := buildClass("com/example/Foo", "", 52, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if got := cf.ClassName(); got != "com/example/Foo" {
		t.Errorf("ClassName = %q, want %q", got, "com/example/Foo")
	}
	if got := cf.ClassNameDotted(); got != "com.example.Foo" {
		t.Errorf("ClassNameDotted = %q, want %q", got, "com.example.Foo")
	}
	if got := cf.SuperClassName(); got != "" {
		t.Errorf("SuperClassName = %q, want empty (no super)", got)
	}
	if cf.MajorVersion != 52 {
		t.Errorf("MajorVersion = %d, want 52", cf.MajorVersion)
	}
}

func TestParse_WithSuperClass(t *testing.T) {
	data := buildClass("com/example/Child", "com/example/Parent", 55, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if got := cf.SuperClassName(); got != "com/example/Parent" {
		t.Errorf("SuperClassName = %q, want %q", got, "com/example/Parent")
	}
}

func TestParse_WithFieldAndMethod(t *testing.T) {
	// Extra CP entries (1-based starting at #5):
	//   #5  UTF8 "myField"
	//   #6  UTF8 "I"
	//   #7  UTF8 "myMethod"
	//   #8  UTF8 "(I)V"
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("myField")...)  // #5
	extraCP = append(extraCP, utf8Entry("I")...)        // #6
	extraCP = append(extraCP, utf8Entry("myMethod")...) // #7
	extraCP = append(extraCP, utf8Entry("(I)V")...)     // #8

	field := buildMember(AccPublic|AccStatic, 5, 6)
	method := buildMember(AccPublic, 7, 8)

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 4, nil,
		[][]byte{field}, [][]byte{method})
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cf.Fields) != 1 {
		t.Fatalf("expected 1 field, got %d", len(cf.Fields))
	}
	f := cf.Fields[0]
	if f.Name != "myField" {
		t.Errorf("field.Name = %q, want %q", f.Name, "myField")
	}
	if f.Descriptor != "I" {
		t.Errorf("field.Descriptor = %q, want %q", f.Descriptor, "I")
	}
	if !f.IsStatic() {
		t.Error("expected field to be static")
	}
	if f.IsFinal() {
		t.Error("expected field not to be final")
	}
	// Signature falls back to descriptor when no Signature attribute
	if got := f.Signature(); got != "I" {
		t.Errorf("field.Signature() = %q, want %q", got, "I")
	}
	// ConstantValueIndex = 0 when absent
	if got := f.ConstantValueIndex(); got != 0 {
		t.Errorf("field.ConstantValueIndex() = %d, want 0", got)
	}

	if len(cf.Methods) != 1 {
		t.Fatalf("expected 1 method, got %d", len(cf.Methods))
	}
	m := cf.Methods[0]
	if m.Name != "myMethod" {
		t.Errorf("method.Name = %q, want %q", m.Name, "myMethod")
	}
	if m.Descriptor != "(I)V" {
		t.Errorf("method.Descriptor = %q, want %q", m.Descriptor, "(I)V")
	}
	if m.IsConstructor() {
		t.Error("regular method should not be a constructor")
	}
	if m.IsStaticInitializer() {
		t.Error("regular method should not be static initializer")
	}
	if m.IsAbstract() {
		t.Error("method should not be abstract")
	}
	if m.IsNative() {
		t.Error("method should not be native")
	}
	// Signature falls back to descriptor
	if got := m.Signature(); got != "(I)V" {
		t.Errorf("method.Signature() = %q, want %q", got, "(I)V")
	}
	// Code() nil – no Code attribute
	if c := m.Code(); c != nil {
		t.Error("expected nil Code for method without Code attribute")
	}
	// ExceptionTypes nil – no Exceptions attribute
	if ex := m.ExceptionTypes(); ex != nil {
		t.Error("expected nil ExceptionTypes")
	}
}

func TestParse_ConstructorAndStaticInit(t *testing.T) {
	// Extra CP: #5=<init>, #6=()V, #7=<clinit>, #8=()V (reuse)
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("<init>")...)   // #5
	extraCP = append(extraCP, utf8Entry("()V")...)      // #6
	extraCP = append(extraCP, utf8Entry("<clinit>")...) // #7
	// reuse #6 for clinit descriptor

	init_ := buildMember(AccPublic, 5, 6)
	clinit := buildMember(AccStatic, 7, 6)

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 3, nil,
		nil, [][]byte{init_, clinit})
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(cf.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(cf.Methods))
	}
	if !cf.Methods[0].IsConstructor() {
		t.Error("expected <init> to be a constructor")
	}
	if !cf.Methods[1].IsStaticInitializer() {
		t.Error("expected <clinit> to be a static initializer")
	}
}

func TestParse_InterfaceNames(t *testing.T) {
	// Extra CP: #5=UTF8("java/io/Serializable"), #6=Class(#5)
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("java/io/Serializable")...) // #5
	extraCP = append(extraCP, classEntry(5)...)                     // #6

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 2, []uint16{6}, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	names := cf.InterfaceNames()
	if len(names) != 1 || names[0] != "java/io/Serializable" {
		t.Errorf("InterfaceNames = %v, want [java/io/Serializable]", names)
	}
}

// ---------------------------------------------------------------------------
// Tests: JavaVersion
// ---------------------------------------------------------------------------

func TestJavaVersion(t *testing.T) {
	tests := []struct {
		major uint16
		want  string
	}{
		{45, "Java 1.1"},
		{46, "Java 1.2"},
		{47, "Java 1.3"},
		{48, "Java 1.4"},
		{49, "Java 5"},
		{50, "Java 6"},
		{51, "Java 7"},
		{52, "Java 8"},
		{53, "Java 9"},
		{54, "Java 10"},
		{55, "Java 11"},
		{56, "Java 12"},
		{57, "Java 13"},
		{58, "Java 14"},
		{59, "Java 15"},
		{60, "Java 16"},
		{61, "Java 17"},
		{62, "Java 18"},
		{63, "Java 19"},
		{64, "Java 20"},
		{65, "Java 21"},
		{66, "Java 22"},
		{67, "Java 23"},
		{68, "Java 24"}, // > 67 branch: 68-44=24
		{70, "Java 26"},
		{44, "version 44.0"}, // unknown old version
		{1, "version 1.0"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			cf := &ClassFile{MajorVersion: tc.major, MinorVersion: 0}
			if got := cf.JavaVersion(); got != tc.want {
				t.Errorf("JavaVersion(%d) = %q, want %q", tc.major, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: AccessFlags
// ---------------------------------------------------------------------------

func TestAccessFlags_Has(t *testing.T) {
	a := AccPublic | AccFinal
	if !a.Has(AccPublic) {
		t.Error("expected Public set")
	}
	if !a.Has(AccFinal) {
		t.Error("expected Final set")
	}
	if a.Has(AccAbstract) {
		t.Error("expected Abstract not set")
	}
}

func TestAccessFlags_ClassAccessString(t *testing.T) {
	tests := []struct {
		flags AccessFlags
		want  string
	}{
		{AccPublic, "public"},
		{AccPublic | AccFinal, "public final"},
		{AccAbstract, "abstract"},
		{AccPublic | AccAbstract, "public abstract"},
		{0, ""},
		{AccSuper, ""}, // super not included in class access string
	}
	for _, tc := range tests {
		t.Run(tc.want+"/"+string(rune('0'+tc.flags%10)), func(t *testing.T) {
			if got := tc.flags.ClassAccessString(); got != tc.want {
				t.Errorf("ClassAccessString(%#x) = %q, want %q", uint16(tc.flags), got, tc.want)
			}
		})
	}
}

func TestAccessFlags_FieldAccessString(t *testing.T) {
	tests := []struct {
		flags AccessFlags
		want  string
	}{
		{AccPublic, "public"},
		{AccPrivate, "private"},
		{AccProtected, "protected"},
		{AccStatic, "static"},
		{AccFinal, "final"},
		{AccVolatile, "volatile"},
		{AccTransient, "transient"},
		{AccPublic | AccStatic | AccFinal, "public static final"},
		{0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.flags.FieldAccessString(); got != tc.want {
				t.Errorf("FieldAccessString(%#x) = %q, want %q", uint16(tc.flags), got, tc.want)
			}
		})
	}
}

func TestAccessFlags_MethodAccessString(t *testing.T) {
	tests := []struct {
		flags AccessFlags
		want  string
	}{
		{AccPublic, "public"},
		{AccPrivate, "private"},
		{AccProtected, "protected"},
		{AccStatic, "static"},
		{AccFinal, "final"},
		{AccAbstract, "abstract"},
		{AccNative, "native"},
		{AccStrict, "strictfp"},
		{AccPublic | AccStatic | AccFinal, "public static final"},
		{0, ""},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.flags.MethodAccessString(); got != tc.want {
				t.Errorf("MethodAccessString(%#x) = %q, want %q", uint16(tc.flags), got, tc.want)
			}
		})
	}
}

func TestAccessFlags_TypePredicates(t *testing.T) {
	tests := []struct {
		name  string
		flags AccessFlags
		fn    func(AccessFlags) bool
		want  bool
	}{
		{"IsInterface true", AccInterface, AccessFlags.IsInterface, true},
		{"IsInterface false", AccPublic, AccessFlags.IsInterface, false},
		{"IsEnum true", AccEnum, AccessFlags.IsEnum, true},
		{"IsEnum false", AccPublic, AccessFlags.IsEnum, false},
		{"IsAnnotation true", AccAnnotation, AccessFlags.IsAnnotation, true},
		{"IsAnnotation false", AccPublic, AccessFlags.IsAnnotation, false},
		{"IsModule true", AccModule, AccessFlags.IsModule, true},
		{"IsModule false", AccPublic, AccessFlags.IsModule, false},
		{"IsSynthetic true", AccSynthetic, AccessFlags.IsSynthetic, true},
		{"IsSynthetic false", AccPublic, AccessFlags.IsSynthetic, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.fn(tc.flags); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMethod_AccessPredicates(t *testing.T) {
	tests := []struct {
		name  string
		flags AccessFlags
		fn    func(*Method) bool
		want  bool
	}{
		{"IsStatic true", AccStatic, (*Method).IsStatic, true},
		{"IsStatic false", AccPublic, (*Method).IsStatic, false},
		{"IsAbstract true", AccAbstract, (*Method).IsAbstract, true},
		{"IsNative true", AccNative, (*Method).IsNative, true},
		{"IsSynthetic true", AccSynthetic, (*Method).IsSynthetic, true},
		{"IsBridge true", AccBridge, (*Method).IsBridge, true},
		{"IsVarargs true", AccVarargs, (*Method).IsVarargs, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &Method{AccessFlags: tc.flags}
			if got := tc.fn(m); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: descriptor parsing
// ---------------------------------------------------------------------------

func TestDescriptorToJava(t *testing.T) {
	tests := []struct {
		desc string
		want string
	}{
		{"B", "byte"},
		{"C", "char"},
		{"D", "double"},
		{"F", "float"},
		{"I", "int"},
		{"J", "long"},
		{"S", "short"},
		{"Z", "boolean"},
		{"V", "void"},
		{"Ljava/lang/String;", "java.lang.String"},
		{"[I", "int[]"},
		{"[[B", "byte[][]"},
		{"[Ljava/lang/Object;", "java.lang.Object[]"},
		{"", "void"}, // empty → void (pos >= len)
		{"X", "X"},   // unknown tag → returned as-is
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if got := descriptorToJava(tc.desc); got != tc.want {
				t.Errorf("descriptorToJava(%q) = %q, want %q", tc.desc, got, tc.want)
			}
		})
	}
}

func TestParseMethodDescriptor(t *testing.T) {
	tests := []struct {
		desc       string
		retWant    string
		paramsWant string
	}{
		{"()V", "void", ""},
		{"(I)V", "void", "int"},
		{"(ILjava/lang/String;Z)Ljava/lang/Object;", "java.lang.Object", "int, java.lang.String, boolean"},
		{"([I[B)V", "void", "int[], byte[]"},
		{"", "void", ""},               // empty / no leading '('
		{"notADescriptor", "void", ""}, // no leading '('
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			ret, params := parseMethodDescriptor(tc.desc)
			if ret != tc.retWant {
				t.Errorf("return = %q, want %q", ret, tc.retWant)
			}
			if params != tc.paramsWant {
				t.Errorf("params = %q, want %q", params, tc.paramsWant)
			}
		})
	}
}

func TestDescriptorParamsToJava(t *testing.T) {
	tests := []struct {
		desc string
		want string
	}{
		{"()V", "()"},
		{"(I)V", "(int)"},
		{"", "()"},
		{"notADescriptor", "()"},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			if got := descriptorParamsToJava(tc.desc); got != tc.want {
				t.Errorf("descriptorParamsToJava(%q) = %q, want %q", tc.desc, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: ClassFile.IsInterface / IsEnum / IsAnnotation / IsModule
// ---------------------------------------------------------------------------

func TestClassFile_TypePredicates(t *testing.T) {
	tests := []struct {
		name  string
		flags AccessFlags
		fn    func(*ClassFile) bool
		want  bool
	}{
		{"IsInterface true", AccInterface, (*ClassFile).IsInterface, true},
		{"IsInterface false", AccPublic, (*ClassFile).IsInterface, false},
		{"IsEnum true", AccEnum, (*ClassFile).IsEnum, true},
		{"IsAnnotation true", AccAnnotation, (*ClassFile).IsAnnotation, true},
		{"IsModule true", AccModule, (*ClassFile).IsModule, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Build a real parsed class with the right flags.
			data := buildClass("com/example/Foo", "", 52, tc.flags, nil, 0, nil, nil, nil)
			cf, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := tc.fn(cf); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Stub output
// ---------------------------------------------------------------------------

func TestStub_BasicClass(t *testing.T) {
	data := buildClass("com/example/Foo", "", 52, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "package com.example;") {
		t.Errorf("stub missing package declaration:\n%s", stub)
	}
	if !strings.Contains(stub, "public") {
		t.Errorf("stub missing public modifier:\n%s", stub)
	}
	if !strings.Contains(stub, "class Foo") {
		t.Errorf("stub missing 'class Foo':\n%s", stub)
	}
	if !strings.Contains(stub, "// Decompiled from") {
		t.Errorf("stub missing header comment:\n%s", stub)
	}
}

func TestStub_Interface(t *testing.T) {
	data := buildClass("com/example/IFoo", "", 52, AccPublic|AccInterface|AccAbstract, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "interface IFoo") {
		t.Errorf("stub should say 'interface IFoo':\n%s", stub)
	}
}

func TestStub_Enum(t *testing.T) {
	data := buildClass("com/example/Color", "", 52, AccPublic|AccEnum, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "enum Color") {
		t.Errorf("stub should say 'enum Color':\n%s", stub)
	}
}

func TestStub_Annotation(t *testing.T) {
	// Annotation types carry AccAnnotation|AccInterface. The Stub() method
	// checks IsInterface() first (AccInterface wins), so the output says
	// "interface" rather than "@interface". This test documents that behaviour.
	data := buildClass("com/example/MyAnn", "", 52, AccPublic|AccAnnotation|AccInterface, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cf.IsAnnotation() {
		t.Error("IsAnnotation() should be true")
	}
	stub := cf.Stub()
	// IsInterface() fires first in Stub(), so the keyword emitted is "interface".
	if !strings.Contains(stub, "interface MyAnn") {
		t.Errorf("stub should contain 'interface MyAnn':\n%s", stub)
	}
}

func TestStub_WithSuperClass(t *testing.T) {
	data := buildClass("com/example/Child", "com/example/Parent", 52, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "extends com.example.Parent") {
		t.Errorf("stub missing extends clause:\n%s", stub)
	}
}

func TestStub_WithInterface(t *testing.T) {
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("java/io/Serializable")...) // #5
	extraCP = append(extraCP, classEntry(5)...)                     // #6

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 2, []uint16{6}, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "implements java.io.Serializable") {
		t.Errorf("stub missing implements clause:\n%s", stub)
	}
}

func TestStub_WithFieldAndMethods(t *testing.T) {
	// CP: #5=UTF8("count"), #6=UTF8("I"), #7=UTF8("run"), #8=UTF8("()V"),
	//     #9=UTF8("abs"), #10=UTF8("()V")
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("count")...) // #5
	extraCP = append(extraCP, utf8Entry("I")...)     // #6
	extraCP = append(extraCP, utf8Entry("run")...)   // #7
	extraCP = append(extraCP, utf8Entry("()V")...)   // #8
	extraCP = append(extraCP, utf8Entry("abs")...)   // #9
	extraCP = append(extraCP, utf8Entry("()V")...)   // #10 (duplicate ok)

	field := buildMember(AccPrivate, 5, 6)
	methodConcrete := buildMember(AccPublic, 7, 8)
	methodAbstract := buildMember(AccPublic|AccAbstract, 9, 10)

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 6, nil,
		[][]byte{field}, [][]byte{methodConcrete, methodAbstract})
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "private") {
		t.Errorf("stub missing private field:\n%s", stub)
	}
	if !strings.Contains(stub, "count") {
		t.Errorf("stub missing field name 'count':\n%s", stub)
	}
	if !strings.Contains(stub, "run()") {
		t.Errorf("stub missing method 'run':\n%s", stub)
	}
	// abstract method should end with ';' not '{ /* ... */ }'
	if !strings.Contains(stub, "abs();") {
		t.Errorf("stub abstract method should end with ';':\n%s", stub)
	}
}

func TestStub_StaticInitAndConstructor(t *testing.T) {
	// #5=<init>, #6=()V, #7=<clinit>, #8=()V (dup)
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("<init>")...)   // #5
	extraCP = append(extraCP, utf8Entry("()V")...)      // #6
	extraCP = append(extraCP, utf8Entry("<clinit>")...) // #7

	init_ := buildMember(AccPublic, 5, 6)
	clinit := buildMember(AccStatic, 7, 6)

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 3, nil,
		nil, [][]byte{init_, clinit})
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "Foo()") {
		t.Errorf("stub missing constructor:\n%s", stub)
	}
	if !strings.Contains(stub, "static {") {
		t.Errorf("stub missing static initializer:\n%s", stub)
	}
}

func TestStub_NativeMethod(t *testing.T) {
	// #5=UTF8("nativeOp"), #6=UTF8("()I")
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("nativeOp")...) // #5
	extraCP = append(extraCP, utf8Entry("()I")...)      // #6

	method := buildMember(AccPublic|AccNative, 5, 6)

	data := buildClass("com/example/Foo", "", 52, AccPublic, extraCP, 2, nil,
		nil, [][]byte{method})
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	// native method ends with ';'
	if !strings.Contains(stub, "nativeOp();") {
		t.Errorf("stub native method should end with ';':\n%s", stub)
	}
}

func TestStub_InterfaceWithSuperInterface(t *testing.T) {
	// Interface extending another interface uses "extends" not "implements"
	// Extra: #5=UTF8("java/io/Serializable"), #6=Class(#5)
	var extraCP []byte
	extraCP = append(extraCP, utf8Entry("java/io/Serializable")...) // #5
	extraCP = append(extraCP, classEntry(5)...)                     // #6

	data := buildClass("com/example/IFoo", "", 52, AccPublic|AccInterface|AccAbstract, extraCP, 2, []uint16{6}, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if !strings.Contains(stub, "extends java.io.Serializable") {
		t.Errorf("interface stub should say 'extends', not 'implements':\n%s", stub)
	}
}

func TestStub_NoPackage(t *testing.T) {
	// Class name without a package (no dot in dotted form)
	data := buildClass("Foo", "", 52, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	// Should NOT have a package statement
	if strings.Contains(stub, "package") {
		t.Errorf("class without package should not have package statement:\n%s", stub)
	}
	if !strings.Contains(stub, "class Foo") {
		t.Errorf("stub missing 'class Foo':\n%s", stub)
	}
}

func TestStub_SuperClassIsObject(t *testing.T) {
	// When super is java/lang/Object, Stub() should NOT emit "extends java.lang.Object"
	data := buildClass("com/example/Foo", "java/lang/Object", 52, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	stub := cf.Stub()
	if strings.Contains(stub, "extends java.lang.Object") {
		t.Errorf("should suppress 'extends java.lang.Object':\n%s", stub)
	}
}

// ---------------------------------------------------------------------------
// Tests: Field.IsStatic / IsFinal
// ---------------------------------------------------------------------------

func TestField_Predicates(t *testing.T) {
	f := &Field{AccessFlags: AccStatic | AccFinal}
	if !f.IsStatic() {
		t.Error("expected IsStatic true")
	}
	if !f.IsFinal() {
		t.Error("expected IsFinal true")
	}

	f2 := &Field{AccessFlags: AccPublic}
	if f2.IsStatic() {
		t.Error("expected IsStatic false")
	}
	if f2.IsFinal() {
		t.Error("expected IsFinal false")
	}
}

// ---------------------------------------------------------------------------
// Tests: ClassFile.SourceFile (no SourceFile attribute → "")
// ---------------------------------------------------------------------------

func TestClassFile_SourceFile_Missing(t *testing.T) {
	data := buildClass("com/example/Foo", "", 52, AccPublic, nil, 0, nil, nil, nil)
	cf, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if sf := cf.SourceFile(); sf != "" {
		t.Errorf("SourceFile() = %q, want empty", sf)
	}
}
