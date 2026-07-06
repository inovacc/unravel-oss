/*
Copyright (c) 2026 Security Research

types_coverage_test.go — comprehensive table-driven tests to raise coverage
of descriptor parsing, signature parsing, and all JavaType implementations.
No classfiles, DB, network, or cgo needed.
*/
package types

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// ParseFieldDescriptor — extended branches
// ---------------------------------------------------------------------------

func TestParseFieldDescriptor_AllPrimitives(t *testing.T) {
	cases := []struct {
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
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			jt, err := ParseFieldDescriptor(tc.desc)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if jt.Name() != tc.want {
				t.Errorf("Name()=%q want %q", jt.Name(), tc.want)
			}
		})
	}
}

func TestParseFieldDescriptor_MultiDimArray(t *testing.T) {
	cases := []struct {
		desc    string
		dims    int
		elemStr string
	}{
		{"[I", 1, "int"},
		{"[[D", 2, "double"},
		{"[[[Ljava/lang/String;", 3, "String"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			jt, err := ParseFieldDescriptor(tc.desc)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.desc, err)
			}
			if !jt.IsArray() {
				t.Errorf("expected IsArray true for %q", tc.desc)
			}
			if jt.ArrayDimensions() != tc.dims {
				t.Errorf("ArrayDimensions()=%d want %d", jt.ArrayDimensions(), tc.dims)
			}
			if !strings.Contains(jt.ElementType().Name(), tc.elemStr) {
				t.Errorf("ElementType().Name()=%q want contains %q", jt.ElementType().Name(), tc.elemStr)
			}
		})
	}
}

func TestParseFieldDescriptor_TrailingData(t *testing.T) {
	_, err := ParseFieldDescriptor("IJ") // two primitives — trailing data
	if err == nil {
		t.Error("expected error for trailing data")
	}
}

func TestParseFieldDescriptor_UnterminatedObject(t *testing.T) {
	_, err := ParseFieldDescriptor("Ljava/lang/String") // missing semicolon
	if err == nil {
		t.Error("expected error for unterminated object descriptor")
	}
}

func TestParseFieldDescriptor_UnknownChar(t *testing.T) {
	_, err := ParseFieldDescriptor("Q")
	if err == nil {
		t.Error("expected error for unknown descriptor char Q")
	}
}

func TestParseFieldDescriptor_ArrayUnknownElem(t *testing.T) {
	_, err := ParseFieldDescriptor("[Q")
	if err == nil {
		t.Error("expected error for array with unknown element type")
	}
}

// ---------------------------------------------------------------------------
// ParseMethodDescriptor — extended branches
// ---------------------------------------------------------------------------

func TestParseMethodDescriptor_NoParams(t *testing.T) {
	params, ret, err := ParseMethodDescriptor("()V")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 0 {
		t.Errorf("params: got %d want 0", len(params))
	}
	if ret != TypeVoid {
		t.Errorf("return: got %v want void", ret)
	}
}

func TestParseMethodDescriptor_NonVoidReturn(t *testing.T) {
	params, ret, err := ParseMethodDescriptor("(II)I")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(params) != 2 {
		t.Errorf("params: got %d want 2", len(params))
	}
	if ret.Name() != "int" {
		t.Errorf("return: got %v want int", ret)
	}
}

func TestParseMethodDescriptor_ArrayReturn(t *testing.T) {
	_, ret, err := ParseMethodDescriptor("()[B")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ret.IsArray() {
		t.Error("expected array return type")
	}
}

func TestParseMethodDescriptor_MissingClose(t *testing.T) {
	// no closing ')'
	_, _, err := ParseMethodDescriptor("(I")
	if err == nil {
		t.Error("expected error for missing ')'")
	}
}

func TestParseMethodDescriptor_TrailingAfterReturn(t *testing.T) {
	_, _, err := ParseMethodDescriptor("()IJ")
	if err == nil {
		t.Error("expected error for trailing data after return type")
	}
}

func TestParseMethodDescriptor_BadParam(t *testing.T) {
	_, _, err := ParseMethodDescriptor("(Q)V")
	if err == nil {
		t.Error("expected error for bad param descriptor")
	}
}

func TestParseMethodDescriptor_BadReturn(t *testing.T) {
	_, _, err := ParseMethodDescriptor("()Q")
	if err == nil {
		t.Error("expected error for bad return descriptor")
	}
}

// ---------------------------------------------------------------------------
// DescriptorToJava — error path (returns raw string)
// ---------------------------------------------------------------------------

func TestDescriptorToJava_Invalid(t *testing.T) {
	got := DescriptorToJava("INVALID")
	if got != "INVALID" {
		t.Errorf("expected raw string on error, got %q", got)
	}
}

func TestDescriptorToJava_Valid(t *testing.T) {
	got := DescriptorToJava("Ljava/util/List;")
	if got != "List" {
		t.Errorf("got %q want List", got)
	}
}

// ---------------------------------------------------------------------------
// MethodDescriptorToJava — error path
// ---------------------------------------------------------------------------

func TestMethodDescriptorToJava_Invalid(t *testing.T) {
	got := MethodDescriptorToJava("foo", "NOTADESCRIPTOR")
	if !strings.Contains(got, "foo") {
		t.Errorf("error fallback must contain method name, got %q", got)
	}
}

func TestMethodDescriptorToJava_MultiParam(t *testing.T) {
	got := MethodDescriptorToJava("add", "(ILjava/lang/String;)V")
	if !strings.Contains(got, "add") {
		t.Errorf("missing method name in %q", got)
	}
	if !strings.Contains(got, "int") {
		t.Errorf("missing int param in %q", got)
	}
}

// ---------------------------------------------------------------------------
// CountMethodParams — various combos
// ---------------------------------------------------------------------------

func TestCountMethodParams_LongDouble(t *testing.T) {
	count, slots := CountMethodParams("(JD)V")
	if count != 2 {
		t.Errorf("count: got %d want 2", count)
	}
	if slots != 4 {
		t.Errorf("slots: got %d want 4 (J=2, D=2)", slots)
	}
}

func TestCountMethodParams_Invalid(t *testing.T) {
	count, slots := CountMethodParams("NOTADESCRIPTOR")
	if count != 0 || slots != 0 {
		t.Errorf("expected 0,0 on invalid, got %d,%d", count, slots)
	}
}

func TestCountMethodParams_NoParams(t *testing.T) {
	count, slots := CountMethodParams("()V")
	if count != 0 {
		t.Errorf("count: got %d want 0", count)
	}
	if slots != 0 {
		t.Errorf("slots: got %d want 0", slots)
	}
}

// ---------------------------------------------------------------------------
// RawType — interface coverage
// ---------------------------------------------------------------------------

func TestRawType_Interface(t *testing.T) {
	cases := []struct {
		rt       RawType
		name     string
		desc     string
		category int
		isObj    bool
		isPrim   bool
	}{
		{TypeBoolean, "boolean", "Z", 1, false, true},
		{TypeByte, "byte", "B", 1, false, true},
		{TypeChar, "char", "C", 1, false, true},
		{TypeShort, "short", "S", 1, false, true},
		{TypeInt, "int", "I", 1, false, true},
		{TypeLong, "long", "J", 2, false, true},
		{TypeFloat, "float", "F", 1, false, true},
		{TypeDouble, "double", "D", 2, false, true},
		{TypeVoid, "void", "V", 0, false, false},
		{TypeRef, "reference", "", 1, true, false},
		{TypeNull, "null", "", 1, true, false},
		{TypeReturnAddress, "returnAddress", "", 1, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.rt.Name() != tc.name {
				t.Errorf("Name()=%q want %q", tc.rt.Name(), tc.name)
			}
			if tc.rt.RawName() != tc.name {
				t.Errorf("RawName()=%q want %q", tc.rt.RawName(), tc.name)
			}
			if tc.rt.String() != tc.name {
				t.Errorf("String()=%q want %q", tc.rt.String(), tc.name)
			}
			if tc.rt.Descriptor() != tc.desc {
				t.Errorf("Descriptor()=%q want %q", tc.rt.Descriptor(), tc.desc)
			}
			if tc.rt.StackCategory() != tc.category {
				t.Errorf("StackCategory()=%d want %d", tc.rt.StackCategory(), tc.category)
			}
			if tc.rt.IsObject() != tc.isObj {
				t.Errorf("IsObject()=%v want %v", tc.rt.IsObject(), tc.isObj)
			}
			if tc.rt.IsPrimitive() != tc.isPrim {
				t.Errorf("IsPrimitive()=%v want %v", tc.rt.IsPrimitive(), tc.isPrim)
			}
			// non-array invariants
			if tc.rt.IsArray() {
				t.Errorf("IsArray() should be false for RawType")
			}
			if tc.rt.ArrayDimensions() != 0 {
				t.Errorf("ArrayDimensions() should be 0")
			}
			if tc.rt.ElementType() != tc.rt {
				t.Errorf("ElementType() should return self")
			}
			if tc.rt.ComponentType() != nil {
				t.Errorf("ComponentType() should be nil")
			}
		})
	}
}

func TestRawType_OutOfRange(t *testing.T) {
	rt := RawType(999)
	name := rt.Name()
	if !strings.HasPrefix(name, "RawType(") {
		t.Errorf("out-of-range Name()=%q, want prefix RawType(", name)
	}
	if rt.Descriptor() != "" {
		t.Errorf("out-of-range Descriptor() should be empty, got %q", rt.Descriptor())
	}
}

// ---------------------------------------------------------------------------
// RawType — BoxedName, IsNumeric, IsIntegral
// ---------------------------------------------------------------------------

func TestRawType_BoxedName(t *testing.T) {
	cases := []struct {
		rt   RawType
		want string
	}{
		{TypeBoolean, "java.lang.Boolean"},
		{TypeByte, "java.lang.Byte"},
		{TypeChar, "java.lang.Character"},
		{TypeShort, "java.lang.Short"},
		{TypeInt, "java.lang.Integer"},
		{TypeLong, "java.lang.Long"},
		{TypeFloat, "java.lang.Float"},
		{TypeDouble, "java.lang.Double"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.rt.BoxedName(); got != tc.want {
				t.Errorf("BoxedName()=%q want %q", got, tc.want)
			}
		})
	}
	// void has no boxed name
	if got := TypeVoid.BoxedName(); got != "" {
		t.Errorf("TypeVoid.BoxedName() should be empty, got %q", got)
	}
}

func TestRawType_IsNumeric(t *testing.T) {
	numeric := []RawType{TypeByte, TypeChar, TypeShort, TypeInt, TypeLong, TypeFloat, TypeDouble}
	for _, rt := range numeric {
		if !rt.IsNumeric() {
			t.Errorf("%v.IsNumeric() = false, want true", rt)
		}
	}
	if TypeBoolean.IsNumeric() {
		t.Error("TypeBoolean.IsNumeric() should be false")
	}
	if TypeVoid.IsNumeric() {
		t.Error("TypeVoid.IsNumeric() should be false")
	}
}

func TestRawType_IsIntegral(t *testing.T) {
	integral := []RawType{TypeBoolean, TypeByte, TypeChar, TypeShort, TypeInt}
	for _, rt := range integral {
		if !rt.IsIntegral() {
			t.Errorf("%v.IsIntegral() = false, want true", rt)
		}
	}
	notIntegral := []RawType{TypeLong, TypeFloat, TypeDouble, TypeVoid}
	for _, rt := range notIntegral {
		if rt.IsIntegral() {
			t.Errorf("%v.IsIntegral() = true, want false", rt)
		}
	}
}

// ---------------------------------------------------------------------------
// PrimitiveFromName and UnboxedTypeFor
// ---------------------------------------------------------------------------

func TestPrimitiveFromName(t *testing.T) {
	cases := []struct {
		name string
		rt   RawType
		ok   bool
	}{
		{"int", TypeInt, true},
		{"long", TypeLong, true},
		{"boolean", TypeBoolean, true},
		{"void", TypeVoid, true},
		{"notaprimitive", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := PrimitiveFromName(tc.name)
			if ok != tc.ok {
				t.Errorf("PrimitiveFromName(%q) ok=%v want %v", tc.name, ok, tc.ok)
			}
			if ok && got != tc.rt {
				t.Errorf("PrimitiveFromName(%q)=%v want %v", tc.name, got, tc.rt)
			}
		})
	}
}

func TestUnboxedTypeFor(t *testing.T) {
	cases := []struct {
		className string
		rt        RawType
		ok        bool
	}{
		{"java.lang.Integer", TypeInt, true},
		{"java.lang.Boolean", TypeBoolean, true},
		{"java.lang.Double", TypeDouble, true},
		{"java.lang.Long", TypeLong, true},
		{"java.lang.String", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.className, func(t *testing.T) {
			got, ok := UnboxedTypeFor(tc.className)
			if ok != tc.ok {
				t.Errorf("UnboxedTypeFor(%q) ok=%v want %v", tc.className, ok, tc.ok)
			}
			if ok && got != tc.rt {
				t.Errorf("UnboxedTypeFor(%q)=%v want %v", tc.className, got, tc.rt)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SimplifyJavaLang
// ---------------------------------------------------------------------------

func TestSimplifyJavaLang(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"java.lang.String", "String"},
		{"com.example.foo.Bar", "Bar"},
		{"Foo", "Foo"}, // no dot — returns as-is
		{"", ""},       // empty
		{"a.b", "b"},
		{"java.lang.Object", "Object"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got := SimplifyJavaLang(tc.in)
			if got != tc.want {
				t.Errorf("SimplifyJavaLang(%q)=%q want %q", tc.in, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RefType — all methods
// ---------------------------------------------------------------------------

func TestRefType_Methods(t *testing.T) {
	rt := NewRefType("java.lang.String")

	if rt.Name() != "String" {
		t.Errorf("Name()=%q want String", rt.Name())
	}
	if rt.RawName() != "java.lang.String" {
		t.Errorf("RawName()=%q want java.lang.String", rt.RawName())
	}
	if rt.String() != "java.lang.String" {
		t.Errorf("String()=%q want java.lang.String", rt.String())
	}
	if rt.Descriptor() != "Ljava/lang/String;" {
		t.Errorf("Descriptor()=%q want Ljava/lang/String;", rt.Descriptor())
	}
	if rt.InternalName() != "java/lang/String" {
		t.Errorf("InternalName()=%q want java/lang/String", rt.InternalName())
	}
	if rt.SimpleName() != "String" {
		t.Errorf("SimpleName()=%q want String", rt.SimpleName())
	}
	if rt.PackageName() != "java.lang" {
		t.Errorf("PackageName()=%q want java.lang", rt.PackageName())
	}
	if !rt.IsObject() {
		t.Error("IsObject() should be true")
	}
	if rt.IsPrimitive() {
		t.Error("IsPrimitive() should be false")
	}
	if rt.IsArray() {
		t.Error("IsArray() should be false")
	}
	if rt.ArrayDimensions() != 0 {
		t.Error("ArrayDimensions() should be 0")
	}
	if rt.ElementType() != rt {
		t.Error("ElementType() should return self")
	}
	if rt.ComponentType() != nil {
		t.Error("ComponentType() should be nil")
	}
	if rt.StackCategory() != 1 {
		t.Errorf("StackCategory()=%d want 1", rt.StackCategory())
	}
}

func TestRefType_Methods_NestedClass(t *testing.T) {
	rt := NewRefType("java.lang.invoke.MethodHandles$Lookup")

	if rt.Name() != "Lookup" {
		t.Errorf("Name()=%q want Lookup", rt.Name())
	}
	if rt.SimpleName() != "Lookup" {
		t.Errorf("SimpleName()=%q want Lookup", rt.SimpleName())
	}
	if rt.RawName() != "java.lang.invoke.MethodHandles$Lookup" {
		t.Errorf("RawName()=%q want java.lang.invoke.MethodHandles$Lookup", rt.RawName())
	}
	if rt.Descriptor() != "Ljava/lang/invoke/MethodHandles$Lookup;" {
		t.Errorf("Descriptor()=%q want Ljava/lang/invoke/MethodHandles$Lookup;", rt.Descriptor())
	}
}

func TestRefType_NoPackage(t *testing.T) {
	rt := NewRefType("Foo")
	if rt.PackageName() != "" {
		t.Errorf("PackageName()=%q want empty for unqualified name", rt.PackageName())
	}
	if rt.SimpleName() != "Foo" {
		t.Errorf("SimpleName()=%q want Foo", rt.SimpleName())
	}
	if rt.Name() != "Foo" {
		t.Errorf("Name()=%q want Foo", rt.Name())
	}
}

func TestNewRefTypeFromInternal(t *testing.T) {
	rt := NewRefTypeFromInternal("java/util/List")
	if rt.RawName() != "java.util.List" {
		t.Errorf("RawName()=%q want java.util.List", rt.RawName())
	}
	if rt.InternalName() != "java/util/List" {
		t.Errorf("InternalName()=%q want java/util/List", rt.InternalName())
	}
}

// ---------------------------------------------------------------------------
// ArrayType — all methods
// ---------------------------------------------------------------------------

func TestArrayType_Methods(t *testing.T) {
	elem := NewRefType("java.lang.String")
	arr := NewArrayType(2, elem)

	if arr.Name() != "String[][]" {
		t.Errorf("Name()=%q want String[][]", arr.Name())
	}
	if arr.RawName() != "String[][]" {
		t.Errorf("RawName()=%q want String[][]", arr.RawName())
	}
	if arr.String() != "String[][]" {
		t.Errorf("String()=%q want String[][]", arr.String())
	}
	if arr.Descriptor() != "[[Ljava/lang/String;" {
		t.Errorf("Descriptor()=%q want [[Ljava/lang/String;", arr.Descriptor())
	}
	if !arr.IsObject() {
		t.Error("IsObject() should be true")
	}
	if arr.IsPrimitive() {
		t.Error("IsPrimitive() should be false")
	}
	if !arr.IsArray() {
		t.Error("IsArray() should be true")
	}
	if arr.ArrayDimensions() != 2 {
		t.Errorf("ArrayDimensions()=%d want 2", arr.ArrayDimensions())
	}
	if arr.ElementType() != elem {
		t.Error("ElementType() should return underlying element type")
	}
	if arr.StackCategory() != 1 {
		t.Errorf("StackCategory()=%d want 1", arr.StackCategory())
	}
}

func TestArrayType_ComponentType_SingleDim(t *testing.T) {
	elem := TypeInt
	arr := NewArrayType(1, elem)
	comp := arr.ComponentType()
	if comp != elem {
		t.Errorf("ComponentType() for 1-dim array should return element, got %v", comp)
	}
}

func TestArrayType_ComponentType_MultiDim(t *testing.T) {
	elem := TypeInt
	arr := NewArrayType(3, elem)
	comp := arr.ComponentType()
	if comp == nil {
		t.Fatal("ComponentType() should not be nil for multi-dim array")
	}
	if comp.ArrayDimensions() != 2 {
		t.Errorf("ComponentType() dims=%d want 2", comp.ArrayDimensions())
	}
}

func TestArrayType_Primitive(t *testing.T) {
	arr := NewArrayType(1, TypeInt)
	if arr.Descriptor() != "[I" {
		t.Errorf("Descriptor()=%q want [I", arr.Descriptor())
	}
	if arr.Name() != "int[]" {
		t.Errorf("Name()=%q want int[]", arr.Name())
	}
}

// ---------------------------------------------------------------------------
// GenericType
// ---------------------------------------------------------------------------

func TestGenericType_Methods(t *testing.T) {
	base := NewRefType("java.util.List")
	param := NewRefType("java.lang.String")
	gt := NewGenericType(base, param)

	if gt.Name() != "List<String>" {
		t.Errorf("Name()=%q want List<String>", gt.Name())
	}
	if gt.RawName() != "java.util.List" {
		t.Errorf("RawName()=%q want java.util.List", gt.RawName())
	}
	if gt.Descriptor() != "Ljava/util/List;" {
		t.Errorf("Descriptor()=%q want Ljava/util/List;", gt.Descriptor())
	}
	if gt.String() != "List<String>" {
		t.Errorf("String()=%q want List<String>", gt.String())
	}
	if !gt.IsObject() {
		t.Error("IsObject() should be true")
	}
	if gt.IsPrimitive() {
		t.Error("IsPrimitive() should be false")
	}
	if gt.IsArray() {
		t.Error("IsArray() should be false")
	}
	if gt.ArrayDimensions() != 0 {
		t.Error("ArrayDimensions() should be 0")
	}
	if gt.ElementType() != gt {
		t.Error("ElementType() should return self")
	}
	if gt.ComponentType() != nil {
		t.Error("ComponentType() should be nil")
	}
	if gt.StackCategory() != 1 {
		t.Errorf("StackCategory()=%d want 1", gt.StackCategory())
	}
}

func TestGenericType_MultipleParams(t *testing.T) {
	base := NewRefType("java.util.Map")
	k := NewRefType("java.lang.String")
	v := NewRefType("java.lang.Integer")
	gt := NewGenericType(base, k, v)

	if gt.Name() != "Map<String, Integer>" {
		t.Errorf("Name()=%q want Map<String, Integer>", gt.Name())
	}
}

func TestGenericType_NoParams(t *testing.T) {
	base := NewRefType("java.util.List")
	gt := NewGenericType(base)
	if gt.Name() != "List<>" {
		t.Errorf("Name()=%q want List<>", gt.Name())
	}
}

// ---------------------------------------------------------------------------
// WildcardType
// ---------------------------------------------------------------------------

func TestWildcardType_Unbounded(t *testing.T) {
	w := NewWildcard()
	if w.Name() != "?" {
		t.Errorf("Name()=%q want ?", w.Name())
	}
	if w.RawName() != "?" {
		t.Errorf("RawName()=%q want ?", w.RawName())
	}
	if w.Descriptor() != "" {
		t.Errorf("Descriptor()=%q want empty", w.Descriptor())
	}
	if !w.IsObject() {
		t.Error("IsObject() should be true")
	}
	if w.IsPrimitive() {
		t.Error("IsPrimitive() should be false")
	}
	if w.IsArray() {
		t.Error("IsArray() should be false")
	}
	if w.ArrayDimensions() != 0 {
		t.Error("ArrayDimensions() should be 0")
	}
	if w.ElementType() != w {
		t.Error("ElementType() should return self")
	}
	if w.ComponentType() != nil {
		t.Error("ComponentType() should be nil")
	}
	if w.StackCategory() != 1 {
		t.Errorf("StackCategory()=%d want 1", w.StackCategory())
	}
}

func TestWildcardType_Extends(t *testing.T) {
	bound := NewRefType("java.lang.Number")
	w := NewWildcardExtends(bound)
	if w.Name() != "? extends Number" {
		t.Errorf("Name()=%q want '? extends Number'", w.Name())
	}
	if w.Kind != WildcardExtends {
		t.Errorf("Kind=%v want WildcardExtends", w.Kind)
	}
}

func TestWildcardType_Super(t *testing.T) {
	bound := NewRefType("java.lang.Number")
	w := NewWildcardSuper(bound)
	if w.Name() != "? super Number" {
		t.Errorf("Name()=%q want '? super Number'", w.Name())
	}
	if w.Kind != WildcardSuper {
		t.Errorf("Kind=%v want WildcardSuper", w.Kind)
	}
}

func TestWildcardKind_String(t *testing.T) {
	if WildcardNone.String() != "" {
		t.Errorf("WildcardNone.String()=%q want empty", WildcardNone.String())
	}
	if WildcardExtends.String() != "extends" {
		t.Errorf("WildcardExtends.String()=%q want extends", WildcardExtends.String())
	}
	if WildcardSuper.String() != "super" {
		t.Errorf("WildcardSuper.String()=%q want super", WildcardSuper.String())
	}
	unknown := WildcardKind(99)
	s := unknown.String()
	if !strings.HasPrefix(s, "WildcardKind(") {
		t.Errorf("unknown WildcardKind.String()=%q, want prefix WildcardKind(", s)
	}
}

// ---------------------------------------------------------------------------
// TypeVariable
// ---------------------------------------------------------------------------

func TestTypeVariable_Methods(t *testing.T) {
	tv := NewTypeVariable("T")
	if tv.Name() != "T" {
		t.Errorf("Name()=%q want T", tv.Name())
	}
	if tv.RawName() != "T" {
		t.Errorf("RawName()=%q want T", tv.RawName())
	}
	if tv.Descriptor() != "" {
		t.Errorf("Descriptor()=%q want empty", tv.Descriptor())
	}
	if tv.String() != "T" {
		t.Errorf("String()=%q want T", tv.String())
	}
	if !tv.IsObject() {
		t.Error("IsObject() should be true")
	}
	if tv.IsPrimitive() {
		t.Error("IsPrimitive() should be false")
	}
	if tv.IsArray() {
		t.Error("IsArray() should be false")
	}
	if tv.ArrayDimensions() != 0 {
		t.Error("ArrayDimensions() should be 0")
	}
	if tv.ElementType() != tv {
		t.Error("ElementType() should return self")
	}
	if tv.ComponentType() != nil {
		t.Error("ComponentType() should be nil")
	}
	if tv.StackCategory() != 1 {
		t.Errorf("StackCategory()=%d want 1", tv.StackCategory())
	}
}

// ---------------------------------------------------------------------------
// IntersectionType
// ---------------------------------------------------------------------------

func TestIntersectionType_Methods(t *testing.T) {
	a := NewRefType("java.io.Serializable")
	b := NewRefType("java.lang.Cloneable")
	it := NewIntersectionType(a, b)

	if it.Name() != "Serializable & Cloneable" {
		t.Errorf("Name()=%q want 'Serializable & Cloneable'", it.Name())
	}
	if it.RawName() != "java.io.Serializable" {
		t.Errorf("RawName()=%q want java.io.Serializable", it.RawName())
	}
	if it.Descriptor() != "Ljava/io/Serializable;" {
		t.Errorf("Descriptor()=%q want Ljava/io/Serializable;", it.Descriptor())
	}
	if !it.IsObject() {
		t.Error("IsObject() should be true")
	}
	if it.IsPrimitive() {
		t.Error("IsPrimitive() should be false")
	}
	if it.IsArray() {
		t.Error("IsArray() should be false")
	}
	if it.ArrayDimensions() != 0 {
		t.Error("ArrayDimensions() should be 0")
	}
	if it.ElementType() != it {
		t.Error("ElementType() should return self")
	}
	if it.ComponentType() != nil {
		t.Error("ComponentType() should be nil")
	}
	if it.StackCategory() != 1 {
		t.Errorf("StackCategory()=%d want 1", it.StackCategory())
	}
}

func TestIntersectionType_Empty(t *testing.T) {
	it := NewIntersectionType()
	if it.Name() != "" {
		t.Errorf("empty Name()=%q want empty", it.Name())
	}
	if it.RawName() != "" {
		t.Errorf("empty RawName()=%q want empty", it.RawName())
	}
	if it.Descriptor() != "" {
		t.Errorf("empty Descriptor()=%q want empty", it.Descriptor())
	}
}

func TestIntersectionType_Single(t *testing.T) {
	a := NewRefType("java.lang.Runnable")
	it := NewIntersectionType(a)
	if it.Name() != "Runnable" {
		t.Errorf("single-type Name()=%q want Runnable", it.Name())
	}
}

// ---------------------------------------------------------------------------
// FormalTypeParam.Bound and String
// ---------------------------------------------------------------------------

func TestFormalTypeParam_BoundClassBound(t *testing.T) {
	ftp := FormalTypeParam{
		ParamName:  "T",
		ClassBound: NewRefType("java.lang.Comparable"),
	}
	bound := ftp.Bound()
	if bound.RawName() != "java.lang.Comparable" {
		t.Errorf("Bound()=%v want java.lang.Comparable", bound)
	}
	s := ftp.String()
	if !strings.Contains(s, "extends") {
		t.Errorf("String()=%q should contain 'extends'", s)
	}
}

func TestFormalTypeParam_BoundInterfaceBound(t *testing.T) {
	ftp := FormalTypeParam{
		ParamName:       "T",
		InterfaceBounds: []JavaType{NewRefType("java.io.Serializable")},
	}
	bound := ftp.Bound()
	if bound.RawName() != "java.io.Serializable" {
		t.Errorf("Bound()=%v want java.io.Serializable", bound)
	}
}

func TestFormalTypeParam_BoundDefault(t *testing.T) {
	ftp := FormalTypeParam{ParamName: "T"}
	bound := ftp.Bound()
	if bound.RawName() != "java.lang.Object" {
		t.Errorf("default Bound()=%v want java.lang.Object", bound)
	}
	s := ftp.String()
	// When bound is Object, just the param name is returned
	if s != "T" {
		t.Errorf("String()=%q want T when bound is Object", s)
	}
}

// ---------------------------------------------------------------------------
// Constants — well-known types
// ---------------------------------------------------------------------------

func TestWellKnownTypes(t *testing.T) {
	cases := []struct {
		jt   JavaType
		name string
	}{
		{ObjectType, "Object"},
		{StringType, "String"},
		{ClassType, "Class"},
		{ThrowableType, "Throwable"},
		{EnumType, "Enum"},
		{RecordType, "Record"},
		{IterableType, "Iterable"},
		{ComparableType, "Comparable"},
		{SerializableType, "Serializable"},
		{CloseableType, "Closeable"},
		{AutoCloseableType, "AutoCloseable"},
		{NumberType, "Number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.jt == nil {
				t.Fatalf("well-known type %q is nil", tc.name)
			}
			if tc.jt.Name() != tc.name {
				t.Errorf("Name()=%q want %q", tc.jt.Name(), tc.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseClassSignature
// ---------------------------------------------------------------------------

func TestParseClassSignature_Simple(t *testing.T) {
	// java.lang.Object has no superclass — use a simple case like "Ljava/lang/Object;"
	sig := "Ljava/lang/Object;"
	cs, err := ParseClassSignature(sig)
	if err != nil {
		t.Fatalf("ParseClassSignature(%q): %v", sig, err)
	}
	if cs.SuperClass == nil {
		t.Error("SuperClass should not be nil")
	}
	if cs.SuperClass.RawName() != "java.lang.Object" {
		t.Errorf("SuperClass=%q want java.lang.Object", cs.SuperClass.RawName())
	}
}

func TestParseClassSignature_WithFormalParams(t *testing.T) {
	// <T:Ljava/lang/Object;>Ljava/lang/Object;
	sig := "<T:Ljava/lang/Object;>Ljava/lang/Object;"
	cs, err := ParseClassSignature(sig)
	if err != nil {
		t.Fatalf("ParseClassSignature(%q): %v", sig, err)
	}
	if len(cs.FormalParams) != 1 {
		t.Errorf("FormalParams count=%d want 1", len(cs.FormalParams))
	}
	if cs.FormalParams[0].ParamName != "T" {
		t.Errorf("FormalParams[0].ParamName=%q want T", cs.FormalParams[0].ParamName)
	}
}

func TestParseClassSignature_WithInterfaces(t *testing.T) {
	// Ljava/lang/Object;Ljava/io/Serializable;Ljava/lang/Cloneable;
	sig := "Ljava/lang/Object;Ljava/io/Serializable;Ljava/lang/Cloneable;"
	cs, err := ParseClassSignature(sig)
	if err != nil {
		t.Fatalf("ParseClassSignature(%q): %v", sig, err)
	}
	if len(cs.Interfaces) != 2 {
		t.Errorf("Interfaces count=%d want 2", len(cs.Interfaces))
	}
}

func TestParseClassSignature_Invalid(t *testing.T) {
	cases := []string{
		"",
		"T",                     // starts with type variable but no superclass
		"<T>Ljava/lang/Object;", // formal params with missing colon
	}
	for _, sig := range cases {
		t.Run(sig, func(t *testing.T) {
			_, err := ParseClassSignature(sig)
			if err == nil {
				t.Errorf("expected error for invalid class signature %q", sig)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseMethodSignature
// ---------------------------------------------------------------------------

func TestParseMethodSignature_VoidNoParams(t *testing.T) {
	sig := "()V"
	ms, err := ParseMethodSignature(sig)
	if err != nil {
		t.Fatalf("ParseMethodSignature(%q): %v", sig, err)
	}
	if len(ms.ParamTypes) != 0 {
		t.Errorf("ParamTypes count=%d want 0", len(ms.ParamTypes))
	}
	if ms.ReturnType != TypeVoid {
		t.Errorf("ReturnType=%v want void", ms.ReturnType)
	}
}

func TestParseMethodSignature_WithParams(t *testing.T) {
	sig := "(ILjava/lang/String;)Ljava/lang/Object;"
	ms, err := ParseMethodSignature(sig)
	if err != nil {
		t.Fatalf("ParseMethodSignature(%q): %v", sig, err)
	}
	if len(ms.ParamTypes) != 2 {
		t.Errorf("ParamTypes count=%d want 2", len(ms.ParamTypes))
	}
	if ms.ReturnType.RawName() != "java.lang.Object" {
		t.Errorf("ReturnType=%q want java.lang.Object", ms.ReturnType.RawName())
	}
}

func TestParseMethodSignature_WithFormalParams(t *testing.T) {
	// <T:Ljava/lang/Object;>(TT;)TT;
	sig := "<T:Ljava/lang/Object;>(TT;)TT;"
	ms, err := ParseMethodSignature(sig)
	if err != nil {
		t.Fatalf("ParseMethodSignature(%q): %v", sig, err)
	}
	if len(ms.FormalParams) != 1 {
		t.Errorf("FormalParams count=%d want 1", len(ms.FormalParams))
	}
}

func TestParseMethodSignature_WithExceptions(t *testing.T) {
	// ()V^Ljava/io/IOException;
	sig := "()V^Ljava/io/IOException;"
	ms, err := ParseMethodSignature(sig)
	if err != nil {
		t.Fatalf("ParseMethodSignature(%q): %v", sig, err)
	}
	if len(ms.Exceptions) != 1 {
		t.Errorf("Exceptions count=%d want 1", len(ms.Exceptions))
	}
}

func TestParseMethodSignature_Invalid(t *testing.T) {
	cases := []string{
		"",
		"V",    // no opening paren
		"(Q)V", // bad param type
	}
	for _, sig := range cases {
		t.Run(sig, func(t *testing.T) {
			_, err := ParseMethodSignature(sig)
			if err == nil {
				t.Errorf("expected error for invalid method signature %q", sig)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ParseFieldSignature
// ---------------------------------------------------------------------------

func TestParseFieldSignature_TypeVariable(t *testing.T) {
	sig := "TT;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if jt.Name() != "T" {
		t.Errorf("Name()=%q want T", jt.Name())
	}
}

func TestParseFieldSignature_Generic(t *testing.T) {
	sig := "Ljava/util/List<Ljava/lang/String;>;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if !strings.Contains(jt.Name(), "List") {
		t.Errorf("Name()=%q should contain List", jt.Name())
	}
}

func TestParseFieldSignature_Array(t *testing.T) {
	sig := "[Ljava/lang/String;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if !jt.IsArray() {
		t.Error("expected array type")
	}
}

func TestParseFieldSignature_Invalid(t *testing.T) {
	_, err := ParseFieldSignature("")
	if err == nil {
		t.Error("expected error for empty field signature")
	}
	_, err = ParseFieldSignature("Q")
	if err == nil {
		t.Error("expected error for unknown char Q")
	}
}

// ---------------------------------------------------------------------------
// Generic signature: wildcard type args
// ---------------------------------------------------------------------------

func TestParseFieldSignature_WildcardExtends(t *testing.T) {
	// List<? extends Number>
	sig := "Ljava/util/List<+Ljava/lang/Number;>;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if !strings.Contains(jt.Name(), "extends") {
		t.Errorf("Name()=%q should contain 'extends'", jt.Name())
	}
}

func TestParseFieldSignature_WildcardSuper(t *testing.T) {
	// List<? super Integer>
	sig := "Ljava/util/List<-Ljava/lang/Integer;>;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if !strings.Contains(jt.Name(), "super") {
		t.Errorf("Name()=%q should contain 'super'", jt.Name())
	}
}

func TestParseFieldSignature_UnboundedWildcard(t *testing.T) {
	// List<?>
	sig := "Ljava/util/List<*>;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if !strings.Contains(jt.Name(), "?") {
		t.Errorf("Name()=%q should contain ?", jt.Name())
	}
}

// ---------------------------------------------------------------------------
// Inner class type signature
// ---------------------------------------------------------------------------

func TestParseFieldSignature_InnerClass(t *testing.T) {
	// Map.Entry<String, Integer>
	sig := "Ljava/util/Map.Entry<Ljava/lang/String;Ljava/lang/Integer;>;"
	jt, err := ParseFieldSignature(sig)
	if err != nil {
		t.Fatalf("ParseFieldSignature(%q): %v", sig, err)
	}
	if jt == nil {
		t.Fatal("expected non-nil type")
	}
}

// ---------------------------------------------------------------------------
// Formal type param: interface-only bound (empty class bound)
// ---------------------------------------------------------------------------

func TestParseClassSignature_InterfaceOnlyBound(t *testing.T) {
	// <T::Ljava/io/Serializable;>Ljava/lang/Object;
	// Note: double colon means empty class bound, then interface bound
	sig := "<T::Ljava/io/Serializable;>Ljava/lang/Object;"
	cs, err := ParseClassSignature(sig)
	if err != nil {
		t.Fatalf("ParseClassSignature(%q): %v", sig, err)
	}
	if len(cs.FormalParams) != 1 {
		t.Fatalf("FormalParams count=%d want 1", len(cs.FormalParams))
	}
	ftp := cs.FormalParams[0]
	if ftp.ClassBound != nil {
		t.Error("ClassBound should be nil for interface-only bound")
	}
	if len(ftp.InterfaceBounds) != 1 {
		t.Errorf("InterfaceBounds count=%d want 1", len(ftp.InterfaceBounds))
	}
}

// ---------------------------------------------------------------------------
// Multi-exception method signature
// ---------------------------------------------------------------------------

func TestParseMethodSignature_MultipleExceptions(t *testing.T) {
	sig := "()V^Ljava/io/IOException;^Ljava/lang/RuntimeException;"
	ms, err := ParseMethodSignature(sig)
	if err != nil {
		t.Fatalf("ParseMethodSignature(%q): %v", sig, err)
	}
	if len(ms.Exceptions) != 2 {
		t.Errorf("Exceptions count=%d want 2", len(ms.Exceptions))
	}
}

// ---------------------------------------------------------------------------
// MethodSignature / ClassSignature struct field accessors
// ---------------------------------------------------------------------------

func TestClassSignature_Struct(t *testing.T) {
	cs := &ClassSignature{
		FormalParams: []FormalTypeParam{{ParamName: "K"}, {ParamName: "V"}},
		SuperClass:   NewRefType("java.lang.Object"),
		Interfaces:   []JavaType{NewRefType("java.io.Serializable")},
	}
	if len(cs.FormalParams) != 2 {
		t.Errorf("FormalParams=%d want 2", len(cs.FormalParams))
	}
	if len(cs.Interfaces) != 1 {
		t.Errorf("Interfaces=%d want 1", len(cs.Interfaces))
	}
}

func TestMethodSignature_Struct(t *testing.T) {
	ms := &MethodSignature{
		FormalParams: []FormalTypeParam{{ParamName: "E"}},
		ParamTypes:   []JavaType{TypeInt},
		ReturnType:   TypeVoid,
		Exceptions:   []JavaType{NewRefType("java.lang.Exception")},
	}
	if len(ms.FormalParams) != 1 {
		t.Errorf("FormalParams=%d want 1", len(ms.FormalParams))
	}
	if len(ms.ParamTypes) != 1 {
		t.Errorf("ParamTypes=%d want 1", len(ms.ParamTypes))
	}
	if ms.ReturnType != TypeVoid {
		t.Errorf("ReturnType=%v want void", ms.ReturnType)
	}
}
