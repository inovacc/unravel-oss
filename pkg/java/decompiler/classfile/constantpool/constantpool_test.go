package constantpool

import (
	"bytes"
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildCP encodes a sequence of raw constant-pool entries into a byte slice and
// returns a Pool parsed from them.  entries is a flat byte slice already
// containing the tag+payload bytes for every entry (exactly as they appear in
// a .class file between constant_pool_count and the access_flags field).
// count is the constant_pool_count value (number-of-entries + 1).
func buildCP(t *testing.T, count uint16, entries []byte) *Pool {
	t.Helper()
	r := reader.NewReader(entries)
	p, err := Read(r, count)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	return p
}

// u2 encodes a uint16 big-endian.
func u2(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// u4 encodes a uint32 big-endian.
func u4(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// u8 encodes a uint64 big-endian.
func u8(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

// utf8Entry builds a TagUTF8 entry: tag(1) + length(u2) + bytes.
func utf8Entry(s string) []byte {
	raw := []byte(s)
	var buf []byte
	buf = append(buf, byte(TagUTF8))
	buf = append(buf, u2(uint16(len(raw)))...)
	buf = append(buf, raw...)
	return buf
}

// singleIndexEntry builds an entry whose payload is a single u2 index.
func singleIndexEntry(tag Tag, idx uint16) []byte {
	return append([]byte{byte(tag)}, u2(idx)...)
}

// doubleIndexEntry builds an entry whose payload is two u2 indices.
func doubleIndexEntry(tag Tag, idx1, idx2 uint16) []byte {
	b := []byte{byte(tag)}
	b = append(b, u2(idx1)...)
	b = append(b, u2(idx2)...)
	return b
}

// ---------------------------------------------------------------------------
// Tag.String
// ---------------------------------------------------------------------------

func TestTagString(t *testing.T) {
	cases := []struct {
		tag  Tag
		want string
	}{
		{TagUTF8, "UTF8"},
		{TagInteger, "Integer"},
		{TagFloat, "Float"},
		{TagLong, "Long"},
		{TagDouble, "Double"},
		{TagClass, "Class"},
		{TagString, "String"},
		{TagFieldRef, "FieldRef"},
		{TagMethodRef, "MethodRef"},
		{TagInterfaceMethodRef, "InterfaceMethodRef"},
		{TagNameAndType, "NameAndType"},
		{TagMethodHandle, "MethodHandle"},
		{TagMethodType, "MethodType"},
		{TagDynamic, "Dynamic"},
		{TagInvokeDynamic, "InvokeDynamic"},
		{TagModule, "Module"},
		{TagPackage, "Package"},
		{Tag(0), "Unknown"},
		{Tag(255), "Unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.tag.String(); got != tc.want {
				t.Errorf("Tag(%d).String() = %q, want %q", tc.tag, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Entry.IsWide
// ---------------------------------------------------------------------------

func TestEntryIsWide(t *testing.T) {
	cases := []struct {
		tag  Tag
		wide bool
	}{
		{TagLong, true},
		{TagDouble, true},
		{TagUTF8, false},
		{TagInteger, false},
		{TagFloat, false},
		{TagClass, false},
		{TagString, false},
		{TagFieldRef, false},
		{TagMethodRef, false},
		{TagInterfaceMethodRef, false},
		{TagNameAndType, false},
		{TagMethodHandle, false},
		{TagMethodType, false},
		{TagDynamic, false},
		{TagInvokeDynamic, false},
		{TagModule, false},
		{TagPackage, false},
	}
	for _, tc := range cases {
		t.Run(tc.tag.String(), func(t *testing.T) {
			e := &Entry{Tag: tc.tag}
			if got := e.IsWide(); got != tc.wide {
				t.Errorf("IsWide() = %v, want %v", got, tc.wide)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Read — happy paths for every tag
// ---------------------------------------------------------------------------

func TestRead_AllTags(t *testing.T) {
	// We build a pool with one entry of each type to exercise every branch of
	// readEntry.  Indices are arranged so that cross-reference tests in Pool
	// methods also work:
	//
	//  #1 = UTF8  "java/lang/Object"
	//  #2 = UTF8  "myField"
	//  #3 = UTF8  "I"
	//  #4 = Integer  42
	//  #5 = Float    3.14
	//  #6 = Long     1234567890123  (occupies slots 6 and 7)
	//  #8 = Double   2.718...       (occupies slots 8 and 9)
	//  #10 = Class   -> #1
	//  #11 = String  -> #1
	//  #12 = NameAndType  name=#2  desc=#3
	//  #13 = FieldRef     class=#10  nat=#12
	//  #14 = MethodRef    class=#10  nat=#12
	//  #15 = InterfaceMethodRef  class=#10  nat=#12
	//  #16 = MethodHandle kind=5  ref=#14
	//  #17 = MethodType  -> #3
	//  #18 = Dynamic     bsm=0  nat=#12
	//  #19 = InvokeDynamic bsm=0  nat=#12
	//  #20 = Module -> #1
	//  #21 = Package -> #1
	//
	// constant_pool_count = 22

	var buf []byte
	// #1 UTF8 "java/lang/Object"
	buf = append(buf, utf8Entry("java/lang/Object")...)
	// #2 UTF8 "myField"
	buf = append(buf, utf8Entry("myField")...)
	// #3 UTF8 "I"
	buf = append(buf, utf8Entry("I")...)
	// #4 Integer 42
	buf = append(buf, byte(TagInteger))
	buf = append(buf, u4(42)...)
	// #5 Float 3.14
	buf = append(buf, byte(TagFloat))
	buf = append(buf, u4(math.Float32bits(3.14))...)
	// #6 Long 1234567890123 (wide — takes slots 6 and 7)
	buf = append(buf, byte(TagLong))
	buf = append(buf, u8(1234567890123)...)
	// #8 Double 2.718281828 (wide — takes slots 8 and 9)
	buf = append(buf, byte(TagDouble))
	buf = append(buf, u8(math.Float64bits(2.718281828))...)
	// #10 Class -> #1
	buf = append(buf, singleIndexEntry(TagClass, 1)...)
	// #11 String -> #1
	buf = append(buf, singleIndexEntry(TagString, 1)...)
	// #12 NameAndType name=#2, desc=#3
	buf = append(buf, doubleIndexEntry(TagNameAndType, 2, 3)...)
	// #13 FieldRef class=#10, nat=#12
	buf = append(buf, doubleIndexEntry(TagFieldRef, 10, 12)...)
	// #14 MethodRef class=#10, nat=#12
	buf = append(buf, doubleIndexEntry(TagMethodRef, 10, 12)...)
	// #15 InterfaceMethodRef class=#10, nat=#12
	buf = append(buf, doubleIndexEntry(TagInterfaceMethodRef, 10, 12)...)
	// #16 MethodHandle kind=5, ref=#14
	buf = append(buf, byte(TagMethodHandle), 5)
	buf = append(buf, u2(14)...)
	// #17 MethodType -> #3
	buf = append(buf, singleIndexEntry(TagMethodType, 3)...)
	// #18 Dynamic bsm=0, nat=#12
	buf = append(buf, doubleIndexEntry(TagDynamic, 0, 12)...)
	// #19 InvokeDynamic bsm=0, nat=#12
	buf = append(buf, doubleIndexEntry(TagInvokeDynamic, 0, 12)...)
	// #20 Module -> #1
	buf = append(buf, singleIndexEntry(TagModule, 1)...)
	// #21 Package -> #1
	buf = append(buf, singleIndexEntry(TagPackage, 1)...)

	const count = 22
	p := buildCP(t, count, buf)

	if p.Count() != count {
		t.Errorf("Count() = %d, want %d", p.Count(), count)
	}

	t.Run("UTF8", func(t *testing.T) {
		e := p.Get(1)
		if e == nil || e.Tag != TagUTF8 {
			t.Fatalf("slot 1: want UTF8 entry, got %v", e)
		}
		if e.UTF8Value != "java/lang/Object" {
			t.Errorf("UTF8Value = %q, want %q", e.UTF8Value, "java/lang/Object")
		}
	})

	t.Run("Integer", func(t *testing.T) {
		e := p.Get(4)
		if e == nil || e.Tag != TagInteger {
			t.Fatalf("slot 4: want Integer, got %v", e)
		}
		if e.IntValue != 42 {
			t.Errorf("IntValue = %d, want 42", e.IntValue)
		}
	})

	t.Run("Float", func(t *testing.T) {
		e := p.Get(5)
		if e == nil || e.Tag != TagFloat {
			t.Fatalf("slot 5: want Float, got %v", e)
		}
		if math.Abs(float64(e.FloatValue-3.14)) > 1e-5 {
			t.Errorf("FloatValue = %f, want ~3.14", e.FloatValue)
		}
	})

	t.Run("Long", func(t *testing.T) {
		e := p.Get(6)
		if e == nil || e.Tag != TagLong {
			t.Fatalf("slot 6: want Long, got %v", e)
		}
		if e.LongValue != 1234567890123 {
			t.Errorf("LongValue = %d, want 1234567890123", e.LongValue)
		}
		// slot 7 must be the nil continuation placeholder
		if p.Get(7) != nil {
			t.Error("slot 7 (wide continuation) should be nil")
		}
	})

	t.Run("Double", func(t *testing.T) {
		e := p.Get(8)
		if e == nil || e.Tag != TagDouble {
			t.Fatalf("slot 8: want Double, got %v", e)
		}
		if math.Abs(e.DoubleValue-2.718281828) > 1e-9 {
			t.Errorf("DoubleValue = %f, want ~2.718281828", e.DoubleValue)
		}
		if p.Get(9) != nil {
			t.Error("slot 9 (wide continuation) should be nil")
		}
	})

	t.Run("Class", func(t *testing.T) {
		e := p.Get(10)
		if e == nil || e.Tag != TagClass {
			t.Fatalf("slot 10: want Class, got %v", e)
		}
		if e.NameIndex != 1 {
			t.Errorf("NameIndex = %d, want 1", e.NameIndex)
		}
	})

	t.Run("String", func(t *testing.T) {
		e := p.Get(11)
		if e == nil || e.Tag != TagString {
			t.Fatalf("slot 11: want String, got %v", e)
		}
		if e.NameIndex != 1 {
			t.Errorf("NameIndex = %d, want 1", e.NameIndex)
		}
	})

	t.Run("NameAndType", func(t *testing.T) {
		e := p.Get(12)
		if e == nil || e.Tag != TagNameAndType {
			t.Fatalf("slot 12: want NameAndType, got %v", e)
		}
		if e.NameIndex != 2 || e.DescriptorIndex != 3 {
			t.Errorf("NameIndex=%d DescIndex=%d, want 2,3", e.NameIndex, e.DescriptorIndex)
		}
	})

	t.Run("FieldRef", func(t *testing.T) {
		e := p.Get(13)
		if e == nil || e.Tag != TagFieldRef {
			t.Fatalf("slot 13: want FieldRef, got %v", e)
		}
		if e.ClassIndex != 10 || e.NameAndTypeIndex != 12 {
			t.Errorf("ClassIndex=%d NATIndex=%d, want 10,12", e.ClassIndex, e.NameAndTypeIndex)
		}
	})

	t.Run("MethodRef", func(t *testing.T) {
		e := p.Get(14)
		if e == nil || e.Tag != TagMethodRef {
			t.Fatalf("slot 14: want MethodRef, got %v", e)
		}
	})

	t.Run("InterfaceMethodRef", func(t *testing.T) {
		e := p.Get(15)
		if e == nil || e.Tag != TagInterfaceMethodRef {
			t.Fatalf("slot 15: want InterfaceMethodRef, got %v", e)
		}
	})

	t.Run("MethodHandle", func(t *testing.T) {
		e := p.Get(16)
		if e == nil || e.Tag != TagMethodHandle {
			t.Fatalf("slot 16: want MethodHandle, got %v", e)
		}
		if e.ReferenceKind != 5 || e.ReferenceIndex != 14 {
			t.Errorf("Kind=%d Ref=%d, want 5,14", e.ReferenceKind, e.ReferenceIndex)
		}
	})

	t.Run("MethodType", func(t *testing.T) {
		e := p.Get(17)
		if e == nil || e.Tag != TagMethodType {
			t.Fatalf("slot 17: want MethodType, got %v", e)
		}
		if e.NameIndex != 3 {
			t.Errorf("NameIndex = %d, want 3", e.NameIndex)
		}
	})

	t.Run("Dynamic", func(t *testing.T) {
		e := p.Get(18)
		if e == nil || e.Tag != TagDynamic {
			t.Fatalf("slot 18: want Dynamic, got %v", e)
		}
		if e.BootstrapMethodAttrIndex != 0 || e.NameAndTypeIndex != 12 {
			t.Errorf("BSM=%d NAT=%d, want 0,12", e.BootstrapMethodAttrIndex, e.NameAndTypeIndex)
		}
	})

	t.Run("InvokeDynamic", func(t *testing.T) {
		e := p.Get(19)
		if e == nil || e.Tag != TagInvokeDynamic {
			t.Fatalf("slot 19: want InvokeDynamic, got %v", e)
		}
	})

	t.Run("Module", func(t *testing.T) {
		e := p.Get(20)
		if e == nil || e.Tag != TagModule {
			t.Fatalf("slot 20: want Module, got %v", e)
		}
	})

	t.Run("Package", func(t *testing.T) {
		e := p.Get(21)
		if e == nil || e.Tag != TagPackage {
			t.Fatalf("slot 21: want Package, got %v", e)
		}
	})
}

// ---------------------------------------------------------------------------
// Read — error branches
// ---------------------------------------------------------------------------

func TestRead_UnknownTag(t *testing.T) {
	// Tag 99 is invalid.
	buf := []byte{99}
	r := reader.NewReader(buf)
	_, err := Read(r, 2) // count=2 → one entry expected
	if err == nil {
		t.Fatal("expected error for unknown tag")
	}
	if !strings.Contains(err.Error(), "unknown constant pool tag") {
		t.Errorf("error message should mention 'unknown constant pool tag', got: %v", err)
	}
}

func TestRead_TruncatedUTF8(t *testing.T) {
	// Tag byte present but length u2 is missing.
	buf := []byte{byte(TagUTF8)}
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for UTF8 with missing length")
	}
}

func TestRead_TruncatedUTF8Data(t *testing.T) {
	// Length says 5 but only 2 bytes follow.
	var buf []byte
	buf = append(buf, byte(TagUTF8))
	buf = append(buf, u2(5)...)
	buf = append(buf, 'a', 'b') // only 2 of 5 bytes
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for UTF8 data")
	}
}

func TestRead_TruncatedInteger(t *testing.T) {
	buf := []byte{byte(TagInteger), 0x00, 0x00} // only 3 bytes, need 4
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Integer")
	}
}

func TestRead_TruncatedFloat(t *testing.T) {
	buf := []byte{byte(TagFloat), 0x00} // too short
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Float")
	}
}

func TestRead_TruncatedLong(t *testing.T) {
	buf := []byte{byte(TagLong), 0x00, 0x00, 0x00} // only 3 bytes, need 8
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Long")
	}
}

func TestRead_TruncatedDouble(t *testing.T) {
	buf := []byte{byte(TagDouble), 0x00, 0x00} // too short
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Double")
	}
}

func TestRead_TruncatedClass(t *testing.T) {
	buf := []byte{byte(TagClass), 0x00} // only 1 byte, need u2
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Class")
	}
}

func TestRead_TruncatedString(t *testing.T) {
	buf := []byte{byte(TagString), 0x00} // only 1 byte, need u2
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for String")
	}
}

func TestRead_TruncatedFieldRef(t *testing.T) {
	// First u2 present, second missing.
	buf := append([]byte{byte(TagFieldRef)}, u2(1)...)
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for FieldRef second index")
	}
}

func TestRead_TruncatedMethodRef(t *testing.T) {
	buf := append([]byte{byte(TagMethodRef)}, u2(1)...)
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for MethodRef second index")
	}
}

func TestRead_TruncatedInterfaceMethodRef(t *testing.T) {
	buf := append([]byte{byte(TagInterfaceMethodRef)}, u2(1)...)
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for InterfaceMethodRef second index")
	}
}

func TestRead_TruncatedNameAndType(t *testing.T) {
	buf := append([]byte{byte(TagNameAndType)}, u2(1)...)
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for NameAndType second index")
	}
}

func TestRead_TruncatedMethodHandle(t *testing.T) {
	// kind byte present, ref u2 missing.
	buf := []byte{byte(TagMethodHandle), 5}
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for MethodHandle ref index")
	}
}

func TestRead_TruncatedDynamic(t *testing.T) {
	buf := append([]byte{byte(TagDynamic)}, u2(0)...)
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Dynamic second index")
	}
}

func TestRead_TruncatedInvokeDynamic(t *testing.T) {
	buf := append([]byte{byte(TagInvokeDynamic)}, u2(0)...)
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for InvokeDynamic second index")
	}
}

func TestRead_TruncatedModule(t *testing.T) {
	buf := []byte{byte(TagModule), 0x00}
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Module")
	}
}

func TestRead_TruncatedPackage(t *testing.T) {
	buf := []byte{byte(TagPackage), 0x00}
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for Package")
	}
}

func TestRead_TruncatedMethodType(t *testing.T) {
	buf := []byte{byte(TagMethodType), 0x00}
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected truncation error for MethodType")
	}
}

func TestRead_TruncatedMethodHandle_kind(t *testing.T) {
	// Completely empty — kind byte missing.
	buf := []byte{byte(TagMethodHandle)}
	r := reader.NewReader(buf)
	_, err := Read(r, 2)
	if err == nil {
		t.Fatal("expected error for missing MethodHandle kind")
	}
}

// ---------------------------------------------------------------------------
// Pool.Get boundary conditions
// ---------------------------------------------------------------------------

func TestPool_Get_Boundaries(t *testing.T) {
	buf := utf8Entry("hello")
	p := buildCP(t, 2, buf)

	t.Run("index_0_returns_nil", func(t *testing.T) {
		if p.Get(0) != nil {
			t.Error("Get(0) should return nil")
		}
	})

	t.Run("index_equals_count_returns_nil", func(t *testing.T) {
		// count = 2, so valid index is 1 only; index 2 >= count → nil
		if p.Get(2) != nil {
			t.Error("Get(count) should return nil")
		}
	})

	t.Run("index_beyond_count_returns_nil", func(t *testing.T) {
		if p.Get(100) != nil {
			t.Error("Get(100) on small pool should return nil")
		}
	})

	t.Run("valid_index", func(t *testing.T) {
		e := p.Get(1)
		if e == nil {
			t.Fatal("Get(1) should return non-nil")
		}
		if e.Tag != TagUTF8 {
			t.Errorf("expected TagUTF8, got %s", e.Tag)
		}
	})
}

// ---------------------------------------------------------------------------
// Pool accessor methods
// ---------------------------------------------------------------------------

func buildRichPool(t *testing.T) *Pool {
	t.Helper()
	//  #1 = UTF8 "java/lang/Object"
	//  #2 = UTF8 "myField"
	//  #3 = UTF8 "I"
	//  #4 = Class  -> #1
	//  #5 = String -> #1
	//  #6 = NameAndType name=#2, desc=#3
	//  #7 = FieldRef class=#4, nat=#6
	//  #8 = MethodRef class=#4, nat=#6
	//  #9 = InterfaceMethodRef class=#4, nat=#6
	//  #10 = Module -> #1
	//  #11 = Package -> #1
	var buf []byte
	buf = append(buf, utf8Entry("java/lang/Object")...)
	buf = append(buf, utf8Entry("myField")...)
	buf = append(buf, utf8Entry("I")...)
	buf = append(buf, singleIndexEntry(TagClass, 1)...)
	buf = append(buf, singleIndexEntry(TagString, 1)...)
	buf = append(buf, doubleIndexEntry(TagNameAndType, 2, 3)...)
	buf = append(buf, doubleIndexEntry(TagFieldRef, 4, 6)...)
	buf = append(buf, doubleIndexEntry(TagMethodRef, 4, 6)...)
	buf = append(buf, doubleIndexEntry(TagInterfaceMethodRef, 4, 6)...)
	buf = append(buf, singleIndexEntry(TagModule, 1)...)
	buf = append(buf, singleIndexEntry(TagPackage, 1)...)
	return buildCP(t, 12, buf)
}

func TestPool_UTF8(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		if got := p.UTF8(1); got != "java/lang/Object" {
			t.Errorf("UTF8(1) = %q, want %q", got, "java/lang/Object")
		}
	})

	t.Run("wrong_tag_returns_empty", func(t *testing.T) {
		if got := p.UTF8(4); got != "" { // slot 4 is Class
			t.Errorf("UTF8 on Class entry should be empty, got %q", got)
		}
	})

	t.Run("out_of_range_returns_empty", func(t *testing.T) {
		if got := p.UTF8(99); got != "" {
			t.Errorf("UTF8(99) should be empty, got %q", got)
		}
	})
}

func TestPool_ClassName(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		if got := p.ClassName(4); got != "java/lang/Object" {
			t.Errorf("ClassName(4) = %q, want %q", got, "java/lang/Object")
		}
	})

	t.Run("wrong_tag_returns_empty", func(t *testing.T) {
		if got := p.ClassName(1); got != "" { // slot 1 is UTF8, not Class
			t.Errorf("ClassName on UTF8 entry should be empty, got %q", got)
		}
	})
}

func TestPool_ClassNameDotted(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		got := p.ClassNameDotted(4)
		if got != "java.lang.Object" {
			t.Errorf("ClassNameDotted(4) = %q, want %q", got, "java.lang.Object")
		}
	})

	t.Run("invalid_index", func(t *testing.T) {
		if got := p.ClassNameDotted(99); got != "" {
			t.Errorf("ClassNameDotted(99) should be empty, got %q", got)
		}
	})
}

func TestPool_NameAndType(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		name, desc := p.NameAndType(6)
		if name != "myField" || desc != "I" {
			t.Errorf("NameAndType(6) = (%q, %q), want (%q, %q)", name, desc, "myField", "I")
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		name, desc := p.NameAndType(1) // UTF8, not NameAndType
		if name != "" || desc != "" {
			t.Errorf("NameAndType on UTF8 should return empty strings, got (%q,%q)", name, desc)
		}
	})
}

func TestPool_FieldRefInfo(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		cn, fn, fd := p.FieldRefInfo(7)
		if cn != "java/lang/Object" || fn != "myField" || fd != "I" {
			t.Errorf("FieldRefInfo(7) = (%q, %q, %q), want (java/lang/Object, myField, I)", cn, fn, fd)
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		cn, fn, fd := p.FieldRefInfo(1)
		if cn != "" || fn != "" || fd != "" {
			t.Errorf("FieldRefInfo on UTF8 should return empty, got (%q,%q,%q)", cn, fn, fd)
		}
	})
}

func TestPool_MethodRefInfo(t *testing.T) {
	p := buildRichPool(t)

	t.Run("MethodRef", func(t *testing.T) {
		cn, mn, md := p.MethodRefInfo(8)
		if cn != "java/lang/Object" || mn != "myField" || md != "I" {
			t.Errorf("MethodRefInfo(8) = (%q,%q,%q), want (java/lang/Object,myField,I)", cn, mn, md)
		}
	})

	t.Run("InterfaceMethodRef", func(t *testing.T) {
		cn, mn, md := p.MethodRefInfo(9)
		if cn != "java/lang/Object" || mn != "myField" || md != "I" {
			t.Errorf("MethodRefInfo(9) = (%q,%q,%q), want (java/lang/Object,myField,I)", cn, mn, md)
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		cn, mn, md := p.MethodRefInfo(1)
		if cn != "" || mn != "" || md != "" {
			t.Errorf("MethodRefInfo on UTF8 should return empty, got (%q,%q,%q)", cn, mn, md)
		}
	})
}

func TestPool_StringValue(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		if got := p.StringValue(5); got != "java/lang/Object" {
			t.Errorf("StringValue(5) = %q, want %q", got, "java/lang/Object")
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		if got := p.StringValue(1); got != "" {
			t.Errorf("StringValue on UTF8 should return empty, got %q", got)
		}
	})
}

func TestPool_ModuleName(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		if got := p.ModuleName(10); got != "java/lang/Object" {
			t.Errorf("ModuleName(10) = %q, want %q", got, "java/lang/Object")
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		if got := p.ModuleName(1); got != "" {
			t.Errorf("ModuleName on UTF8 should return empty, got %q", got)
		}
	})
}

func TestPool_PackageName(t *testing.T) {
	p := buildRichPool(t)

	t.Run("valid", func(t *testing.T) {
		if got := p.PackageName(11); got != "java/lang/Object" {
			t.Errorf("PackageName(11) = %q, want %q", got, "java/lang/Object")
		}
	})

	t.Run("wrong_tag", func(t *testing.T) {
		if got := p.PackageName(1); got != "" {
			t.Errorf("PackageName on UTF8 should return empty, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Pool.Validate
// ---------------------------------------------------------------------------

func TestPool_Validate_Valid(t *testing.T) {
	p := buildRichPool(t)
	if err := p.Validate(); err != nil {
		t.Errorf("Validate() on well-formed pool returned error: %v", err)
	}
}

func TestPool_Validate_BrokenRefs(t *testing.T) {
	// Build a pool where a Class entry points to a non-existent name_index.
	// #1 = Class -> #99 (no such entry)
	var buf []byte
	buf = append(buf, singleIndexEntry(TagClass, 99)...)
	p := buildCP(t, 2, buf)
	err := p.Validate()
	if err == nil {
		t.Fatal("Validate() should fail with broken Class name_index")
	}
}

func TestPool_Validate_BrokenString(t *testing.T) {
	var buf []byte
	buf = append(buf, singleIndexEntry(TagString, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken String index")
	}
}

func TestPool_Validate_BrokenMethodType(t *testing.T) {
	var buf []byte
	buf = append(buf, singleIndexEntry(TagMethodType, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken MethodType index")
	}
}

func TestPool_Validate_BrokenFieldRefClass(t *testing.T) {
	// FieldRef -> class_index=99 (missing)
	var buf []byte
	buf = append(buf, doubleIndexEntry(TagFieldRef, 99, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken FieldRef class_index")
	}
}

func TestPool_Validate_BrokenFieldRefNAT(t *testing.T) {
	// FieldRef: class_index=1 (UTF8), nat_index=99 (missing)
	var buf []byte
	buf = append(buf, utf8Entry("Foo")...)                     // #1
	buf = append(buf, doubleIndexEntry(TagFieldRef, 1, 99)...) // #2
	p := buildCP(t, 3, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken FieldRef nat_index")
	}
}

func TestPool_Validate_BrokenNameAndType(t *testing.T) {
	// NameAndType: name_index=99 (missing)
	var buf []byte
	buf = append(buf, doubleIndexEntry(TagNameAndType, 99, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken NameAndType name_index")
	}
}

func TestPool_Validate_BrokenNameAndTypeDesc(t *testing.T) {
	// NameAndType: name_index=1 (valid UTF8), descriptor_index=99 (missing)
	var buf []byte
	buf = append(buf, utf8Entry("foo")...)                        // #1
	buf = append(buf, doubleIndexEntry(TagNameAndType, 1, 99)...) // #2
	p := buildCP(t, 3, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken NameAndType descriptor_index")
	}
}

func TestPool_Validate_BrokenMethodHandle(t *testing.T) {
	// MethodHandle: reference_index=99 (missing)
	buf := []byte{byte(TagMethodHandle), 5}
	buf = append(buf, u2(99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken MethodHandle reference_index")
	}
}

func TestPool_Validate_BrokenDynamic(t *testing.T) {
	var buf []byte
	buf = append(buf, doubleIndexEntry(TagDynamic, 0, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken Dynamic nat_index")
	}
}

func TestPool_Validate_BrokenInvokeDynamic(t *testing.T) {
	var buf []byte
	buf = append(buf, doubleIndexEntry(TagInvokeDynamic, 0, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken InvokeDynamic nat_index")
	}
}

func TestPool_Validate_BrokenModule(t *testing.T) {
	var buf []byte
	buf = append(buf, singleIndexEntry(TagModule, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken Module name_index")
	}
}

func TestPool_Validate_BrokenPackage(t *testing.T) {
	var buf []byte
	buf = append(buf, singleIndexEntry(TagPackage, 99)...)
	p := buildCP(t, 2, buf)
	if err := p.Validate(); err == nil {
		t.Fatal("Validate() should fail with broken Package name_index")
	}
}

// ---------------------------------------------------------------------------
// Pool.Dump
// ---------------------------------------------------------------------------

func TestPool_Dump(t *testing.T) {
	p := buildRichPool(t)
	var sb strings.Builder
	p.Dump(&sb)
	out := sb.String()

	checks := []string{
		"Utf8", "java/lang/Object",
		"Class",
		"String",
		"NameAndType",
		"Fieldref",
		"Methodref",
		"InterfaceMethodref",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("Dump output missing %q; got:\n%s", want, out)
		}
	}
}

func TestPool_Dump_AllTags(t *testing.T) {
	// Build pool with every tag to exercise every Dump branch.
	var buf []byte
	buf = append(buf, utf8Entry("hello")...) // #1
	buf = append(buf, byte(TagInteger))      // #2
	buf = append(buf, u4(7)...)
	buf = append(buf, byte(TagFloat)) // #3
	buf = append(buf, u4(math.Float32bits(1.5))...)
	buf = append(buf, byte(TagLong)) // #4 (wide → #5 nil)
	buf = append(buf, u8(99)...)
	buf = append(buf, byte(TagDouble)) // #6 (wide → #7 nil)
	buf = append(buf, u8(math.Float64bits(9.9))...)
	buf = append(buf, singleIndexEntry(TagString, 1)...)                 // #8
	buf = append(buf, singleIndexEntry(TagClass, 1)...)                  // #9
	buf = append(buf, singleIndexEntry(TagMethodType, 1)...)             // #10
	buf = append(buf, doubleIndexEntry(TagNameAndType, 1, 1)...)         // #11
	buf = append(buf, doubleIndexEntry(TagFieldRef, 9, 11)...)           // #12
	buf = append(buf, doubleIndexEntry(TagMethodRef, 9, 11)...)          // #13
	buf = append(buf, doubleIndexEntry(TagInterfaceMethodRef, 9, 11)...) // #14
	buf = append(buf, byte(TagMethodHandle), 1)                          // #15
	buf = append(buf, u2(13)...)
	buf = append(buf, doubleIndexEntry(TagDynamic, 0, 11)...)       // #16
	buf = append(buf, doubleIndexEntry(TagInvokeDynamic, 0, 11)...) // #17
	buf = append(buf, singleIndexEntry(TagModule, 1)...)            // #18
	buf = append(buf, singleIndexEntry(TagPackage, 1)...)           // #19

	p := buildCP(t, 20, buf)

	var w bytes.Buffer
	p.Dump(&w)
	out := w.String()

	// The wide continuation slots should emit "(wide continuation)"
	if !strings.Contains(out, "wide continuation") {
		t.Errorf("Dump should show wide continuation for Long/Double slots; got:\n%s", out)
	}

	dumpKeywords := []string{
		"Integer", "Float", "Long", "Double", "String",
		"Class", "MethodType", "NameAndType", "Fieldref", "Methodref",
		"InterfaceMethodref", "MethodHandle", "Dynamic", "InvokeDynamic",
		"Module", "Package",
	}
	for _, kw := range dumpKeywords {
		if !strings.Contains(out, kw) {
			t.Errorf("Dump missing keyword %q; got:\n%s", kw, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Wide-entry slot accounting at boundary (last entry is wide)
// ---------------------------------------------------------------------------

func TestRead_WideAtLastSlot(t *testing.T) {
	// count=3: entry #1 is a Long (wide). Slot #2 is the continuation.
	// The loop should NOT try to write entries[2] (index out of range).
	var buf []byte
	buf = append(buf, byte(TagLong))
	buf = append(buf, u8(42)...)
	p := buildCP(t, 3, buf)

	e := p.Get(1)
	if e == nil || e.Tag != TagLong {
		t.Fatal("expected Long at slot 1")
	}
	if p.Get(2) != nil {
		t.Error("continuation slot 2 should be nil")
	}
}
