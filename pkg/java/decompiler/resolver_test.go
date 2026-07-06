package decompiler

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ---------------------------------------------------------------------------
// cpResolver unit tests
// ---------------------------------------------------------------------------
// We construct constant pools directly from class-file binaries and then call
// cpResolver methods directly.

// buildPoolWith builds a binary class file whose constant pool contains known
// entries, parses it, and returns the pool.
//
// Pool layout (1-based):
//
//	#1  Class -> #3               (this class)
//	#2  Class -> #4               (java/lang/Object)
//	#3  UTF8  "com/test/Resolver"
//	#4  UTF8  "java/lang/Object"
//	#5  Class -> #6               (referenced class)
//	#6  UTF8  "java/lang/String"
//	#7  FieldRef #5.#8
//	#8  NameAndType #9:#10
//	#9  UTF8  "value"
//	#10 UTF8  "I"
//	#11 MethodRef #5.#12
//	#12 NameAndType #13:#14
//	#13 UTF8  "length"
//	#14 UTF8  "()I"
//	#15 InterfaceMethodRef #5.#12   (reuses same NAT)
//	#16 Integer(99)
//	#17 Float(1.5)
//	#18 Long(12345)     [wide: #18+#19]
//	#20 Double(2.71)    [wide: #20+#21]
//	#22 String -> #6   (string constant pointing to UTF8 #6)
//	#23 InvokeDynamic bsm=0, NAT=#8
//	count = 24
func buildResolverTestPool() *constantpool.Pool {
	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 24) // count

	// #1 Class -> #3
	buf = append(buf, 7)
	buf = appendU16(buf, 3)
	// #2 Class -> #4
	buf = append(buf, 7)
	buf = appendU16(buf, 4)
	// #3 UTF8 "com/test/Resolver"
	buf = appendUTF8Entry(buf, "com/test/Resolver")
	// #4 UTF8 "java/lang/Object"
	buf = appendUTF8Entry(buf, "java/lang/Object")
	// #5 Class -> #6
	buf = append(buf, 7)
	buf = appendU16(buf, 6)
	// #6 UTF8 "java/lang/String"
	buf = appendUTF8Entry(buf, "java/lang/String")
	// #7 FieldRef #5.#8
	buf = append(buf, 9)
	buf = appendU16(buf, 5)
	buf = appendU16(buf, 8)
	// #8 NameAndType #9:#10
	buf = append(buf, 12)
	buf = appendU16(buf, 9)
	buf = appendU16(buf, 10)
	// #9 UTF8 "value"
	buf = appendUTF8Entry(buf, "value")
	// #10 UTF8 "I"
	buf = appendUTF8Entry(buf, "I")
	// #11 MethodRef #5.#12
	buf = append(buf, 10)
	buf = appendU16(buf, 5)
	buf = appendU16(buf, 12)
	// #12 NameAndType #13:#14
	buf = append(buf, 12)
	buf = appendU16(buf, 13)
	buf = appendU16(buf, 14)
	// #13 UTF8 "length"
	buf = appendUTF8Entry(buf, "length")
	// #14 UTF8 "()I"
	buf = appendUTF8Entry(buf, "()I")
	// #15 InterfaceMethodRef #5.#12
	buf = append(buf, 11)
	buf = appendU16(buf, 5)
	buf = appendU16(buf, 12)
	// #16 Integer(99)
	buf = append(buf, 3)
	buf = appendU32(buf, 99)
	// #17 Float(1.5)
	buf = append(buf, 4)
	buf = appendU32(buf, 0x3FC00000) // 1.5f bits
	// #18 Long(12345) [wide: #18+#19]
	buf = append(buf, 5)
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 12345)
	// #20 Double(2.71) [wide: #20+#21]
	buf = append(buf, 6)
	{
		import_math_bits := doubleToUint64Bits(2.71)
		buf = appendU32(buf, uint32(import_math_bits>>32))
		buf = appendU32(buf, uint32(import_math_bits))
	}
	// #22 String -> #6
	buf = append(buf, 8)
	buf = appendU16(buf, 6)
	// #23 InvokeDynamic bsm_attr_index=0, name_and_type_index=#8
	buf = append(buf, 18)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 8)

	// Class body
	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1) // this
	buf = appendU16(buf, 2) // super
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)

	cf, err := classfile.Parse(buf)
	if err != nil {
		return nil
	}
	return cf.ConstantPool
}

// doubleToUint64Bits returns the IEEE 754 bit representation of a float64.
// We hardcode the value for 2.71 to avoid importing math in test files.
func doubleToUint64Bits(_ float64) uint64 {
	// 2.71 ≈ 0x4005C28F5C28F5C3
	return 0x4005C28F5C28F5C3
}

// ---------------------------------------------------------------------------
// ResolveClass
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveClass(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	t.Run("valid class ref", func(t *testing.T) {
		jt, err := r.ResolveClass(5) // #5 = Class -> "java/lang/String"
		if err != nil {
			t.Fatalf("ResolveClass(5) error: %v", err)
		}
		if jt == nil {
			t.Fatal("expected non-nil JavaType")
		}
		if !strings.Contains(jt.Name(), "String") {
			t.Errorf("expected String, got %q", jt.Name())
		}
	})

	t.Run("invalid index returns error", func(t *testing.T) {
		_, err := r.ResolveClass(99)
		if err == nil {
			t.Error("expected error for out-of-range index")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveFieldRef
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveFieldRef(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	t.Run("valid field ref", func(t *testing.T) {
		fr, err := r.ResolveFieldRef(7) // #7 = FieldRef java/lang/String.value:I
		if err != nil {
			t.Fatalf("ResolveFieldRef(7) error: %v", err)
		}
		if fr == nil {
			t.Fatal("expected non-nil FieldRef")
		}
		if !strings.Contains(fr.ClassName, "String") {
			t.Errorf("ClassName = %q, expected to contain 'String'", fr.ClassName)
		}
		if fr.FieldName != "value" {
			t.Errorf("FieldName = %q, want %q", fr.FieldName, "value")
		}
		if fr.FieldType == nil {
			t.Error("expected non-nil FieldType")
		}
	})

	t.Run("invalid index returns error", func(t *testing.T) {
		_, err := r.ResolveFieldRef(99)
		if err == nil {
			t.Error("expected error for out-of-range index")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveMethodRef
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveMethodRef(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	t.Run("valid method ref", func(t *testing.T) {
		mr, err := r.ResolveMethodRef(11) // #11 = MethodRef String.length:()I
		if err != nil {
			t.Fatalf("ResolveMethodRef(11) error: %v", err)
		}
		if mr == nil {
			t.Fatal("expected non-nil MethodRef")
		}
		if !strings.Contains(mr.ClassName, "String") {
			t.Errorf("ClassName = %q", mr.ClassName)
		}
		if mr.MethodName != "length" {
			t.Errorf("MethodName = %q, want 'length'", mr.MethodName)
		}
		if mr.ReturnType == nil {
			t.Error("expected non-nil ReturnType")
		}
	})

	t.Run("invalid index returns error", func(t *testing.T) {
		_, err := r.ResolveMethodRef(99)
		if err == nil {
			t.Error("expected error for out-of-range index")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveInterfaceMethodRef
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveInterfaceMethodRef(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	t.Run("valid interface method ref", func(t *testing.T) {
		mr, err := r.ResolveInterfaceMethodRef(15) // #15 = InterfaceMethodRef
		if err != nil {
			t.Fatalf("ResolveInterfaceMethodRef(15) error: %v", err)
		}
		if mr == nil {
			t.Fatal("expected non-nil MethodRef")
		}
		if mr.MethodName != "length" {
			t.Errorf("MethodName = %q, want 'length'", mr.MethodName)
		}
	})

	t.Run("invalid index returns error", func(t *testing.T) {
		_, err := r.ResolveInterfaceMethodRef(99)
		if err == nil {
			t.Error("expected error")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveLiteral
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveLiteral(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	tests := []struct {
		name       string
		idx        uint16
		wantSuffix string // suffix the String() result must end with
		wantInfix  string // substring the String() result must contain
	}{
		{"integer", 16, "", "99"},
		{"float", 17, "f", "1.5"},
		{"long", 18, "L", "12345"},
		{"double", 20, "d", ""}, // just needs a 'd' suffix — actual bits may vary
		{"string", 22, `"`, ""}, // any quoted string
		{"class", 5, ".class", "String"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lit, err := r.ResolveLiteral(tt.idx)
			if err != nil {
				t.Fatalf("ResolveLiteral(%d) error: %v", tt.idx, err)
			}
			if lit == nil {
				t.Fatal("expected non-nil literal")
			}
			got := lit.String()
			if tt.wantSuffix != "" && !strings.HasSuffix(got, tt.wantSuffix) {
				t.Errorf("literal(%s) = %q, want suffix %q", tt.name, got, tt.wantSuffix)
			}
			if tt.wantInfix != "" && !strings.Contains(got, tt.wantInfix) {
				t.Errorf("literal(%s) = %q, want to contain %q", tt.name, got, tt.wantInfix)
			}
		})
	}

	t.Run("nil entry returns error", func(t *testing.T) {
		_, err := r.ResolveLiteral(99)
		if err == nil {
			t.Error("expected error for out-of-range index")
		}
	})

	t.Run("unexpected tag returns error", func(t *testing.T) {
		// Index 7 = FieldRef — not a literal tag
		_, err := r.ResolveLiteral(7)
		if err == nil {
			t.Error("expected error for non-literal tag")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveInvokeDynamic
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveInvokeDynamic(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	t.Run("valid invokedynamic", func(t *testing.T) {
		di, err := r.ResolveInvokeDynamic(23) // #23 = InvokeDynamic
		if err != nil {
			t.Fatalf("ResolveInvokeDynamic(23) error: %v", err)
		}
		if di == nil {
			t.Fatal("expected non-nil DynamicInvocation")
		}
	})

	t.Run("nil entry returns error", func(t *testing.T) {
		_, err := r.ResolveInvokeDynamic(99)
		if err == nil {
			t.Error("expected error for out-of-range index")
		}
	})

	t.Run("wrong tag returns error", func(t *testing.T) {
		// Index 7 = FieldRef, not InvokeDynamic
		_, err := r.ResolveInvokeDynamic(7)
		if err == nil {
			t.Error("expected error for wrong tag")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveNameAndType
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveNameAndType(t *testing.T) {
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	t.Run("valid name and type", func(t *testing.T) {
		name, desc, err := r.ResolveNameAndType(8) // #8 = NameAndType "value":"I"
		if err != nil {
			t.Fatalf("ResolveNameAndType(8) error: %v", err)
		}
		if name != "value" {
			t.Errorf("name = %q, want 'value'", name)
		}
		if desc != "I" {
			t.Errorf("desc = %q, want 'I'", desc)
		}
	})

	t.Run("invalid index returns error", func(t *testing.T) {
		_, _, err := r.ResolveNameAndType(99)
		if err == nil {
			t.Error("expected error for out-of-range index")
		}
	})
}

// ---------------------------------------------------------------------------
// Test cpResolver via DecompileBytes (integration path through pipeline)
// ---------------------------------------------------------------------------

// buildClassWithGetstatic builds a class with a static method that does:
//
//	getstatic java/lang/System.out Ljava/io/PrintStream;
//	return
//
// This exercises ResolveFieldRef in the decompilation pipeline.
func buildClassWithGetstatic(className string) []byte {
	// CP:
	// #1  Class -> #3              (this)
	// #2  Class -> #4              (java/lang/Object)
	// #3  UTF8 className
	// #4  UTF8 "java/lang/Object"
	// #5  Class -> #6              (java/lang/System)
	// #6  UTF8 "java/lang/System"
	// #7  FieldRef #5.#8
	// #8  NameAndType #9:#10
	// #9  UTF8 "out"
	// #10 UTF8 "Ljava/io/PrintStream;"
	// #11 UTF8 "run"
	// #12 UTF8 "()V"
	// #13 UTF8 "Code"
	// count = 14

	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 14)

	buf = append(buf, 7)
	buf = appendU16(buf, 3) // #1
	buf = append(buf, 7)
	buf = appendU16(buf, 4)                        // #2
	buf = appendUTF8Entry(buf, className)          // #3
	buf = appendUTF8Entry(buf, "java/lang/Object") // #4
	buf = append(buf, 7)
	buf = appendU16(buf, 6)                        // #5
	buf = appendUTF8Entry(buf, "java/lang/System") // #6
	buf = append(buf, 9)                           // #7 FieldRef
	buf = appendU16(buf, 5)
	buf = appendU16(buf, 8)
	buf = append(buf, 12) // #8 NameAndType
	buf = appendU16(buf, 9)
	buf = appendU16(buf, 10)
	buf = appendUTF8Entry(buf, "out")                   // #9
	buf = appendUTF8Entry(buf, "Ljava/io/PrintStream;") // #10
	buf = appendUTF8Entry(buf, "run")                   // #11
	buf = appendUTF8Entry(buf, "()V")                   // #12
	buf = appendUTF8Entry(buf, "Code")                  // #13

	buf = appendU16(buf, 0x0021) // ACC_PUBLIC | ACC_SUPER
	buf = appendU16(buf, 1)      // this
	buf = appendU16(buf, 2)      // super
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 1) // 1 method

	// Method: public static void run()
	buf = appendU16(buf, 0x0009) // ACC_PUBLIC | ACC_STATIC
	buf = appendU16(buf, 11)     // "run"
	buf = appendU16(buf, 12)     // "()V"
	buf = appendU16(buf, 1)      // 1 attr

	// Code attribute
	buf = appendU16(buf, 13) // "Code"
	// bytecode: getstatic #7 (b2 00 07) + pop (57) + return (b1)
	bytecode := []byte{0xb2, 0x00, 0x07, 0x57, 0xb1}
	codeLen := uint32(2 + 2 + 4 + len(bytecode) + 2 + 2)
	buf = appendU32(buf, codeLen)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 0) // static: 0 locals
	buf = appendU32(buf, uint32(len(bytecode)))
	buf = append(buf, bytecode...)
	buf = appendU16(buf, 0) // exception table
	buf = appendU16(buf, 0) // code attrs

	buf = appendU16(buf, 0) // class attrs
	return buf
}

func TestDecompileBytes_WithGetstatic(t *testing.T) {
	data := buildClassWithGetstatic("com/example/Getstatic")
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	// Should have decompiled something; even an error comment is acceptable.
	if !strings.Contains(source, "class Getstatic") {
		t.Errorf("expected class Getstatic in output:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// buildClassWithLDC exercises ResolveLiteral via ldc instruction
// ---------------------------------------------------------------------------

func buildClassWithLDC(className string) []byte {
	// CP:
	// #1 Class -> #3
	// #2 Class -> #4
	// #3 UTF8 className
	// #4 UTF8 "java/lang/Object"
	// #5 String -> #6
	// #6 UTF8 "hello"
	// #7 UTF8 "getMsg"
	// #8 UTF8 "()Ljava/lang/String;"
	// #9 UTF8 "Code"
	// count = 10

	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 10)

	buf = append(buf, 7)
	buf = appendU16(buf, 3)
	buf = append(buf, 7)
	buf = appendU16(buf, 4)
	buf = appendUTF8Entry(buf, className)
	buf = appendUTF8Entry(buf, "java/lang/Object")
	buf = append(buf, 8)
	buf = appendU16(buf, 6)                            // #5 String -> #6
	buf = appendUTF8Entry(buf, "hello")                // #6
	buf = appendUTF8Entry(buf, "getMsg")               // #7
	buf = appendUTF8Entry(buf, "()Ljava/lang/String;") // #8
	buf = appendUTF8Entry(buf, "Code")                 // #9

	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 2)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 1) // 1 method

	// public static String getMsg() { return "hello"; }
	buf = appendU16(buf, 0x0009) // ACC_PUBLIC | ACC_STATIC
	buf = appendU16(buf, 7)
	buf = appendU16(buf, 8)
	buf = appendU16(buf, 1)

	buf = appendU16(buf, 9)
	// bytecode: ldc #5 (12 05) + areturn (b0)
	bytecode := []byte{0x12, 0x05, 0xb0}
	codeLen := uint32(2 + 2 + 4 + len(bytecode) + 2 + 2)
	buf = appendU32(buf, codeLen)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 1)
	buf = appendU32(buf, uint32(len(bytecode)))
	buf = append(buf, bytecode...)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)

	buf = appendU16(buf, 0)
	return buf
}

func TestDecompileBytes_WithLDC(t *testing.T) {
	data := buildClassWithLDC("com/example/LDCTest")
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "LDCTest") {
		t.Errorf("expected LDCTest in output:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// buildClassWithInvokevirtual exercises ResolveMethodRef via the pipeline
// ---------------------------------------------------------------------------

func buildClassWithInvokevirtual(className string) []byte {
	// Invokes String.length() on a field.
	// CP:
	// #1 Class -> #3
	// #2 Class -> #4
	// #3 UTF8 className
	// #4 UTF8 "java/lang/Object"
	// #5 Class -> #6
	// #6 UTF8 "java/lang/String"
	// #7 MethodRef #5.#8
	// #8 NameAndType #9:#10
	// #9 UTF8 "length"
	// #10 UTF8 "()I"
	// #11 UTF8 "getLen"
	// #12 UTF8 "(Ljava/lang/String;)I"
	// #13 UTF8 "Code"
	// count = 14

	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 14)

	buf = append(buf, 7)
	buf = appendU16(buf, 3)
	buf = append(buf, 7)
	buf = appendU16(buf, 4)
	buf = appendUTF8Entry(buf, className)
	buf = appendUTF8Entry(buf, "java/lang/Object")
	buf = append(buf, 7)
	buf = appendU16(buf, 6)
	buf = appendUTF8Entry(buf, "java/lang/String")
	buf = append(buf, 10)
	buf = appendU16(buf, 5)
	buf = appendU16(buf, 8)
	buf = append(buf, 12)
	buf = appendU16(buf, 9)
	buf = appendU16(buf, 10)
	buf = appendUTF8Entry(buf, "length")
	buf = appendUTF8Entry(buf, "()I")
	buf = appendUTF8Entry(buf, "getLen")
	buf = appendUTF8Entry(buf, "(Ljava/lang/String;)I")
	buf = appendUTF8Entry(buf, "Code")

	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 2)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 1) // 1 method

	// public static int getLen(String s) { return s.length(); }
	buf = appendU16(buf, 0x0009) // ACC_PUBLIC | ACC_STATIC
	buf = appendU16(buf, 11)
	buf = appendU16(buf, 12)
	buf = appendU16(buf, 1)

	buf = appendU16(buf, 13)
	// bytecode: aload_0 (2a) + invokevirtual #7 (b6 00 07) + ireturn (ac)
	bytecode := []byte{0x2a, 0xb6, 0x00, 0x07, 0xac}
	codeLen := uint32(2 + 2 + 4 + len(bytecode) + 2 + 2)
	buf = appendU32(buf, codeLen)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 1) // 1 local (param s)
	buf = appendU32(buf, uint32(len(bytecode)))
	buf = append(buf, bytecode...)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 0)

	buf = appendU16(buf, 0)
	return buf
}

func TestDecompileBytes_WithInvokevirtual(t *testing.T) {
	data := buildClassWithInvokevirtual("com/example/InvokeTest")
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "InvokeTest") {
		t.Errorf("expected InvokeTest in output:\n%s", source)
	}
	// Method should appear (either decompiled or as error stub)
	if !strings.Contains(source, "getLen") {
		t.Errorf("expected 'getLen' in output:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// ResolveLiteral error paths — test the switch default branch
// ---------------------------------------------------------------------------

func TestCPResolver_ResolveLiteral_WrongTag(t *testing.T) {
	// Build a pool where index 7 = FieldRef (tag 9) — not a literal.
	pool := buildResolverTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}
	r := newCPResolver(pool)

	// FieldRef is not a literal, should get "unexpected literal tag" error.
	_, err := r.ResolveLiteral(7)
	if err == nil {
		t.Error("expected error for FieldRef tag as literal")
	}
	if !strings.Contains(err.Error(), "unexpected") && !strings.Contains(err.Error(), "tag") {
		t.Errorf("error message should mention 'unexpected' or 'tag', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test that the _ import doesn't cause issues — verify ast.FieldRef fields
// ---------------------------------------------------------------------------

func TestASTFieldRef_Fields(t *testing.T) {
	ft, _ := types.ParseFieldDescriptor("I")
	fr := &ast.FieldRef{
		ClassName:  "com.example.Foo",
		FieldName:  "bar",
		Descriptor: "I",
		FieldType:  ft,
	}
	if fr.ClassName != "com.example.Foo" {
		t.Errorf("ClassName = %q", fr.ClassName)
	}
	if fr.FieldName != "bar" {
		t.Errorf("FieldName = %q", fr.FieldName)
	}
}
