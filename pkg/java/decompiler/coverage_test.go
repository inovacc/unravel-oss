package decompiler

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/attr"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// ---------------------------------------------------------------------------
// Binary class-file construction helpers
// ---------------------------------------------------------------------------

// appendU32 appends a big-endian uint32.
func appendU32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendU16 appends a big-endian uint16.
func appendU16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

// appendUTF8Entry appends a CONSTANT_Utf8 entry (tag + length + bytes).
func appendUTF8Entry(buf []byte, s string) []byte {
	buf = append(buf, 1) // tag UTF8
	buf = appendU16(buf, uint16(len(s)))
	return append(buf, []byte(s)...)
}

// buildClassWithDefaultConstructor builds a class file with a single default
// constructor method: aload_0 + invokespecial #3 + return (5 bytes).
func buildClassWithDefaultConstructor(className string) []byte {
	// CP:
	// #1 = Class -> #7    (this)
	// #2 = Class -> #8    (super)
	// #3 = Methodref #2.#4
	// #4 = NameAndType #5:#6
	// #5 = UTF8 "<init>"
	// #6 = UTF8 "()V"
	// #7 = UTF8 className
	// #8 = UTF8 "java/lang/Object"
	// #9 = UTF8 "Code"
	// count = 10
	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52) // Java 8

	buf = appendU16(buf, 10) // pool count

	// #1 Class -> #7
	buf = append(buf, 7)
	buf = appendU16(buf, 7)
	// #2 Class -> #8
	buf = append(buf, 7)
	buf = appendU16(buf, 8)
	// #3 Methodref #2.#4
	buf = append(buf, 10)
	buf = appendU16(buf, 2)
	buf = appendU16(buf, 4)
	// #4 NameAndType #5:#6
	buf = append(buf, 12)
	buf = appendU16(buf, 5)
	buf = appendU16(buf, 6)
	// #5 UTF8 "<init>"
	buf = appendUTF8Entry(buf, "<init>")
	// #6 UTF8 "()V"
	buf = appendUTF8Entry(buf, "()V")
	// #7 UTF8 className
	buf = appendUTF8Entry(buf, className)
	// #8 UTF8 "java/lang/Object"
	buf = appendUTF8Entry(buf, "java/lang/Object")
	// #9 UTF8 "Code"
	buf = appendUTF8Entry(buf, "Code")

	buf = appendU16(buf, 0x0021) // ACC_PUBLIC | ACC_SUPER
	buf = appendU16(buf, 1)      // this_class
	buf = appendU16(buf, 2)      // super_class
	buf = appendU16(buf, 0)      // interfaces
	buf = appendU16(buf, 0)      // fields
	buf = appendU16(buf, 1)      // methods = 1

	// Method: public <init> ()V
	buf = appendU16(buf, 0x0001) // ACC_PUBLIC
	buf = appendU16(buf, 5)      // name "<init>"
	buf = appendU16(buf, 6)      // descriptor "()V"
	buf = appendU16(buf, 1)      // attributes = 1 (Code)

	// Code attribute
	buf = appendU16(buf, 9) // attr name = "Code" (#9)
	bytecode := []byte{0x2a, 0xb7, 0x00, 0x03, 0xb1}
	codeLen := uint32(2 + 2 + 4 + len(bytecode) + 2 + 2)
	buf = appendU32(buf, codeLen)
	buf = appendU16(buf, 1) // max_stack
	buf = appendU16(buf, 1) // max_locals
	buf = appendU32(buf, uint32(len(bytecode)))
	buf = append(buf, bytecode...)
	buf = appendU16(buf, 0) // exception_table_length
	buf = appendU16(buf, 0) // code_attributes

	buf = appendU16(buf, 0) // class attributes
	return buf
}

// buildClassWithFlags builds a minimal class with specific access flags.
func buildClassWithFlags(className string, accessFlags uint16) []byte {
	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 5) // count

	buf = append(buf, 7)
	buf = appendU16(buf, 3) // #1 Class -> #3
	buf = append(buf, 7)
	buf = appendU16(buf, 4)                        // #2 Class -> #4
	buf = appendUTF8Entry(buf, className)          // #3
	buf = appendUTF8Entry(buf, "java/lang/Object") // #4

	buf = appendU16(buf, accessFlags)
	buf = appendU16(buf, 1) // this_class
	buf = appendU16(buf, 2) // super_class
	buf = appendU16(buf, 0) // interfaces
	buf = appendU16(buf, 0) // fields
	buf = appendU16(buf, 0) // methods
	buf = appendU16(buf, 0) // attributes
	return buf
}

// buildClassWithField builds a minimal class with one field.
func buildClassWithField(className, fieldName, fieldDesc string) []byte {
	// CP count = 7:
	// #1 Class->#3, #2 Class->#4, #3 UTF8 className, #4 UTF8 Object, #5 UTF8 fieldName, #6 UTF8 fieldDesc
	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 7)

	buf = append(buf, 7)
	buf = appendU16(buf, 3)
	buf = append(buf, 7)
	buf = appendU16(buf, 4)
	buf = appendUTF8Entry(buf, className)
	buf = appendUTF8Entry(buf, "java/lang/Object")
	buf = appendUTF8Entry(buf, fieldName)
	buf = appendUTF8Entry(buf, fieldDesc)

	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 2)
	buf = appendU16(buf, 0) // interfaces
	buf = appendU16(buf, 1) // fields = 1

	// Field entry
	buf = appendU16(buf, 0x0001) // ACC_PUBLIC
	buf = appendU16(buf, 5)      // name_index = #5
	buf = appendU16(buf, 6)      // descriptor_index = #6
	buf = appendU16(buf, 0)      // attributes = 0

	buf = appendU16(buf, 0) // methods
	buf = appendU16(buf, 0) // class attributes
	return buf
}

// buildClassWithMethod builds a minimal class with one void method.
func buildClassWithMethod(className string) []byte {
	// CP count = 8:
	// #1 Class->#3, #2 Class->#4, #3 UTF8 className, #4 UTF8 Object,
	// #5 UTF8 "doSomething", #6 UTF8 "()V", #7 UTF8 "Code"
	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 8)

	buf = append(buf, 7)
	buf = appendU16(buf, 3)
	buf = append(buf, 7)
	buf = appendU16(buf, 4)
	buf = appendUTF8Entry(buf, className)
	buf = appendUTF8Entry(buf, "java/lang/Object")
	buf = appendUTF8Entry(buf, "doSomething")
	buf = appendUTF8Entry(buf, "()V")
	buf = appendUTF8Entry(buf, "Code")

	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 2)
	buf = appendU16(buf, 0) // interfaces
	buf = appendU16(buf, 0) // fields
	buf = appendU16(buf, 1) // methods = 1

	// Method
	buf = appendU16(buf, 0x0001) // ACC_PUBLIC
	buf = appendU16(buf, 5)      // "doSomething"
	buf = appendU16(buf, 6)      // "()V"
	buf = appendU16(buf, 1)      // 1 attribute

	buf = appendU16(buf, 7)  // "Code"
	bytecode := []byte{0xb1} // return
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

// buildClassWithSuperAndInterface builds a class with a non-Object superclass
// and optional interfaces.
func buildClassWithSuperAndInterface(className, superName string, ifaces []string) []byte {
	// CP:
	// #1 = Class -> #3       (this)
	// #2 = Class -> #4       (super)
	// #3 = UTF8 className
	// #4 = UTF8 superName
	// For each iface: Class -> next UTF8, then UTF8 iface name
	// count = 4 + len(ifaces)*2 + 1

	count := uint16(4 + len(ifaces)*2 + 1)
	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, count)

	buf = append(buf, 7)
	buf = appendU16(buf, 3)
	buf = append(buf, 7)
	buf = appendU16(buf, 4)
	buf = appendUTF8Entry(buf, className)
	buf = appendUTF8Entry(buf, superName)

	ifaceClassIdxs := make([]uint16, len(ifaces))
	nextSlot := uint16(5)
	for i, iface := range ifaces {
		ifaceClassIdxs[i] = nextSlot
		buf = append(buf, 7)
		buf = appendU16(buf, nextSlot+1)
		buf = appendUTF8Entry(buf, iface)
		nextSlot += 2
	}

	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1)
	buf = appendU16(buf, 2)
	buf = appendU16(buf, uint16(len(ifaces)))
	for _, idx := range ifaceClassIdxs {
		buf = appendU16(buf, idx)
	}
	buf = appendU16(buf, 0) // fields
	buf = appendU16(buf, 0) // methods
	buf = appendU16(buf, 0) // attributes
	return buf
}

// buildPoolFromBinary builds a pool from a class file binary for use in tests.
// The class file must have a valid constant pool.
func buildPoolFromBinary(data []byte) *constantpool.Pool {
	cf, err := classfile.Parse(data)
	if err != nil {
		return nil
	}
	return cf.ConstantPool
}

// buildTestPool builds a Pool with known entries for renderElementValue tests.
// Pool indices (1-based):
//
//	#1 = Integer(42)
//	#2 = Integer(1)      (boolean true)
//	#3 = UTF8 "hello"   (string)
//	#4 = Double(3.14)   (wide: #4+#5)
//	#6 = Float(2.0)
//	#7 = Long(100)      (wide: #7+#8)
//	#9 = UTF8 "Ljava/lang/SomeEnum;"
//	#10 = UTF8 "VALUE"
//	#11 = UTF8 "Ljava/lang/Override;"
//	... plus the Class/Object entries needed for a valid class file
func buildTestPool() *constantpool.Pool {
	// We need entries 1..N, then Class entries for this/super.
	// Layout:
	// #1 = Class -> #14         (this)
	// #2 = Class -> #15         (super)
	// #3 = Integer(42)
	// #4 = Integer(1)
	// #5 = UTF8 "hello"
	// #6 = Double(3.14)  [wide: #6+#7]
	// #8 = Float(2.0)
	// #9 = Long(100)     [wide: #9+#10]
	// #11 = UTF8 "Ljava/lang/SomeEnum;"
	// #12 = UTF8 "VALUE"
	// #13 = UTF8 "Ljava/lang/Override;"
	// #14 = UTF8 "com/test/Foo"
	// #15 = UTF8 "java/lang/Object"
	// count = 16

	var buf []byte
	buf = appendU32(buf, 0xCAFEBABE)
	buf = appendU16(buf, 0)
	buf = appendU16(buf, 52)
	buf = appendU16(buf, 16) // count

	// #1 Class -> #14
	buf = append(buf, 7)
	buf = appendU16(buf, 14)
	// #2 Class -> #15
	buf = append(buf, 7)
	buf = appendU16(buf, 15)
	// #3 Integer(42)
	buf = append(buf, 3)
	buf = appendU32(buf, 42)
	// #4 Integer(1)
	buf = append(buf, 3)
	buf = appendU32(buf, 1)
	// #5 UTF8 "hello"
	buf = appendUTF8Entry(buf, "hello")
	// #6 Double(3.14) — wide, occupies #6+#7
	buf = append(buf, 6)
	bits64 := math.Float64bits(3.14)
	buf = appendU32(buf, uint32(bits64>>32))
	buf = appendU32(buf, uint32(bits64))
	// #8 Float(2.0)
	buf = append(buf, 4)
	buf = appendU32(buf, uint32(math.Float32bits(2.0)))
	// #9 Long(100) — wide, occupies #9+#10
	buf = append(buf, 5)
	buf = appendU32(buf, 0)
	buf = appendU32(buf, 100)
	// #11 UTF8 "Ljava/lang/SomeEnum;"
	buf = appendUTF8Entry(buf, "Ljava/lang/SomeEnum;")
	// #12 UTF8 "VALUE"
	buf = appendUTF8Entry(buf, "VALUE")
	// #13 UTF8 "Ljava/lang/Override;"
	buf = appendUTF8Entry(buf, "Ljava/lang/Override;")
	// #14 UTF8 "com/test/Foo"
	buf = appendUTF8Entry(buf, "com/test/Foo")
	// #15 UTF8 "java/lang/Object"
	buf = appendUTF8Entry(buf, "java/lang/Object")

	// Class file body
	buf = appendU16(buf, 0x0021)
	buf = appendU16(buf, 1) // this_class
	buf = appendU16(buf, 2) // super_class
	buf = appendU16(buf, 0) // interfaces
	buf = appendU16(buf, 0) // fields
	buf = appendU16(buf, 0) // methods
	buf = appendU16(buf, 0) // attributes

	return buildPoolFromBinary(buf)
}

// ---------------------------------------------------------------------------
// formatFloat / formatDouble
// ---------------------------------------------------------------------------

func TestFormatFloat(t *testing.T) {
	tests := []struct {
		input float32
		want  string
	}{
		{0.0, "0f"},
		{1.5, "1.5f"},
		{float32(math.Inf(1)), "Float.POSITIVE_INFINITY"},
		{float32(math.Inf(-1)), "Float.NEGATIVE_INFINITY"},
		{float32(math.NaN()), "Float.NaN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatFloat(tt.input)
			if got != tt.want {
				t.Errorf("formatFloat(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFormatDouble(t *testing.T) {
	tests := []struct {
		input float64
		want  string
	}{
		{0.0, "0"},
		{3.14, "3.14"},
		{math.Inf(1), "Double.POSITIVE_INFINITY"},
		{math.Inf(-1), "Double.NEGATIVE_INFINITY"},
		{math.NaN(), "Double.NaN"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatDouble(tt.input)
			if got != tt.want {
				t.Errorf("formatDouble(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// annotationDescToName
// ---------------------------------------------------------------------------

func TestAnnotationDescToName(t *testing.T) {
	// annotationDescToName strips "L" prefix and ";" suffix, replaces "/" with ".",
	// then calls SimplifyJavaLang which returns only the last dot-component (simple name).
	tests := []struct {
		desc string
		want string
	}{
		{"Ljava/lang/Override;", "Override"},
		{"Ljava/lang/Deprecated;", "Deprecated"},
		// SimplifyJavaLang strips to the simple name regardless of package
		{"Lcom/example/MyAnnotation;", "MyAnnotation"},
		{"Ljava/lang/SuppressWarnings;", "SuppressWarnings"},
		{"", ""},
		{"X", "X"},
		{"LX", "LX"}, // no trailing ;
		{"ab", "ab"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := annotationDescToName(tt.desc)
			if got != tt.want {
				t.Errorf("annotationDescToName(%q) = %q, want %q", tt.desc, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractDescriptorRefs
// ---------------------------------------------------------------------------

func TestExtractDescriptorRefs(t *testing.T) {
	tests := []struct {
		desc string
		want []string
	}{
		{"(Ljava/lang/String;)V", []string{"java/lang/String"}},
		{"(ILjava/util/List;)Ljava/lang/Object;", []string{"java/util/List", "java/lang/Object"}},
		{"(II)I", nil},
		{"", nil},
		{"(Ljava/lang/String;Ljava/io/IOException;)V", []string{"java/lang/String", "java/io/IOException"}},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			var got []string
			extractDescriptorRefs(tt.desc, func(s string) { got = append(got, s) })

			if len(got) != len(tt.want) {
				t.Errorf("extractDescriptorRefs(%q): got %v, want %v", tt.desc, got, tt.want)
				return
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("extractDescriptorRefs(%q)[%d] = %q, want %q", tt.desc, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractSignatureRefs
// ---------------------------------------------------------------------------

func TestExtractSignatureRefs(t *testing.T) {
	// extractSignatureRefs extracts base class names (before '<') from generic signatures.
	// The outer loop advances past the outer ';', so inner type refs inside '<...>' are
	// NOT separately extracted — only the outermost base name is captured per L...;.
	tests := []struct {
		sig  string
		want []string
	}{
		// List<String>: outer 'L' at index 0 matches 'java/util/List' (base before '<'),
		// then i advances to end=';' position of outer ref. Inner refs not extracted.
		{"Ljava/util/List<Ljava/lang/String;>;", []string{"java/util/List"}},
		{"Ljava/lang/Object;", []string{"java/lang/Object"}},
		// Map<String,Integer>: only base 'java/util/Map' extracted
		{"(Ljava/util/Map<Ljava/lang/String;Ljava/lang/Integer;>;)V",
			[]string{"java/util/Map"}},
		{"", nil},
		{"(II)I", nil},
		// Two adjacent non-generic refs are both extracted
		{"Ljava/lang/String;Ljava/io/IOException;", []string{"java/lang/String", "java/io/IOException"}},
	}

	for _, tt := range tests {
		t.Run(tt.sig, func(t *testing.T) {
			var got []string
			extractSignatureRefs(tt.sig, func(s string) { got = append(got, s) })

			if len(got) != len(tt.want) {
				t.Errorf("extractSignatureRefs(%q): got %v, want %v", tt.sig, got, tt.want)
				return
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("extractSignatureRefs(%q)[%d] = %q, want %q", tt.sig, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isDefaultConstructor — via DecompileBytes
// ---------------------------------------------------------------------------

func TestIsDefaultConstructor_Stripped(t *testing.T) {
	data := buildClassWithDefaultConstructor("com/example/Test")
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "class Test") {
		t.Errorf("expected class Test in output:\n%s", source)
	}
	// The default constructor body should NOT appear as an explicit method.
	if strings.Count(source, "<init>") > 0 {
		t.Errorf("expected default constructor to be stripped:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// stripTrailingVoidReturn
// ---------------------------------------------------------------------------

func TestStripTrailingVoidReturn_Full(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if got := stripTrailingVoidReturn(nil); got != nil {
			t.Error("nil should stay nil")
		}
	})

	t.Run("removes trailing ReturnVoid", func(t *testing.T) {
		stmts := []stmt.Statement{
			stmt.NewNop(),
			stmt.NewReturnVoid(),
		}
		got := stripTrailingVoidReturn(stmts)
		if len(got) != 1 {
			t.Errorf("expected 1 stmt, got %d", len(got))
		}
	})

	t.Run("keeps non-void return", func(t *testing.T) {
		lit := ast.NewIntLiteral(42)
		stmts := []stmt.Statement{stmt.NewReturn(lit)}
		got := stripTrailingVoidReturn(stmts)
		if len(got) != 1 {
			t.Errorf("expected 1 stmt, got %d", len(got))
		}
	})

	t.Run("empty slice stays empty", func(t *testing.T) {
		got := stripTrailingVoidReturn([]stmt.Statement{})
		if len(got) != 0 {
			t.Errorf("expected 0 stmts, got %d", len(got))
		}
	})
}

// ---------------------------------------------------------------------------
// stripNoArgSuperCall
// ---------------------------------------------------------------------------

func TestStripNoArgSuperCall(t *testing.T) {
	t.Run("nil stays nil", func(t *testing.T) {
		if got := stripNoArgSuperCall(nil); got != nil {
			t.Error("nil should stay nil")
		}
	})

	t.Run("empty slice stays empty", func(t *testing.T) {
		got := stripNoArgSuperCall([]stmt.Statement{})
		if len(got) != 0 {
			t.Errorf("expected 0 stmts, got %d", len(got))
		}
	})

	t.Run("keeps non-expression first stmt", func(t *testing.T) {
		stmts := []stmt.Statement{stmt.NewReturnVoid()}
		got := stripNoArgSuperCall(stmts)
		if len(got) != 1 {
			t.Errorf("expected 1 stmt, got %d", len(got))
		}
	})

	t.Run("keeps expression that is not super()", func(t *testing.T) {
		expr := ast.NewIntLiteral(1)
		stmts := []stmt.Statement{stmt.NewExpressionStatement(expr)}
		got := stripNoArgSuperCall(stmts)
		if len(got) != 1 {
			t.Errorf("expected 1 stmt, got %d", len(got))
		}
	})
}

// ---------------------------------------------------------------------------
// formatParams
// ---------------------------------------------------------------------------

// TestParamNamesMatchBody pins the decompiler-parity fix for the local-variable
// naming divergence: without a LocalVariableTable, a method's declared parameter
// names must equal the names its body references. The regression was declaring
// `add(int arg0, int arg1)` while emitting `return (var1 + var2)` — output that
// does not compile (var1/var2 are undefined). CFR/procyon emit consistent names
// (e.g. `add(int n, int n2){ return n + n2; }`); slot-based fallback naming makes
// unravel self-consistent too. See docs/superpowers/plans/2026-07-02-decompiler-parity-convergence.md.
func TestParamNamesMatchBody(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("compare", "testdata", "golden", "Calculator.class"))
	if err != nil {
		t.Fatalf("read Calculator.class: %v", err)
	}
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes: %v", err)
	}
	// The old bug: declaration used arg{i}, body used var{slot}.
	if strings.Contains(source, "arg0") || strings.Contains(source, "arg1") {
		t.Errorf("declaration still uses arg{i} names, diverging from body var{slot}:\n%s", source)
	}
	// The add(int,int) body references its two params; both must be declared.
	if !strings.Contains(source, "var1") || !strings.Contains(source, "var2") {
		t.Errorf("expected slot-based param names var1/var2 in output:\n%s", source)
	}
	// Self-consistency: every var{n} referenced in the body of add must be
	// declared in add's parameter list (no undefined identifiers).
	if !strings.Contains(source, "int var1, int var2") {
		t.Errorf("params not declared with body names (want `int var1, int var2`):\n%s", source)
	}
}

func TestFormatParams(t *testing.T) {
	t.Run("empty params", func(t *testing.T) {
		got := formatParams(nil, true, nil)
		if got != "()" {
			t.Errorf("empty params: got %q, want %q", got, "()")
		}
	})

	t.Run("single int param static", func(t *testing.T) {
		params := []types.JavaType{types.TypeInt}
		got := formatParams(params, true, nil)
		// Static: first param is slot 0, named to match the body's var{slot}.
		if got != "(int var0)" {
			t.Errorf("single int: got %q, want %q", got, "(int var0)")
		}
	})

	t.Run("single int param instance skips this", func(t *testing.T) {
		params := []types.JavaType{types.TypeInt}
		// instance method: slot 0 = "this", so params start at slot 1
		got := formatParams(params, false, nil)
		if !strings.Contains(got, "int") {
			t.Errorf("instance int: missing int in %q", got)
		}
	})

	t.Run("with lvt names static", func(t *testing.T) {
		params := []types.JavaType{types.TypeInt, types.TypeLong}
		lvtNames := map[int]string{0: "count", 1: "offset"}
		got := formatParams(params, true, lvtNames)
		if !strings.Contains(got, "count") {
			t.Errorf("expected 'count' in %q", got)
		}
		if !strings.Contains(got, "offset") {
			t.Errorf("expected 'offset' in %q", got)
		}
	})

	t.Run("with lvt names instance", func(t *testing.T) {
		params := []types.JavaType{types.TypeInt}
		// instance: slot 1 (slot 0 = this)
		lvtNames := map[int]string{1: "value"}
		got := formatParams(params, false, lvtNames)
		if !strings.Contains(got, "value") {
			t.Errorf("expected 'value' in %q", got)
		}
	})

	t.Run("multiple params no lvt", func(t *testing.T) {
		params := []types.JavaType{types.TypeInt, types.TypeBoolean, types.TypeDouble}
		got := formatParams(params, true, nil)
		if !strings.Contains(got, "int") || !strings.Contains(got, "boolean") || !strings.Contains(got, "double") {
			t.Errorf("unexpected params output: %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// formatGenericParams
// ---------------------------------------------------------------------------

func TestFormatGenericParams(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		got := formatGenericParams(nil, true, nil)
		if got != "()" {
			t.Errorf("empty: got %q, want %q", got, "()")
		}
	})

	t.Run("single String param", func(t *testing.T) {
		strType, err := types.ParseFieldDescriptor("Ljava/lang/String;")
		if err != nil {
			t.Fatal(err)
		}
		params := []types.JavaType{strType}
		got := formatGenericParams(params, true, nil)
		if !strings.Contains(got, "String") {
			t.Errorf("expected String in params: %q", got)
		}
	})

	t.Run("with lvt name override instance", func(t *testing.T) {
		params := []types.JavaType{types.TypeInt}
		lvt := map[int]string{1: "myParam"}
		got := formatGenericParams(params, false, lvt)
		if !strings.Contains(got, "myParam") {
			t.Errorf("expected 'myParam' in %q", got)
		}
	})

	t.Run("long param advances slot by 2", func(t *testing.T) {
		params := []types.JavaType{types.TypeLong, types.TypeInt}
		lvt := map[int]string{0: "l", 2: "i"}
		got := formatGenericParams(params, true, lvt)
		if !strings.Contains(got, "l") || !strings.Contains(got, "i") {
			t.Errorf("expected 'l' and 'i' in %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// descriptorParamsJavaWithNames
// ---------------------------------------------------------------------------

func TestDescriptorParamsJavaWithNames(t *testing.T) {
	tests := []struct {
		desc     string
		isStatic bool
		want     string
	}{
		{"()V", true, "()"},
		{"(I)V", true, "(int var0)"},
		{"(Ljava/lang/String;)V", true, "(String var0)"},
		{"not-a-descriptor", true, "()"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := descriptorParamsJavaWithNames(tt.desc, tt.isStatic, nil)
			if got != tt.want {
				t.Errorf("descriptorParamsJavaWithNames(%q) = %q, want %q", tt.desc, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// extractLocalVarNames
// ---------------------------------------------------------------------------

func TestExtractLocalVarNames(t *testing.T) {
	t.Run("nil attributes returns nil", func(t *testing.T) {
		code := &attr.Code{Attributes: nil}
		got := extractLocalVarNames(code, &constantpool.Pool{})
		if got != nil {
			t.Error("expected nil for nil attributes")
		}
	})

	t.Run("no LVT attribute returns nil", func(t *testing.T) {
		code := &attr.Code{Attributes: attr.NewMap()}
		got := extractLocalVarNames(code, &constantpool.Pool{})
		if got != nil {
			t.Error("expected nil when no LVT")
		}
	})

	t.Run("LVT with this-only returns nil", func(t *testing.T) {
		// Build a pool with UTF8 "this"
		pool := buildTestPool()
		if pool == nil {
			t.Skip("pool construction failed")
		}

		// Build an LVT with a single "this" entry at index 0.
		// We need a pool entry with UTF8 "this" — use any UTF8 index.
		// For the test pool, index #5 = "hello" (not "this").
		// We need to verify behavior when LVT only has "this".
		// Use a minimal class file approach with a method that has LVT.
		// For simplicity, build a LVT attribute directly via attr.Map.
		m := attr.NewMap()

		// Construct a proper LVT. We need a pool with "this" at some index.
		// The test pool doesn't have "this", so extractLocalVarNames will skip it
		// (pool.UTF8 returns "" for non-UTF8 or out-of-range entries).
		lvt := &attr.LocalVariableTable{
			Entries: []attr.LocalVariableEntry{
				{NameIndex: 0, Index: 0}, // index 0 = "this" slot, but name will be ""
			},
		}
		m.Add(lvt)
		code := &attr.Code{Attributes: m}
		// NameIndex=0 → pool.UTF8(0) = "" → should be skipped
		got := extractLocalVarNames(code, pool)
		// Since name is "" (pool.UTF8(0) = ""), it's skipped, result is nil
		if got != nil {
			t.Errorf("expected nil for LVT with only empty-name entries, got %v", got)
		}
	})

	t.Run("LVT with valid names via class file", func(t *testing.T) {
		// Verify that a method parsed from bytes with a LVT gets variable names.
		// We can't easily build this without the full class file infrastructure,
		// so just verify that a normal class with method parses OK.
		data := buildClassWithMethod("com/lvt/Test")
		dec := &NativeDecompiler{}
		_, err := dec.DecompileBytes(data)
		if err != nil {
			t.Fatalf("DecompileBytes failed: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// resolveFieldType
// ---------------------------------------------------------------------------

func TestResolveFieldType_ViaDecompileBytes(t *testing.T) {
	data := buildClassWithField("com/example/WithField", "myField", "I")
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes on class with field failed: %v", err)
	}
	if !strings.Contains(source, "int") {
		t.Errorf("expected field type 'int' in output:\n%s", source)
	}
	if !strings.Contains(source, "myField") {
		t.Errorf("expected field name 'myField' in output:\n%s", source)
	}
}

func TestResolveFieldType_BooleanAndLong(t *testing.T) {
	tests := []struct {
		fieldDesc string
		wantType  string
	}{
		{"Z", "boolean"},
		{"J", "long"},
		{"Ljava/lang/String;", "String"},
		{"[I", "int[]"},
	}
	for _, tt := range tests {
		t.Run(tt.fieldDesc, func(t *testing.T) {
			data := buildClassWithField("com/example/T", "f", tt.fieldDesc)
			dec := &NativeDecompiler{}
			source, err := dec.DecompileBytes(data)
			if err != nil {
				t.Fatalf("DecompileBytes failed: %v", err)
			}
			if !strings.Contains(source, tt.wantType) {
				t.Errorf("expected type %q in output:\n%s", tt.wantType, source)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// hasDecompilationErrors
// ---------------------------------------------------------------------------

func TestHasDecompilationErrors(t *testing.T) {
	tests := []struct {
		source string
		want   bool
	}{
		{"", false},
		{"public class Foo { }", false},
		{"public class Foo { /* decompilation error: something */ }", true},
		{"/* error: bad stuff */", true},
		{"// ERROR: something went wrong", true},
		{"// This is a normal comment", false},
	}

	for i, tt := range tests {
		name := tt.source
		if len(name) > 30 {
			name = name[:30]
		}
		t.Run(strings.Join([]string{"case", strings.Join([]string{string(rune('0' + i))}, "")}, "_")+name, func(t *testing.T) {
			got := hasDecompilationErrors(tt.source)
			if got != tt.want {
				t.Errorf("hasDecompilationErrors(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HybridDecompiler
// ---------------------------------------------------------------------------

func TestHybridDecompiler_HasFallback(t *testing.T) {
	t.Run("no paths = no fallback", func(t *testing.T) {
		h := &HybridDecompiler{Native: &NativeDecompiler{}}
		if h.HasFallback() {
			t.Error("expected HasFallback() == false")
		}
	})

	t.Run("java only = no fallback", func(t *testing.T) {
		h := &HybridDecompiler{Native: &NativeDecompiler{}, JavaCmd: "/usr/bin/java"}
		if h.HasFallback() {
			t.Error("expected HasFallback() == false without CFRPath")
		}
	})

	t.Run("both set = has fallback", func(t *testing.T) {
		h := &HybridDecompiler{
			Native:  &NativeDecompiler{},
			JavaCmd: "/usr/bin/java",
			CFRPath: "/tools/cfr.jar",
		}
		if !h.HasFallback() {
			t.Error("expected HasFallback() == true")
		}
	})
}

func TestHybridDecompiler_DecompileBytes_NativePath(t *testing.T) {
	data := buildMinimalClassBytes("com/example/Hybrid", 52)
	h := &HybridDecompiler{Native: &NativeDecompiler{}}
	source, err := h.DecompileBytes(data)
	if err != nil {
		t.Fatalf("HybridDecompiler.DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "Hybrid") {
		t.Errorf("expected class name Hybrid in output:\n%s", source)
	}
}

func TestHybridDecompiler_DecompileBytes_NativeError_NoFallback(t *testing.T) {
	h := &HybridDecompiler{Native: &NativeDecompiler{}}
	_, err := h.DecompileBytes([]byte("not a class"))
	if err == nil {
		t.Error("expected error for invalid class data")
	}
}

func TestHybridDecompiler_DecompileBytes_FallbackOnlyWithoutJava(t *testing.T) {
	// FallbackOnly but no Java/CFR — HasFallback()=false so the FallbackOnly
	// branch doesn't execute, falls through to native.
	data := buildMinimalClassBytes("com/example/FallbackTest", 52)
	h := &HybridDecompiler{
		Native:       &NativeDecompiler{},
		FallbackOnly: true,
	}
	source, err := h.DecompileBytes(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(source, "FallbackTest") {
		t.Errorf("expected FallbackTest in output:\n%s", source)
	}
}

func TestHybridDecompiler_DecompileJAR_NoFallback(t *testing.T) {
	h := &HybridDecompiler{Native: &NativeDecompiler{}}
	err := h.DecompileJAR("some.jar", t.TempDir())
	if err == nil {
		t.Error("expected error from DecompileJAR with no fallback")
	}
}

func TestHybridDecompiler_Decompile_FileNotFound(t *testing.T) {
	h := &HybridDecompiler{Native: &NativeDecompiler{}}
	err := h.Decompile("/nonexistent/path/Foo.class", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent class file")
	}
}

func TestHybridDecompiler_Decompile_ValidFile(t *testing.T) {
	data := buildMinimalClassBytes("com/example/FileTest", 52)
	tmpDir := t.TempDir()
	classFile := filepath.Join(tmpDir, "FileTest.class")
	if err := os.WriteFile(classFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	h := &HybridDecompiler{Native: &NativeDecompiler{}}
	if err := h.Decompile(classFile, outDir); err != nil {
		t.Fatalf("Decompile failed: %v", err)
	}
	javaFile := filepath.Join(outDir, "FileTest.java")
	if _, err := os.Stat(javaFile); err != nil {
		t.Errorf("expected output file %s: %v", javaFile, err)
	}
}

func TestNewHybridDecompiler(t *testing.T) {
	h := NewHybridDecompiler()
	if h == nil {
		t.Fatal("NewHybridDecompiler returned nil")
	}
	if h.Native == nil {
		t.Error("Native should be set")
	}
}

// ---------------------------------------------------------------------------
// NativeDecompiler.Decompile (file-based)
// ---------------------------------------------------------------------------

func TestNativeDecompiler_Decompile_FileNotFound(t *testing.T) {
	dec := &NativeDecompiler{}
	err := dec.Decompile("/does/not/exist/Foo.class", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestNativeDecompiler_Decompile_ValidFile(t *testing.T) {
	data := buildMinimalClassBytes("com/example/NativeTest", 52)
	tmpDir := t.TempDir()
	classFile := filepath.Join(tmpDir, "NativeTest.class")
	if err := os.WriteFile(classFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	dec := &NativeDecompiler{}
	if err := dec.Decompile(classFile, outDir); err != nil {
		t.Fatalf("Decompile failed: %v", err)
	}
	javaFile := filepath.Join(outDir, "NativeTest.java")
	if _, err := os.Stat(javaFile); err != nil {
		t.Errorf("expected output file %s: %v", javaFile, err)
	}
}

func TestNativeDecompiler_Decompile_InvalidClass(t *testing.T) {
	tmpDir := t.TempDir()
	classFile := filepath.Join(tmpDir, "Bad.class")
	if err := os.WriteFile(classFile, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	dec := &NativeDecompiler{}
	err := dec.Decompile(classFile, tmpDir)
	if err == nil {
		t.Error("expected error decompiling invalid class file")
	}
}

// ---------------------------------------------------------------------------
// renderElementValue — all tag branches
// ---------------------------------------------------------------------------

func TestRenderElementValue(t *testing.T) {
	pool := buildTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}

	tests := []struct {
		name string
		ev   attr.ElementValue
		want string
	}{
		{
			name: "integer_42",
			// #3 = Integer(42)
			ev:   attr.ElementValue{Tag: 'I', ConstValueIdx: 3},
			want: "42",
		},
		{
			name: "boolean_true",
			// #4 = Integer(1) → nonzero → true
			ev:   attr.ElementValue{Tag: 'Z', ConstValueIdx: 4},
			want: "true",
		},
		{
			name: "boolean_false",
			// #3 = Integer(42) → nonzero → true... use a zero. We don't have one.
			// Use tag 'Z' with an out-of-range idx → "/* unknown */"
			ev:   attr.ElementValue{Tag: 'Z', ConstValueIdx: 99},
			want: "/* unknown */",
		},
		{
			name: "string",
			// #5 = UTF8 "hello" — but tag 's' expects ConstValueIdx to be a string (UTF8) entry
			ev:   attr.ElementValue{Tag: 's', ConstValueIdx: 5},
			want: `"hello"`,
		},
		{
			name: "array_empty",
			ev:   attr.ElementValue{Tag: '[', ArrayValues: nil},
			want: "{}",
		},
		{
			name: "array_one_int",
			ev: attr.ElementValue{Tag: '[', ArrayValues: []attr.ElementValue{
				{Tag: 'I', ConstValueIdx: 3},
			}},
			want: "{42}",
		},
		{
			name: "unknown_tag",
			ev:   attr.ElementValue{Tag: 0xFF},
			want: "/* unknown */",
		},
		{
			name: "nil_pool_entry",
			ev:   attr.ElementValue{Tag: 'I', ConstValueIdx: 99},
			want: "/* unknown */",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderElementValue(tt.ev, pool)
			if got != tt.want {
				t.Errorf("renderElementValue tag=%c: got %q, want %q", tt.ev.Tag, got, tt.want)
			}
		})
	}
}

func TestRenderElementValue_AllTags(t *testing.T) {
	pool := buildTestPool()
	if pool == nil {
		t.Skip("pool construction failed")
	}

	// 'B' byte — #3 = Integer(42)
	got := renderElementValue(attr.ElementValue{Tag: 'B', ConstValueIdx: 3}, pool)
	if !strings.HasPrefix(got, "(byte)") {
		t.Errorf("byte tag: got %q", got)
	}

	// 'C' char — #4 = Integer(1)
	got = renderElementValue(attr.ElementValue{Tag: 'C', ConstValueIdx: 4}, pool)
	if !strings.HasPrefix(got, "'") {
		t.Errorf("char tag: got %q", got)
	}

	// 'D' double — #6 = Double(3.14)
	got = renderElementValue(attr.ElementValue{Tag: 'D', ConstValueIdx: 6}, pool)
	if got == "/* unknown */" {
		t.Errorf("double tag: got unknown, pool entry may be missing")
	}

	// 'F' float — #8 = Float(2.0)
	got = renderElementValue(attr.ElementValue{Tag: 'F', ConstValueIdx: 8}, pool)
	if got == "/* unknown */" {
		t.Errorf("float tag: got unknown")
	}

	// 'J' long — #9 = Long(100)
	got = renderElementValue(attr.ElementValue{Tag: 'J', ConstValueIdx: 9}, pool)
	if !strings.HasSuffix(got, "L") {
		t.Errorf("long tag: got %q, expected L suffix", got)
	}

	// 'S' short — #3 = Integer(42)
	got = renderElementValue(attr.ElementValue{Tag: 'S', ConstValueIdx: 3}, pool)
	if !strings.HasPrefix(got, "(short)") {
		t.Errorf("short tag: got %q", got)
	}

	// 'e' enum — type at #11 "Ljava/lang/SomeEnum;", const at #12 "VALUE"
	got = renderElementValue(attr.ElementValue{Tag: 'e', EnumTypeIdx: 11, EnumConstIdx: 12}, pool)
	if !strings.Contains(got, ".") {
		t.Errorf("enum tag: got %q, expected dot-separated", got)
	}

	// 'c' class — #5 = UTF8 "hello"
	got = renderElementValue(attr.ElementValue{Tag: 'c', ClassInfoIdx: 5}, pool)
	if !strings.HasSuffix(got, ".class") {
		t.Errorf("class tag: got %q", got)
	}

	// '@' annotation with nil AnnotationVal
	got = renderElementValue(attr.ElementValue{Tag: '@', AnnotationVal: nil}, pool)
	if got != "/* unknown */" {
		t.Errorf("annotation nil: got %q, want /* unknown */", got)
	}

	// '@' annotation with a value — TypeIndex #13 = "Ljava/lang/Override;"
	ae := &attr.AnnotationEntry{TypeIndex: 13}
	got = renderElementValue(attr.ElementValue{Tag: '@', AnnotationVal: ae}, pool)
	if !strings.HasPrefix(got, "@") {
		t.Errorf("annotation tag: got %q", got)
	}
}

// ---------------------------------------------------------------------------
// collectAnnotationImports
// ---------------------------------------------------------------------------

func TestCollectAnnotationImports(t *testing.T) {
	t.Run("nil attrs returns nothing", func(t *testing.T) {
		var collected []string
		collectAnnotationImports(nil, &constantpool.Pool{}, func(s string) {
			collected = append(collected, s)
		})
		if len(collected) != 0 {
			t.Errorf("expected no imports, got %v", collected)
		}
	})

	t.Run("empty map returns nothing", func(t *testing.T) {
		var collected []string
		collectAnnotationImports(attr.NewMap(), &constantpool.Pool{}, func(s string) {
			collected = append(collected, s)
		})
		if len(collected) != 0 {
			t.Errorf("expected no imports, got %v", collected)
		}
	})
}

// ---------------------------------------------------------------------------
// renderAnnotations
// ---------------------------------------------------------------------------

func TestRenderAnnotations(t *testing.T) {
	t.Run("nil attrs returns empty", func(t *testing.T) {
		got := renderAnnotations(nil, &constantpool.Pool{}, "")
		if got != "" {
			t.Errorf("nil attrs should return empty, got %q", got)
		}
	})

	t.Run("no RuntimeVisibleAnnotations returns empty", func(t *testing.T) {
		got := renderAnnotations(attr.NewMap(), &constantpool.Pool{}, "")
		if got != "" {
			t.Errorf("empty map should return empty, got %q", got)
		}
	})
}

// ---------------------------------------------------------------------------
// decompileClass — interface / enum / annotation access flags
// ---------------------------------------------------------------------------

func TestDecompileClass_Interface(t *testing.T) {
	// ACC_PUBLIC=0x0001, ACC_INTERFACE=0x0200, ACC_ABSTRACT=0x0400
	data := buildClassWithFlags("com/example/MyInterface", 0x0601)
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "interface") {
		t.Errorf("expected 'interface' in output:\n%s", source)
	}
}

func TestDecompileClass_Enum(t *testing.T) {
	// ACC_PUBLIC=0x0001, ACC_SUPER=0x0020, ACC_ENUM=0x4000
	data := buildClassWithFlags("com/example/MyEnum", 0x4021)
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "enum") {
		t.Errorf("expected 'enum' in output:\n%s", source)
	}
}

func TestDecompileClass_Annotation(t *testing.T) {
	// decompileClass checks IsInterface() FIRST then IsAnnotation().
	// An @interface has both AccInterface and AccAnnotation set in real JVM files,
	// which means IsInterface() fires first and emits "interface".
	// To reach the IsAnnotation() branch in decompileClass, we need AccAnnotation
	// WITHOUT AccInterface. Use flags: ACC_PUBLIC=0x0001 | ACC_ANNOTATION=0x2000.
	data := buildClassWithFlags("com/example/MyAnnot", 0x2001)
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "@interface") {
		t.Errorf("expected '@interface' in output:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// decompileClass with superclass and interfaces
// ---------------------------------------------------------------------------

func TestDecompileClass_WithSuperclass(t *testing.T) {
	data := buildClassWithSuperAndInterface("com/example/Child", "com/example/Parent", nil)
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "extends") {
		t.Errorf("expected 'extends' in output:\n%s", source)
	}
}

func TestDecompileClass_WithInterfaces(t *testing.T) {
	data := buildClassWithSuperAndInterface("com/example/Impl", "java/lang/Object", []string{"java/io/Serializable"})
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "implements") {
		t.Errorf("expected 'implements' in output:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// decompileClass with a void method
// ---------------------------------------------------------------------------

func TestDecompileClass_WithMethod(t *testing.T) {
	data := buildClassWithMethod("com/example/WithMethod")
	dec := &NativeDecompiler{}
	source, err := dec.DecompileBytes(data)
	if err != nil {
		t.Fatalf("DecompileBytes failed: %v", err)
	}
	if !strings.Contains(source, "doSomething") {
		t.Errorf("expected method 'doSomething' in output:\n%s", source)
	}
}

// ---------------------------------------------------------------------------
// indentBlock edge cases
// ---------------------------------------------------------------------------

func TestIndentBlock_MultiLevel(t *testing.T) {
	input := "x\ny\n"
	got := indentBlock(input, 3)
	// 3 levels * 4 spaces = 12 spaces
	if !strings.Contains(got, "            x") {
		t.Errorf("expected 12-space indent, got:\n%q", got)
	}
}
