/*
Copyright (c) 2026 Security Research

Golden-source comparison tests for the Java decompiler.

Each test constructs .class bytes for a known Java program, decompiles
with unravel's native decompiler, and verifies the output contains
expected Java constructs. When external decompilers (CFR, Procyon,
Vineflower) are available, their output is also captured and compared.
*/
package compare

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler"
)

// JVM opcodes used in test bytecode construction.
const (
	opALOAD_0       byte = 0x2A
	opALOAD_1       byte = 0x2B
	opICONST_0      byte = 0x03
	opICONST_1      byte = 0x04
	opICONST_2      byte = 0x05
	opICONST_3      byte = 0x06
	opICONST_5      byte = 0x08
	opBIPUSH        byte = 0x10
	opSIPUSH        byte = 0x11
	opLDC           byte = 0x12
	opILOAD_1       byte = 0x1B
	opILOAD_2       byte = 0x1C
	opISTORE_1      byte = 0x3C
	opISTORE_2      byte = 0x3D
	opIADD          byte = 0x60
	opIMUL          byte = 0x68
	opIRETURN       byte = 0xAC
	opARETURN       byte = 0xB0
	opRETURN        byte = 0xB1
	opGETSTATIC     byte = 0xB2
	opPUTFIELD      byte = 0xB5
	opINVOKEVIRTUAL byte = 0xB6
	opINVOKESPECIAL byte = 0xB7
	opINVOKESTATIC  byte = 0xB8
	opNEW           byte = 0xBB
	opDUP           byte = 0x59
	opIFICMPLE      byte = 0xA4
	opGOTO          byte = 0xA7
	opATHROW        byte = 0xBF
	opIF_ICMPGE     byte = 0xA2
)

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

// --- Test 1: Empty class (baseline) ---

func TestGolden_EmptyClass(t *testing.T) {
	cb := NewClassBuilder("com/example/Empty", 52)
	cb.SetSourceFile("Empty.java")

	golden := []string{
		"package com.example;",
		"class Empty",
		"{",
		"}",
	}

	runGoldenTest(t, cb, golden, nil)
}

// --- Test 2: Constructor calling super() ---

func TestGolden_Constructor(t *testing.T) {
	cb := NewClassBuilder("com/example/Person", 52)
	cb.SetSourceFile("Person.java")

	// Add a String field: name
	cb.AddField(0x0002, "name", "Ljava/lang/String;") // private

	// Constructor: public Person() { super(); }
	superInitRef := cb.AddMethodRef("java/lang/Object", "<init>", "()V")
	cb.AddMethod(0x0001, "<init>", "()V", 1, 1, []byte{
		opALOAD_0,
		opINVOKESPECIAL, byte(superInitRef >> 8), byte(superInitRef),
		opRETURN,
	})

	golden := []string{
		"package com.example;",
		"class Person",
		"private String name;",
	}

	notExpected := []string{
		"interface", // should NOT be an interface
	}

	runGoldenTest(t, cb, golden, notExpected)
}

// --- Test 3: Method with arithmetic ---

func TestGolden_ArithmeticMethod(t *testing.T) {
	cb := NewClassBuilder("com/example/Calculator", 52)
	cb.SetSourceFile("Calculator.java")

	// Constructor
	superInitRef := cb.AddMethodRef("java/lang/Object", "<init>", "()V")
	cb.AddMethod(0x0001, "<init>", "()V", 1, 1, []byte{
		opALOAD_0,
		opINVOKESPECIAL, byte(superInitRef >> 8), byte(superInitRef),
		opRETURN,
	})

	// public int add(int a, int b) { return a + b; }
	cb.AddMethod(0x0001, "add", "(II)I", 2, 3, []byte{
		opILOAD_1,
		opILOAD_2,
		opIADD,
		opIRETURN,
	})

	// public static int multiply(int x, int y) { return x * y; }
	cb.AddMethod(0x0009, "multiply", "(II)I", 2, 2, []byte{ // public static
		opILOAD_1, // actually iload_0 for static (no this)
		opILOAD_2, // iload_1
		opIMUL,
		opIRETURN,
	})

	golden := []string{
		"package com.example;",
		"class Calculator",
		"add",
		"multiply",
		"int",
		"static",
	}

	runGoldenTest(t, cb, golden, nil)
}

// --- Test 4: Static field + System.out.println ---

func TestGolden_HelloWorld(t *testing.T) {
	cb := NewClassBuilder("com/example/HelloWorld", 52)
	cb.SetSourceFile("HelloWorld.java")

	// public static final String GREETING = "Hello, World!";
	cb.AddField(0x0019, "GREETING", "Ljava/lang/String;") // public static final

	// Constructor
	superInitRef := cb.AddMethodRef("java/lang/Object", "<init>", "()V")
	cb.AddMethod(0x0001, "<init>", "()V", 1, 1, []byte{
		opALOAD_0,
		opINVOKESPECIAL, byte(superInitRef >> 8), byte(superInitRef),
		opRETURN,
	})

	// public static void main(String[] args) { System.out.println("Hello, World!"); }
	outRef := cb.AddFieldRef("java/lang/System", "out", "Ljava/io/PrintStream;")
	helloStr := cb.AddStringConst("Hello, World!")
	printlnRef := cb.AddMethodRef("java/io/PrintStream", "println", "(Ljava/lang/String;)V")

	cb.AddMethod(0x0009, "main", "([Ljava/lang/String;)V", 2, 1, []byte{
		opGETSTATIC, byte(outRef >> 8), byte(outRef),
		opLDC, byte(helloStr),
		opINVOKEVIRTUAL, byte(printlnRef >> 8), byte(printlnRef),
		opRETURN,
	})

	golden := []string{
		"package com.example;",
		"class HelloWorld",
		"GREETING",
		"String",
		"main",
		"static",
		"final",
	}

	runGoldenTest(t, cb, golden, nil)
}

// --- Test 5: Interface ---

func TestGolden_Interface(t *testing.T) {
	cb := NewClassBuilder("com/example/Greetable", 52)
	cb.SetAccessFlags(0x0601) // ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT
	cb.SetSourceFile("Greetable.java")

	// abstract method: String greet(String name)
	cb.AddMethod(0x0401, "greet", "(Ljava/lang/String;)Ljava/lang/String;", 0, 0, nil) // public abstract

	golden := []string{
		"package com.example;",
		"interface Greetable",
		"greet",
		"String",
	}

	notExpected := []string{
		"class Greetable", // should be interface, not class
	}

	runGoldenTest(t, cb, golden, notExpected)
}

// --- Test 6: Class implementing interface ---

func TestGolden_ImplementsInterface(t *testing.T) {
	cb := NewClassBuilder("com/example/Greeter", 52)
	cb.SetSourceFile("Greeter.java")
	cb.AddInterface("com/example/Greetable")

	// Constructor
	superInitRef := cb.AddMethodRef("java/lang/Object", "<init>", "()V")
	cb.AddMethod(0x0001, "<init>", "()V", 1, 1, []byte{
		opALOAD_0,
		opINVOKESPECIAL, byte(superInitRef >> 8), byte(superInitRef),
		opRETURN,
	})

	// public String greet(String name) { return "Hello, " + name; }
	// Simplified bytecode: just return the arg for now
	cb.AddMethod(0x0001, "greet", "(Ljava/lang/String;)Ljava/lang/String;", 1, 2, []byte{
		opALOAD_1,
		opARETURN,
	})

	golden := []string{
		"package com.example;",
		"class Greeter",
		"implements Greetable",
		"greet",
		"String",
	}

	runGoldenTest(t, cb, golden, nil)
}

// --- Test 7: Enum class ---

func TestGolden_Enum(t *testing.T) {
	cb := NewClassBuilder("com/example/Color", 52)
	cb.SetAccessFlags(0x4031) // ACC_PUBLIC | ACC_SUPER | ACC_FINAL | ACC_ENUM
	cb.SetSuper("java/lang/Enum")
	cb.SetSourceFile("Color.java")

	// Enum constants as static fields
	cb.AddField(0x4019, "RED", "Lcom/example/Color;")   // public static final enum
	cb.AddField(0x4019, "GREEN", "Lcom/example/Color;") // public static final enum
	cb.AddField(0x4019, "BLUE", "Lcom/example/Color;")  // public static final enum

	golden := []string{
		"package com.example;",
		"enum Color",
		"RED",
		"GREEN",
		"BLUE",
	}

	notExpected := []string{
		"class Color",     // should be enum, not class
		"interface Color", // should not be interface
	}

	runGoldenTest(t, cb, golden, notExpected)
}

// --- Test 8: Multiple fields with different types ---

func TestGolden_MultipleFields(t *testing.T) {
	cb := NewClassBuilder("com/example/Config", 52)
	cb.SetSourceFile("Config.java")

	cb.AddField(0x0002, "host", "Ljava/lang/String;")  // private String
	cb.AddField(0x0002, "port", "I")                   // private int
	cb.AddField(0x0002, "debug", "Z")                  // private boolean
	cb.AddField(0x0002, "timeout", "J")                // private long
	cb.AddField(0x0002, "ratio", "D")                  // private double
	cb.AddField(0x0001, "tags", "[Ljava/lang/String;") // public String[]

	golden := []string{
		"package com.example;",
		"class Config",
		"host",
		"port",
		"debug",
		"timeout",
		"ratio",
		"tags",
		"String",
		"int",
		"boolean",
		"long",
		"double",
	}

	runGoldenTest(t, cb, golden, nil)
}

// --- Golden test runner ---

func runGoldenTest(t *testing.T, cb *ClassBuilder, expectedContains []string, notExpected []string) {
	t.Helper()

	classData := cb.Build()

	// Decompile with native decompiler
	native := &decompiler.NativeDecompiler{}
	source, err := native.DecompileBytes(classData)
	if err != nil {
		t.Fatalf("Native decompilation failed: %v", err)
	}

	t.Logf("=== Native output (%d lines) ===\n%s", strings.Count(source, "\n"), source)

	// Check expected constructs
	for _, expected := range expectedContains {
		if !strings.Contains(source, expected) {
			t.Errorf("Native output missing expected construct: %q", expected)
		}
	}

	// Check constructs that should NOT be present
	for _, ne := range notExpected {
		if strings.Contains(source, ne) {
			t.Errorf("Native output unexpectedly contains: %q", ne)
		}
	}

	// Analyze metrics
	metrics := analyzeOutput(source)
	t.Logf("Metrics: lines=%d imports=%d classes=%d methods=%d completeness=%.1f syntax_errors=%d",
		metrics.LineCount, metrics.ImportCount, metrics.ClassCount, metrics.MethodCount,
		metrics.Completeness, metrics.SyntaxErrors)

	if metrics.SyntaxErrors > 0 {
		t.Errorf("Unbalanced braces detected: %d syntax errors", metrics.SyntaxErrors)
	}

	// If external decompilers are available, run comparison
	runExternalComparison(t, classData, cb.thisClass)
}

func runExternalComparison(t *testing.T, classData []byte, className string) {
	t.Helper()

	native := &decompiler.NativeDecompiler{}
	h := NewHarness(native.DecompileBytes)
	defer h.Close()

	if len(h.ExternalTools) == 0 {
		t.Log("No external decompilers available — skipping cross-comparison")
		return
	}

	result := h.Compare(classData, className)

	for dc, output := range result.Outputs {
		if dc == DecompilerNative {
			continue
		}
		t.Logf("=== %s output (%d lines) ===\n%s", dc, strings.Count(output, "\n"), output)
	}

	for dc, errMsg := range result.Errors {
		t.Logf("%s error: %s", dc, errMsg)
	}

	for _, diff := range result.Differences {
		t.Logf("DIFF [%s] %s: %s", diff.Decompiler, diff.Category, diff.Description)
	}

	// Log comparison metrics
	for dc, m := range result.Metrics {
		t.Logf("%s metrics: lines=%d imports=%d classes=%d methods=%d completeness=%.1f",
			dc, m.LineCount, m.ImportCount, m.ClassCount, m.MethodCount, m.Completeness)
	}
}

// --- Golden file persistence ---

// WriteGoldenFiles saves .class and decompiled .java files to the testdata directory
// for manual inspection and regression testing.
func WriteGoldenFiles(t *testing.T) {
	t.Helper()

	testdataDir := filepath.Join("testdata", "golden")
	if err := os.MkdirAll(testdataDir, 0o755); err != nil {
		t.Fatalf("creating testdata dir: %v", err)
	}

	scenarios := []struct {
		name string
		cb   *ClassBuilder
	}{
		{"Empty", func() *ClassBuilder {
			cb := NewClassBuilder("com/example/Empty", 52)
			cb.SetSourceFile("Empty.java")
			return cb
		}()},
		{"Calculator", func() *ClassBuilder {
			cb := NewClassBuilder("com/example/Calculator", 52)
			cb.SetSourceFile("Calculator.java")
			superRef := cb.AddMethodRef("java/lang/Object", "<init>", "()V")
			cb.AddMethod(0x0001, "<init>", "()V", 1, 1, []byte{
				opALOAD_0, opINVOKESPECIAL, byte(superRef >> 8), byte(superRef), opRETURN,
			})
			cb.AddMethod(0x0001, "add", "(II)I", 2, 3, []byte{
				opILOAD_1, opILOAD_2, opIADD, opIRETURN,
			})
			return cb
		}()},
		{"HelloWorld", func() *ClassBuilder {
			cb := NewClassBuilder("com/example/HelloWorld", 52)
			cb.SetSourceFile("HelloWorld.java")
			superRef := cb.AddMethodRef("java/lang/Object", "<init>", "()V")
			cb.AddMethod(0x0001, "<init>", "()V", 1, 1, []byte{
				opALOAD_0, opINVOKESPECIAL, byte(superRef >> 8), byte(superRef), opRETURN,
			})
			outRef := cb.AddFieldRef("java/lang/System", "out", "Ljava/io/PrintStream;")
			helloStr := cb.AddStringConst("Hello, World!")
			printRef := cb.AddMethodRef("java/io/PrintStream", "println", "(Ljava/lang/String;)V")
			cb.AddMethod(0x0009, "main", "([Ljava/lang/String;)V", 2, 1, []byte{
				opGETSTATIC, byte(outRef >> 8), byte(outRef),
				opLDC, byte(helloStr),
				opINVOKEVIRTUAL, byte(printRef >> 8), byte(printRef),
				opRETURN,
			})
			return cb
		}()},
	}

	native := &decompiler.NativeDecompiler{}

	for _, s := range scenarios {
		classData := s.cb.Build()

		// Write .class file
		classPath := filepath.Join(testdataDir, s.name+".class")
		if err := os.WriteFile(classPath, classData, 0o644); err != nil {
			t.Errorf("write %s.class: %v", s.name, err)
			continue
		}

		// Write native .java
		source, err := native.DecompileBytes(classData)
		if err != nil {
			t.Errorf("decompile %s: %v", s.name, err)
			continue
		}

		javaPath := filepath.Join(testdataDir, s.name+".java")
		if err := os.WriteFile(javaPath, []byte(source), 0o644); err != nil {
			t.Errorf("write %s.java: %v", s.name, err)
			continue
		}

		t.Logf("Wrote %s.class + %s.java", s.name, s.name)
	}
}

func TestWriteGoldenFiles(t *testing.T) {
	if os.Getenv("WRITE_GOLDEN") != "1" {
		t.Skip("Set WRITE_GOLDEN=1 to regenerate golden files")
	}
	WriteGoldenFiles(t)
}
