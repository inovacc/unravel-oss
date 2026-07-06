/*
Copyright (c) 2026 Security Research
*/
package compare

import (
	"encoding/binary"
	"strings"
	"testing"
)

// buildMinimalClassBytes constructs a valid .class file in-memory.
func buildMinimalClassBytes(className string, majorVersion uint16) []byte {
	var buf []byte

	buf = binary.BigEndian.AppendUint32(buf, 0xCAFEBABE)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, majorVersion)

	// Constant pool: 5 entries (#1..#4)
	buf = binary.BigEndian.AppendUint16(buf, 5)

	// #1: CONSTANT_Class -> #3
	buf = append(buf, 7)
	buf = binary.BigEndian.AppendUint16(buf, 3)

	// #2: CONSTANT_Class -> #4
	buf = append(buf, 7)
	buf = binary.BigEndian.AppendUint16(buf, 4)

	// #3: UTF8 -> className
	buf = append(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(className)))
	buf = append(buf, []byte(className)...)

	// #4: UTF8 -> "java/lang/Object"
	super := "java/lang/Object"
	buf = append(buf, 1)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(super)))
	buf = append(buf, []byte(super)...)

	// Access flags: public + super
	buf = binary.BigEndian.AppendUint16(buf, 0x0021)
	// this_class: #1
	buf = binary.BigEndian.AppendUint16(buf, 1)
	// super_class: #2
	buf = binary.BigEndian.AppendUint16(buf, 2)
	// interfaces: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// fields: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// methods: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)
	// attributes: 0
	buf = binary.BigEndian.AppendUint16(buf, 0)

	return buf
}

func TestAnalyzeOutput(t *testing.T) {
	tests := []struct {
		name             string
		source           string
		wantLineCount    int
		wantImports      int
		wantClasses      int
		wantPackage      bool
		wantCompileReady bool
	}{
		{
			name: "complete class",
			source: `package com.example;

import java.util.List;
import java.util.Map;

public class Hello {
    public void greet() {
        System.out.println("Hello");
    }
}
`,
			wantLineCount:    11,
			wantImports:      2,
			wantClasses:      1,
			wantPackage:      true,
			wantCompileReady: true,
		},
		{
			name: "empty class",
			source: `public class Empty {
}
`,
			wantLineCount:    3,
			wantImports:      0,
			wantClasses:      1,
			wantPackage:      false,
			wantCompileReady: true,
		},
		{
			name: "unbalanced braces",
			source: `public class Broken {
    public void foo() {
`,
			wantLineCount:    3,
			wantClasses:      1,
			wantPackage:      false,
			wantCompileReady: false,
		},
		{
			name:             "empty output",
			source:           "",
			wantLineCount:    1,
			wantClasses:      0,
			wantPackage:      false,
			wantCompileReady: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := analyzeOutput(tt.source)
			if m.LineCount != tt.wantLineCount {
				t.Errorf("LineCount = %d, want %d", m.LineCount, tt.wantLineCount)
			}
			if m.ImportCount != tt.wantImports {
				t.Errorf("ImportCount = %d, want %d", m.ImportCount, tt.wantImports)
			}
			if m.ClassCount != tt.wantClasses {
				t.Errorf("ClassCount = %d, want %d", m.ClassCount, tt.wantClasses)
			}
			if m.HasPackage != tt.wantPackage {
				t.Errorf("HasPackage = %v, want %v", m.HasPackage, tt.wantPackage)
			}
			if m.CompileReady != tt.wantCompileReady {
				t.Errorf("CompileReady = %v, want %v", m.CompileReady, tt.wantCompileReady)
			}
		})
	}
}

func TestComputeDifferences(t *testing.T) {
	native := `package com.example;

import java.util.List;

public class Hello {
    public void greet() {
    }
}
`
	reference := `package com.example;

import java.util.List;
import java.util.Map;

public class Hello {
    public void greet() {
    }

    public String toString() {
        return "Hello";
    }
}
`

	diffs := computeDifferences(native, reference, DecompilerCFR)

	// Should detect missing import and different method count
	hasImportDiff := false
	hasMethodDiff := false
	for _, d := range diffs {
		if d.Category == "missing_import" {
			hasImportDiff = true
		}
		if d.Category == "method_count" {
			hasMethodDiff = true
		}
	}

	if !hasImportDiff {
		t.Error("expected missing_import difference")
	}
	if !hasMethodDiff {
		t.Error("expected method_count difference")
	}
}

func TestHarnessCompare(t *testing.T) {
	// Create a harness with a mock native decompiler
	h := NewHarness(func(data []byte) (string, error) {
		return "public class Test {\n}\n", nil
	})
	defer h.Close()

	classData := buildMinimalClassBytes("Test", 52)
	result := h.Compare(classData, "Test")

	if _, ok := result.Outputs[DecompilerNative]; !ok {
		t.Error("expected native output")
	}
	if result.ClassName != "Test" {
		t.Errorf("ClassName = %q, want %q", result.ClassName, "Test")
	}
}

func TestSummary(t *testing.T) {
	results := []*Result{
		{
			ClassName: "Test1",
			Outputs:   map[Decompiler]string{DecompilerNative: "class Test1 {}"},
			Metrics:   map[Decompiler]*Metrics{DecompilerNative: {CompileReady: true, ClassCount: 1}},
		},
		{
			ClassName: "Test2",
			Outputs:   map[Decompiler]string{DecompilerNative: "class Test2 {}"},
			Metrics:   map[Decompiler]*Metrics{DecompilerNative: {CompileReady: false, ClassCount: 1}},
		},
	}

	summary := Summary(results)
	if !strings.Contains(summary, "Total classes: 2") {
		t.Error("expected total classes in summary")
	}
	if !strings.Contains(summary, "Native success: 2/2") {
		t.Error("expected native success count")
	}
	if !strings.Contains(summary, "Native compile-ready: 1/2") {
		t.Error("expected compile-ready count")
	}
}

func TestExtractImports(t *testing.T) {
	lines := []string{
		"package com.example;",
		"",
		"import java.util.List;",
		"import java.util.Map;",
		"",
		"public class Test {",
		"}",
	}

	imports := extractImports(lines)
	if len(imports) != 2 {
		t.Errorf("got %d imports, want 2", len(imports))
	}
}
