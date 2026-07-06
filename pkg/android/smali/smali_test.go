/*
Copyright (c) 2026 Security Research
*/
package smali

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/android/dex"
)

func TestOpcodeTable(t *testing.T) {
	// Verify key opcodes are registered correctly
	tests := []struct {
		op       byte
		mnemonic string
		format   Format
		ref      RefKind
		width    int
	}{
		{0x00, "nop", Fmt10x, RefNone, 1},
		{0x01, "move", Fmt12x, RefNone, 1},
		{0x0e, "return-void", Fmt10x, RefNone, 1},
		{0x12, "const/4", Fmt11n, RefNone, 1},
		{0x1a, "const-string", Fmt21c, RefString, 2},
		{0x1c, "const-class", Fmt21c, RefType, 2},
		{0x22, "new-instance", Fmt21c, RefType, 2},
		{0x28, "goto", Fmt10t, RefNone, 1},
		{0x32, "if-eq", Fmt22t, RefNone, 2},
		{0x52, "iget", Fmt22c, RefField, 2},
		{0x6e, "invoke-virtual", Fmt35c, RefMethod, 3},
		{0x70, "invoke-direct", Fmt35c, RefMethod, 3},
		{0x71, "invoke-static", Fmt35c, RefMethod, 3},
		{0x90, "add-int", Fmt23x, RefNone, 2},
		{0xb0, "add-int/2addr", Fmt12x, RefNone, 1},
		{0xd0, "add-int/lit16", Fmt22s, RefNone, 2},
		{0xd8, "add-int/lit8", Fmt22b, RefNone, 2},
	}

	for _, tt := range tests {
		info := Opcodes[tt.op]
		if info.Mnemonic != tt.mnemonic {
			t.Errorf("opcode 0x%02x: mnemonic = %q, want %q", tt.op, info.Mnemonic, tt.mnemonic)
		}
		if info.Format != tt.format {
			t.Errorf("opcode 0x%02x: format = %d, want %d", tt.op, info.Format, tt.format)
		}
		if info.Ref != tt.ref {
			t.Errorf("opcode 0x%02x: ref = %d, want %d", tt.op, info.Ref, tt.ref)
		}
		if info.Width != tt.width {
			t.Errorf("opcode 0x%02x: width = %d, want %d", tt.op, info.Width, tt.width)
		}
	}
}

func TestDecodeInstructions(t *testing.T) {
	dexFile := &dex.DexFile{
		Strings: []string{"Hello", "World", "test"},
		Types:   []string{"Ljava/lang/String;", "Ljava/lang/Object;"},
		Methods: []dex.MethodRef{
			{ClassName: "Lcom/example/Main;", Name: "toString"},
		},
		Fields: []dex.FieldRef{
			{ClassName: "Lcom/example/Main;", Name: "count", TypeName: "I"},
		},
	}

	tests := []struct {
		name    string
		insns   []byte
		wantOps []string
	}{
		{
			name:    "nop",
			insns:   []byte{0x00, 0x00},
			wantOps: []string{"nop"},
		},
		{
			name:    "return-void",
			insns:   []byte{0x0e, 0x00},
			wantOps: []string{"return-void"},
		},
		{
			name:    "const/4",
			insns:   []byte{0x12, 0x30}, // v0, #3
			wantOps: []string{"const/4"},
		},
		{
			name:    "const-string",
			insns:   []byte{0x1a, 0x00, 0x00, 0x00}, // v0, string@0 ("Hello")
			wantOps: []string{"const-string"},
		},
		{
			name: "multiple instructions",
			insns: []byte{
				0x12, 0x10, // const/4 v0, #1
				0x0e, 0x00, // return-void
			},
			wantOps: []string{"const/4", "return-void"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insns := decodeInstructions(tt.insns, dexFile)
			if len(insns) != len(tt.wantOps) {
				t.Fatalf("got %d instructions, want %d", len(insns), len(tt.wantOps))
			}
			for i, insn := range insns {
				if insn.Info.Mnemonic != tt.wantOps[i] {
					t.Errorf("insn[%d] = %q, want %q", i, insn.Info.Mnemonic, tt.wantOps[i])
				}
			}
		})
	}
}

func TestAccessFlagsToString(t *testing.T) {
	tests := []struct {
		flags    uint32
		forClass bool
		want     string
	}{
		{AccPublic, true, "public"},
		{AccPublic | AccStatic, false, "public static"},
		{AccPrivate | AccFinal, false, "private final"},
		{AccPublic | AccAbstract | AccInterface, true, "public interface abstract"},
		{AccPublic | AccConstructor, false, "public constructor"},
		{0, false, ""},
	}

	for _, tt := range tests {
		got := AccessFlagsToString(tt.flags, tt.forClass)
		if got != tt.want {
			t.Errorf("AccessFlagsToString(0x%x, %v) = %q, want %q", tt.flags, tt.forClass, got, tt.want)
		}
	}
}

func TestClassToPath(t *testing.T) {
	tests := []struct {
		className string
		want      string
	}{
		{"Lcom/example/MyClass;", "com/example/MyClass.smali"},
		{"Ljava/lang/String;", "java/lang/String.smali"},
		{"LMain;", "Main.smali"},
	}

	for _, tt := range tests {
		got := classToPath(tt.className, "")
		// Normalize separators for comparison
		got = strings.ReplaceAll(got, "\\", "/")
		if got != tt.want {
			t.Errorf("classToPath(%q) = %q, want %q", tt.className, got, tt.want)
		}
	}
}

func TestFormatClass(t *testing.T) {
	cls := dex.ClassDef{
		ClassName:   "Lcom/example/Main;",
		Superclass:  "Ljava/lang/Object;",
		SourceFile:  "Main.java",
		AccessFlags: AccPublic,
	}

	methods := []MethodCode{
		{
			MethodName:  "<init>",
			AccessFlags: AccPublic | AccConstructor,
			Registers:   1,
			Descriptor:  "()V",
			Instructions: []Instruction{
				{Offset: 0, Info: Opcodes[0x0e]}, // return-void
			},
		},
	}

	output := FormatClass(cls, methods)

	if !strings.Contains(output, ".class public Lcom/example/Main;") {
		t.Error("missing class declaration")
	}
	if !strings.Contains(output, ".super Ljava/lang/Object;") {
		t.Error("missing super declaration")
	}
	if !strings.Contains(output, ".source \"Main.java\"") {
		t.Error("missing source declaration")
	}
	if !strings.Contains(output, ".method public constructor <init>()V") {
		t.Error("missing method declaration")
	}
	if !strings.Contains(output, "return-void") {
		t.Error("missing return-void instruction")
	}
	if !strings.Contains(output, ".end method") {
		t.Error("missing .end method")
	}
}

func TestReadULEB128(t *testing.T) {
	tests := []struct {
		name string
		buf  []byte
		want uint32
		pos  int
	}{
		{"zero", []byte{0x00}, 0, 1},
		{"one", []byte{0x01}, 1, 1},
		{"127", []byte{0x7F}, 127, 1},
		{"128", []byte{0x80, 0x01}, 128, 2},
		{"300", []byte{0xAC, 0x02}, 300, 2},
		{"16256", []byte{0x80, 0x7F}, 16256, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, pos := readULEB128(tt.buf, 0)
			if got != tt.want {
				t.Errorf("readULEB128 = %d, want %d", got, tt.want)
			}
			if pos != tt.pos {
				t.Errorf("readULEB128 pos = %d, want %d", pos, tt.pos)
			}
		})
	}
}

func TestResolveRef(t *testing.T) {
	dexFile := &dex.DexFile{
		Strings: []string{"Hello", "World"},
		Types:   []string{"Ljava/lang/String;"},
		Methods: []dex.MethodRef{{ClassName: "LTest;", Name: "foo"}},
		Fields:  []dex.FieldRef{{ClassName: "LTest;", Name: "bar", TypeName: "I"}},
	}

	tests := []struct {
		kind RefKind
		idx  int
		want string
	}{
		{RefString, 0, `"Hello"`},
		{RefString, 1, `"World"`},
		{RefString, 99, "string@0063"},
		{RefType, 0, "Ljava/lang/String;"},
		{RefType, 99, "type@0063"},
		{RefMethod, 0, "LTest;->foo"},
		{RefField, 0, "LTest;->bar:I"},
		{RefNone, 0, "@0000"},
	}

	for _, tt := range tests {
		got := resolveRef(tt.kind, tt.idx, dexFile)
		if got != tt.want {
			t.Errorf("resolveRef(%d, %d) = %q, want %q", tt.kind, tt.idx, got, tt.want)
		}
	}
}
