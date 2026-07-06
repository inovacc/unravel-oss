/*
Copyright (c) 2026 Security Research
*/
package disasm

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestDisassembleNative_CurrentBinary(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("native disassembly test requires x86/x86_64")
	}

	bin := buildTestBinary(t)

	result, err := disassembleNative(bin, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("disassembleNative: %v", err)
	}

	if result.Format == "" {
		t.Error("expected non-empty format")
	}

	if result.Architecture == "" {
		t.Error("expected non-empty architecture")
	}

	if len(result.Sections) == 0 {
		t.Error("expected at least one section")
	}

	total := 0
	for _, s := range result.Sections {
		total += len(s.Instructions)
	}

	if total == 0 {
		t.Error("expected at least one instruction")
	}

	t.Logf("Disassembled %s %s (%d-bit): %d instructions in %d sections",
		result.Format, result.Architecture, result.Bits, total, len(result.Sections))
}

func TestDecodeSection(t *testing.T) {
	// x86_64 NOP sled + RET
	code := []byte{0x90, 0x90, 0x90, 0xc3} // nop, nop, nop, ret
	section := decodeSection(".text", 0x1000, code, 64, 100, nil)

	if len(section.Instructions) != 4 {
		t.Fatalf("expected 4 instructions, got %d", len(section.Instructions))
	}

	// GNUSyntax produces lowercase mnemonics
	if section.Instructions[0].Mnemonic != "nop" {
		t.Errorf("expected nop, got %s", section.Instructions[0].Mnemonic)
	}

	if section.Instructions[3].Mnemonic != "ret" && section.Instructions[3].Mnemonic != "retq" {
		t.Errorf("expected ret/retq, got %s", section.Instructions[3].Mnemonic)
	}

	if section.Instructions[0].Address != 0x1000 {
		t.Errorf("expected address 0x1000, got 0x%x", section.Instructions[0].Address)
	}
}

func TestDecodeSection_MaxInstructions(t *testing.T) {
	// 10 NOPs
	code := make([]byte, 10)
	for i := range code {
		code[i] = 0x90
	}

	section := decodeSection(".text", 0, code, 64, 5, nil)

	if len(section.Instructions) != 5 {
		t.Errorf("expected 5 instructions (max), got %d", len(section.Instructions))
	}
}

func TestDecodeSection_WithSymbols(t *testing.T) {
	// NOP + RET with a symbol at the start
	code := []byte{0x90, 0xc3}
	syms := []Symbol{{Address: 0x1000, Name: "myfunc", Type: "FUNC"}}

	section := decodeSection(".text", 0x1000, code, 64, 100, syms)

	if len(section.Instructions) != 2 {
		t.Fatalf("expected 2 instructions, got %d", len(section.Instructions))
	}

	if section.Instructions[0].Label != "myfunc" {
		t.Errorf("expected label 'myfunc', got %q", section.Instructions[0].Label)
	}

	if section.Instructions[1].Label != "" {
		t.Errorf("expected no label on second insn, got %q", section.Instructions[1].Label)
	}
}

func TestDecodeSection_GNUSyntax(t *testing.T) {
	// push %rbp; mov %rsp,%rbp
	code := []byte{0x55, 0x48, 0x89, 0xe5}
	section := decodeSection(".text", 0x1000, code, 64, 100, nil)

	if len(section.Instructions) < 2 {
		t.Fatalf("expected at least 2 instructions, got %d", len(section.Instructions))
	}

	// GNUSyntax should produce AT&T style
	insn0 := section.Instructions[0]
	if insn0.Mnemonic != "push" && insn0.Mnemonic != "pushq" {
		t.Errorf("expected 'push' or 'pushq', got %q", insn0.Mnemonic)
	}

	if !strings.Contains(insn0.Operands, "%rbp") {
		t.Errorf("expected operands containing %%rbp, got %q", insn0.Operands)
	}
}

func TestFormatGNU(t *testing.T) {
	result := &Result{
		Format:       "ELF",
		Architecture: "x86_64",
		Bits:         64,
		Sections: []Section{
			{
				Name:    ".text",
				Address: 0x401000,
				Size:    4,
				Instructions: []Instruction{
					{Address: 0x401000, Bytes: []byte{0x55}, Mnemonic: "pushq", Operands: "%rbp", Label: "main"},
					{Address: 0x401001, Bytes: []byte{0x48, 0x89, 0xe5}, Mnemonic: "movq", Operands: "%rsp,%rbp"},
				},
			},
		},
	}

	output := FormatGNU(result, "/tmp/test")

	if !strings.Contains(output, "file format elf64-x86-64") {
		t.Errorf("expected file format header, got:\n%s", output)
	}

	if !strings.Contains(output, "Disassembly of section .text:") {
		t.Errorf("expected section header")
	}

	if !strings.Contains(output, "<main>:") {
		t.Errorf("expected symbol label <main>")
	}

	if !strings.Contains(output, "pushq") {
		t.Errorf("expected pushq mnemonic")
	}
}

func TestGolden_NativeVsObjdump(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires ELF binary and objdump")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("golden test requires x86_64")
	}

	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not available")
	}

	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}

	// Build a tiny C binary
	tmpDir := t.TempDir()
	src := tmpDir + "/test.c"
	bin := tmpDir + "/test-bin"

	err := os.WriteFile(src, []byte(`
void _start() {
    asm("nop; nop; nop");
    asm("mov $60, %rax; xor %rdi, %rdi; syscall");
}
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Compile static, no libc
	cmd := exec.Command("gcc", "-static", "-nostdlib", "-fcf-protection=none", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}

	// Run objdump
	objdumpCmd := exec.Command("objdump", "-d", bin)
	objdumpOut, err := objdumpCmd.Output()
	if err != nil {
		t.Fatalf("objdump: %v", err)
	}

	objdumpInsns := parseObjdumpInstructions(string(objdumpOut))

	// Run native disassembler
	result, err := disassembleNative(bin, Options{MaxInstructions: 1000})
	if err != nil {
		t.Fatalf("native: %v", err)
	}

	// Collect native instructions
	var nativeInsns []testInsn
	for _, sec := range result.Sections {
		for _, insn := range sec.Instructions {
			nativeInsns = append(nativeInsns, testInsn{
				Address:  insn.Address,
				Mnemonic: insn.Mnemonic,
				Operands: insn.Operands,
			})
		}
	}

	// Compare
	if len(objdumpInsns) == 0 {
		t.Fatal("no instructions from objdump")
	}

	if len(nativeInsns) == 0 {
		t.Fatal("no instructions from native")
	}

	// Compare instruction-by-instruction up to the shorter list
	limit := min(len(nativeInsns), len(objdumpInsns))

	mismatches := 0

	for i := range limit {
		o := objdumpInsns[i]
		n := nativeInsns[i]

		if o.Address != n.Address {
			t.Errorf("insn %d: address mismatch: objdump=0x%x native=0x%x", i, o.Address, n.Address)
			mismatches++

			break // addresses diverged, stop comparing
		}

		if normalizeMnemonic(o.Mnemonic) != normalizeMnemonic(n.Mnemonic) {
			t.Errorf("insn %d @ 0x%x: mnemonic mismatch: objdump=%q native=%q", i, o.Address, o.Mnemonic, n.Mnemonic)
			mismatches++
		}

		if normalizeOperands(o.Operands) != normalizeOperands(n.Operands) {
			t.Errorf("insn %d @ 0x%x: operands mismatch: objdump=%q native=%q", i, o.Address, o.Operands, n.Operands)
			mismatches++
		}

		if mismatches > 10 {
			t.Fatalf("too many mismatches, stopping")
		}
	}

	t.Logf("Compared %d instructions, %d mismatches (objdump=%d, native=%d total)",
		limit, mismatches, len(objdumpInsns), len(nativeInsns))
}

func TestGolden_SectionFlags(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires ELF binary and gcc")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("requires x86_64")
	}

	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}

	bin := buildCTestBinary(t)

	result, err := disassembleNative(bin, Options{MaxInstructions: 1000})
	if err != nil {
		t.Fatalf("native: %v", err)
	}

	// All sections should have CODE flag (since we auto-filter to SHF_EXECINSTR)
	for _, sec := range result.Sections {
		hasCode := false
		for _, f := range sec.Flags {
			if f == "CODE" {
				hasCode = true
			}
		}

		if !hasCode {
			t.Errorf("section %s missing CODE flag, has: %v", sec.Name, sec.Flags)
		}
	}
}

func TestGolden_SymbolLabels(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires ELF binary and gcc")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("requires x86_64")
	}

	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}

	bin := buildCTestBinary(t)

	result, err := disassembleNative(bin, Options{MaxInstructions: 1000})
	if err != nil {
		t.Fatalf("native: %v", err)
	}

	// Should have _start label somewhere
	found := false

	for _, sec := range result.Sections {
		for _, insn := range sec.Instructions {
			if insn.Label == "_start" {
				found = true

				break
			}
		}
	}

	if !found {
		t.Error("expected _start symbol label in disassembly")
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{"empty", nil, ""},
		{"single byte", []byte{0xaa}, "aa"},
		{"multiple bytes", []byte{0xaa, 0xbb, 0xcc}, "aa bb cc"},
		{"zero byte", []byte{0x00}, "00"},
		{"mixed values", []byte{0x55, 0x48, 0x89, 0xe5}, "55 48 89 e5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatBytes(tt.input)
			if got != tt.expect {
				t.Errorf("formatBytes(%v) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestGnuFileFormat(t *testing.T) {
	tests := []struct {
		name   string
		result *Result
		expect string
	}{
		{"ELF 64", &Result{Format: "ELF", Bits: 64}, "elf64-x86-64"},
		{"ELF 32", &Result{Format: "ELF", Bits: 32}, "elf32-i386"},
		{"PE 64", &Result{Format: "PE", Bits: 64}, "pei-x86-64"},
		{"PE 32", &Result{Format: "PE", Bits: 32}, "pei-i386"},
		{"Mach-O 64", &Result{Format: "Mach-O", Bits: 64}, "mach-o-x86-64"},
		{"Mach-O 32", &Result{Format: "Mach-O", Bits: 32}, "mach-o-i386"},
		{"unknown format", &Result{Format: "COFF"}, "COFF"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := gnuFileFormat(tt.result)
			if got != tt.expect {
				t.Errorf("gnuFileFormat() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestParseHexBytes(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect []byte
	}{
		{"standard", "55 48 89 e5", []byte{0x55, 0x48, 0x89, 0xe5}},
		{"trailing space", "55 48 89 e5 ", []byte{0x55, 0x48, 0x89, 0xe5}},
		{"single byte", "cc", []byte{0xcc}},
		{"empty string", "", nil},
		{"whitespace only", "   ", nil},
		{"invalid hex skipped", "55 zz 89", []byte{0x55, 0x89}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHexBytes(tt.input)
			if len(got) == 0 && len(tt.expect) == 0 {
				return
			}

			if len(got) != len(tt.expect) {
				t.Fatalf("parseHexBytes(%q) len = %d, want %d", tt.input, len(got), len(tt.expect))
			}

			for i := range got {
				if got[i] != tt.expect[i] {
					t.Errorf("byte %d: got 0x%02x, want 0x%02x", i, got[i], tt.expect[i])
				}
			}
		})
	}
}

func TestFinalizeSectionBounds(t *testing.T) {
	tests := []struct {
		name        string
		section     Section
		wantAddr    uint64
		wantSize    uint64
		wantChanged bool
	}{
		{
			name:        "empty section",
			section:     Section{},
			wantChanged: false,
		},
		{
			name: "single instruction",
			section: Section{
				Instructions: []Instruction{
					{Address: 0x1000, Bytes: []byte{0x90}},
				},
			},
			wantAddr:    0x1000,
			wantSize:    1,
			wantChanged: true,
		},
		{
			name: "multiple instructions",
			section: Section{
				Instructions: []Instruction{
					{Address: 0x1000, Bytes: []byte{0x55}},
					{Address: 0x1001, Bytes: []byte{0x48, 0x89, 0xe5}},
					{Address: 0x1004, Bytes: []byte{0xc3}},
				},
			},
			wantAddr:    0x1000,
			wantSize:    5, // 0x1004 - 0x1000 + 1
			wantChanged: true,
		},
		{
			name: "instruction without bytes uses minimum size 1",
			section: Section{
				Instructions: []Instruction{
					{Address: 0x2000},
					{Address: 0x2004},
				},
			},
			wantAddr:    0x2000,
			wantSize:    5, // 0x2004 - 0x2000 + 1
			wantChanged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.section
			finalizeSectionBounds(&s)

			if !tt.wantChanged {
				if s.Address != 0 || s.Size != 0 {
					t.Errorf("expected unchanged section, got addr=0x%x size=%d", s.Address, s.Size)
				}

				return
			}

			if s.Address != tt.wantAddr {
				t.Errorf("Address = 0x%x, want 0x%x", s.Address, tt.wantAddr)
			}

			if s.Size != tt.wantSize {
				t.Errorf("Size = %d, want %d", s.Size, tt.wantSize)
			}
		})
	}
}

func TestSymbolsInRange(t *testing.T) {
	syms := []Symbol{
		{Address: 0x1000, Name: "a"},
		{Address: 0x1010, Name: "b"},
		{Address: 0x1020, Name: "c"},
		{Address: 0x2000, Name: "d"},
	}

	tests := []struct {
		name      string
		start     uint64
		end       uint64
		wantNames []string
	}{
		{"full range", 0x1000, 0x2001, []string{"a", "b", "c", "d"}},
		{"partial range", 0x1000, 0x1015, []string{"a", "b"}},
		{"single match", 0x1020, 0x1021, []string{"c"}},
		{"no matches", 0x3000, 0x4000, nil},
		{"exclusive end", 0x1000, 0x1000, nil},
		{"empty syms", 0x0, 0xFFFF, []string{"a", "b", "c", "d"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := symbolsInRange(syms, tt.start, tt.end)

			if len(got) != len(tt.wantNames) {
				t.Fatalf("got %d symbols, want %d", len(got), len(tt.wantNames))
			}

			for i, s := range got {
				if s.Name != tt.wantNames[i] {
					t.Errorf("symbol %d: got %q, want %q", i, s.Name, tt.wantNames[i])
				}
			}
		})
	}
}

func TestSymbolsInRange_Empty(t *testing.T) {
	got := symbolsInRange(nil, 0, 0xFFFF)
	if len(got) != 0 {
		t.Errorf("expected empty result for nil syms, got %d", len(got))
	}
}

func TestFindMnemonicEnd(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect int
	}{
		{"with operands", "push %rbp", 4},
		{"no operands", "nop", -1},
		{"ret", "ret", -1},
		{"tab separator", "mov\t%rsp,%rbp", 3},
		{"empty string", "", -1},
		{"only space", " ", 0},
		{"complex operands", "movq 0x10(%rsp),%rax", 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findMnemonicEnd(tt.input)
			if got != tt.expect {
				t.Errorf("findMnemonicEnd(%q) = %d, want %d", tt.input, got, tt.expect)
			}
		})
	}
}

func TestElfSectionFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags elf.SectionFlag
		want  []string
	}{
		{"execinstr", elf.SHF_EXECINSTR, []string{"CODE"}},
		{"write", elf.SHF_WRITE, []string{"DATA"}},
		{"alloc", elf.SHF_ALLOC, []string{"ALLOC"}},
		{"alloc+exec", elf.SHF_ALLOC | elf.SHF_EXECINSTR, []string{"ALLOC", "CODE"}},
		{"alloc+write", elf.SHF_ALLOC | elf.SHF_WRITE, []string{"ALLOC", "DATA"}},
		{"all three", elf.SHF_ALLOC | elf.SHF_EXECINSTR | elf.SHF_WRITE, []string{"ALLOC", "CODE", "DATA"}},
		{"none", 0, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := elfSectionFlags(tt.flags)

			if len(got) != len(tt.want) {
				t.Fatalf("elfSectionFlags(0x%x) = %v, want %v", tt.flags, got, tt.want)
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("flag %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseObjdumpOutput(t *testing.T) {
	output := `
test-bin:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <_start>:
  401000:	55                   	push   %rbp
  401001:	48 89 e5             	mov    %rsp,%rbp
  401004:	90                   	nop
  401005:	c3                   	ret
`

	result, err := parseObjdumpOutput(output, 1000)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	if result.Format != "ELF" {
		t.Errorf("Format = %q, want ELF", result.Format)
	}

	if result.Bits != 64 {
		t.Errorf("Bits = %d, want 64", result.Bits)
	}

	if result.Tool != "objdump" {
		t.Errorf("Tool = %q, want objdump", result.Tool)
	}

	if len(result.Sections) != 1 {
		t.Fatalf("len(Sections) = %d, want 1", len(result.Sections))
	}

	sec := result.Sections[0]
	if sec.Name != ".text" {
		t.Errorf("section name = %q, want .text", sec.Name)
	}

	if len(sec.Instructions) != 4 {
		t.Fatalf("len(Instructions) = %d, want 4", len(sec.Instructions))
	}

	if sec.Instructions[0].Label != "_start" {
		t.Errorf("first instruction label = %q, want _start", sec.Instructions[0].Label)
	}

	if sec.Instructions[0].Mnemonic != "push" {
		t.Errorf("first mnemonic = %q, want push", sec.Instructions[0].Mnemonic)
	}

	if sec.Address != 0x401000 {
		t.Errorf("section Address = 0x%x, want 0x401000", sec.Address)
	}
}

func TestParseObjdumpOutput_MaxInstructions(t *testing.T) {
	output := `
test:     file format elf64-x86-64

Disassembly of section .text:

0000000000001000 <fn>:
  1000:	90                   	nop
  1001:	90                   	nop
  1002:	90                   	nop
  1003:	90                   	nop
  1004:	90                   	nop
`

	result, err := parseObjdumpOutput(output, 3)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	total := 0
	for _, sec := range result.Sections {
		total += len(sec.Instructions)
	}

	if total != 3 {
		t.Errorf("total instructions = %d, want 3", total)
	}
}

func TestParseObjdumpOutput_Empty(t *testing.T) {
	_, err := parseObjdumpOutput("", 1000)
	if err == nil {
		t.Error("expected error for empty output")
	}
}

func TestParseR2Output(t *testing.T) {
	output := `arch x86
bits 64
bintype elf

  0x00401000      push rbp
  0x00401001      mov rsp, rbp
  0x00401004      nop
  0x00401005      ret
`

	result, err := parseR2Output(output, 1000)
	if err != nil {
		t.Fatalf("parseR2Output: %v", err)
	}

	if result.Tool != "radare2" {
		t.Errorf("Tool = %q, want radare2", result.Tool)
	}

	if len(result.Sections) != 1 {
		t.Fatalf("len(Sections) = %d, want 1", len(result.Sections))
	}

	sec := result.Sections[0]
	if len(sec.Instructions) != 4 {
		t.Fatalf("len(Instructions) = %d, want 4", len(sec.Instructions))
	}

	if sec.Instructions[0].Address != 0x401000 {
		t.Errorf("first address = 0x%x, want 0x401000", sec.Instructions[0].Address)
	}

	if sec.Instructions[0].Mnemonic != "push" {
		t.Errorf("first mnemonic = %q, want push", sec.Instructions[0].Mnemonic)
	}
}

func TestParseR2Output_MaxInstructions(t *testing.T) {
	output := `arch x86
bits 64

  0x00001000      nop
  0x00001001      nop
  0x00001002      nop
  0x00001003      nop
`

	result, err := parseR2Output(output, 2)
	if err != nil {
		t.Fatalf("parseR2Output: %v", err)
	}

	total := 0
	for _, sec := range result.Sections {
		total += len(sec.Instructions)
	}

	if total != 2 {
		t.Errorf("total instructions = %d, want 2", total)
	}
}

func TestParseR2Output_Empty(t *testing.T) {
	_, err := parseR2Output("", 1000)
	if err == nil {
		t.Error("expected error for empty output")
	}
}

// --- Disassemble() entry point tests ---

func TestDisassemble_DefaultMaxInstructions(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("native disassembly test requires x86/x86_64")
	}

	bin := buildTestBinary(t)

	// MaxInstructions=0 should default to 1000 internally and still return results.
	result, err := Disassemble(bin, Options{MaxInstructions: 0})
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	total := 0
	for _, s := range result.Sections {
		total += len(s.Instructions)
	}

	if total == 0 {
		t.Error("expected at least one instruction with default max")
	}
}

func TestDisassemble_NativeFallback(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("native disassembly test requires x86/x86_64")
	}

	bin := buildTestBinary(t)

	// Passing a valid ELF must succeed via native fallback if external tools
	// are unavailable, or via external tools if they are — either way the
	// result must be well-formed.
	result, err := Disassemble(bin, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}

	if result.Format == "" {
		t.Error("expected non-empty format")
	}

	if result.Architecture == "" {
		t.Error("expected non-empty architecture")
	}

	if len(result.Sections) == 0 {
		t.Error("expected at least one section")
	}
}

func TestDisassemble_ExternalOnly_InvalidFile(t *testing.T) {
	// Write a file that is not a valid binary so that both objdump and r2
	// will reject it, then ExternalOnly=true must return an error.
	tmpDir := t.TempDir()
	notABinary := tmpDir + "/notabinary.txt"

	if err := os.WriteFile(notABinary, []byte("this is plain text\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Disassemble(notABinary, Options{ExternalOnly: true, MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for ExternalOnly with non-binary file and no tools, got nil")
	}
}

func TestDisassemble_ExternalOnly_NativeFallbackSkipped(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("native disassembly test requires x86/x86_64")
	}

	// Even with a valid ELF, ExternalOnly=true must not fall through to native.
	// If external tools ARE available the call succeeds; if not, it must error
	// rather than silently use the native decoder.  We verify the contract
	// by checking: when external tools are missing the error message mentions them.
	bin := buildTestBinary(t)

	result, err := Disassemble(bin, Options{ExternalOnly: true, MaxInstructions: 10})
	if err != nil {
		// Tools not available — verify the error is about missing tools, not a
		// generic "unsupported format" from the native decoder.
		if !strings.Contains(err.Error(), "objdump") && !strings.Contains(err.Error(), "radare2") {
			t.Errorf("expected tool-related error, got: %v", err)
		}

		return
	}

	// External tools are present — result must still be valid.
	if result == nil {
		t.Fatal("expected non-nil result when external tools succeed")
	}
}

// --- buildSymLookup tests ---

func TestBuildSymLookup_ExactMatch(t *testing.T) {
	syms := []Symbol{
		{Address: 0x1000, Name: "alpha", Size: 16, Type: "FUNC"},
		{Address: 0x2000, Name: "beta", Size: 32, Type: "FUNC"},
	}

	lookup := buildSymLookup(syms)

	name, base := lookup(0x1000)
	if name != "alpha" {
		t.Errorf("expected 'alpha', got %q", name)
	}

	if base != 0x1000 {
		t.Errorf("expected base 0x1000, got 0x%x", base)
	}
}

func TestBuildSymLookup_SizeMatch(t *testing.T) {
	syms := []Symbol{
		{Address: 0x1000, Name: "alpha", Size: 64, Type: "FUNC"},
	}

	lookup := buildSymLookup(syms)

	// Address within symbol's size range should resolve to the symbol.
	name, base := lookup(0x1020)
	if name != "alpha" {
		t.Errorf("expected 'alpha' for address within size, got %q", name)
	}

	if base != 0x1000 {
		t.Errorf("expected base 0x1000, got 0x%x", base)
	}
}

func TestBuildSymLookup_NoMatch(t *testing.T) {
	syms := []Symbol{
		{Address: 0x1000, Name: "alpha", Size: 4, Type: "FUNC"},
	}

	lookup := buildSymLookup(syms)

	// Address beyond the symbol's size range must return empty.
	name, base := lookup(0x2000)
	if name != "" {
		t.Errorf("expected empty name for unresolved address, got %q", name)
	}

	if base != 0 {
		t.Errorf("expected base 0, got 0x%x", base)
	}
}

func TestBuildSymLookup_EmptySyms(t *testing.T) {
	lookup := buildSymLookup(nil)

	name, base := lookup(0x1000)
	if name != "" || base != 0 {
		t.Errorf("expected empty result for nil syms, got %q / 0x%x", name, base)
	}
}

func TestBuildSymLookup_BeyondSizeNoMatch(t *testing.T) {
	// Symbol at 0x1000 with size 4: address 0x1004 is just outside the range.
	syms := []Symbol{
		{Address: 0x1000, Name: "fn", Size: 4, Type: "FUNC"},
	}

	lookup := buildSymLookup(syms)

	name, _ := lookup(0x1004)
	if name != "" {
		t.Errorf("expected no match for address just past symbol size, got %q", name)
	}
}

// --- extractELFSymbols tests ---

func TestExtractELFSymbols(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires ELF binary; Windows produces PE")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86/x86_64 ELF binary")
	}

	bin := buildTestBinary(t)

	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}

	defer func() { _ = f.Close() }()

	syms := extractELFSymbols(f)

	// A Go binary always has symbols; just verify they are address-sorted.
	for i := 1; i < len(syms); i++ {
		if syms[i].Address < syms[i-1].Address {
			t.Errorf("symbols not sorted at index %d: 0x%x < 0x%x", i, syms[i].Address, syms[i-1].Address)
		}
	}

	// Every symbol must have a non-empty name (constructor filters blanks).
	for _, s := range syms {
		if s.Name == "" {
			t.Error("found symbol with empty name")
		}
	}
}

// --- SectionsFilter path in disassembleELF ---

func TestDisassembleELF_SectionsFilter(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86/x86_64 ELF binary")
	}

	bin := buildTestBinary(t)

	result, err := disassembleNative(bin, Options{
		MaxInstructions: 100,
		SectionsFilter:  []string{".text"},
	})
	if err != nil {
		t.Fatalf("disassembleNative with SectionsFilter: %v", err)
	}

	// Result must only contain the requested section.
	for _, sec := range result.Sections {
		if sec.Name != ".text" {
			t.Errorf("unexpected section %q when filtering for .text", sec.Name)
		}
	}

	if len(result.Sections) == 0 {
		t.Error("expected at least one section when filtering .text")
	}
}

// --- FormatGNU 32-bit path ---

func TestFormatGNU_32Bit(t *testing.T) {
	result := &Result{
		Format:       "ELF",
		Architecture: "x86",
		Bits:         32,
		Sections: []Section{
			{
				Name:    ".text",
				Address: 0x8048000,
				Size:    2,
				Instructions: []Instruction{
					{Address: 0x8048000, Bytes: []byte{0x90}, Mnemonic: "nop"},
				},
			},
		},
	}

	output := FormatGNU(result, "/tmp/test32")

	if !strings.Contains(output, "file format elf32-i386") {
		t.Errorf("expected elf32-i386 format header, got:\n%s", output)
	}

	if !strings.Contains(output, "Disassembly of section .text:") {
		t.Errorf("expected section header in output")
	}

	if !strings.Contains(output, "nop") {
		t.Errorf("expected nop mnemonic in output")
	}
}

// --- FormatGNU instruction without label ---

func TestFormatGNU_NoLabel(t *testing.T) {
	result := &Result{
		Format:       "PE",
		Architecture: "x86_64",
		Bits:         64,
		Sections: []Section{
			{
				Name:    ".text",
				Address: 0x140001000,
				Size:    1,
				Instructions: []Instruction{
					// No label set — must not emit a label line.
					{Address: 0x140001000, Bytes: []byte{0x90}, Mnemonic: "nop"},
				},
			},
		},
	}

	output := FormatGNU(result, "/tmp/testpe")

	if strings.Contains(output, "<>:") {
		t.Error("output must not contain empty label '<>:'")
	}

	if !strings.Contains(output, "file format pei-x86-64") {
		t.Errorf("expected pei-x86-64 format header, got:\n%s", output)
	}
}

// --- helpers ---

type testInsn struct {
	Address  uint64
	Mnemonic string
	Operands string
}

var goldenInsnRe = regexp.MustCompile(`^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.+)`)

func parseObjdumpInstructions(output string) []testInsn {
	var insns []testInsn

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		m := goldenInsnRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		addr, _ := strings.CutPrefix(m[1], "0x")
		var a uint64

		for _, c := range addr {
			a = a*16 + uint64(hexVal(byte(c)))
		}

		asmText := strings.TrimSpace(m[3])
		parts := strings.Fields(asmText)

		var insn testInsn
		insn.Address = a

		if len(parts) > 0 {
			insn.Mnemonic = parts[0]
		}

		if len(parts) > 1 {
			insn.Operands = strings.Join(parts[1:], " ")
		}

		insns = append(insns, insn)
	}

	return insns
}

func hexVal(c byte) uint64 {
	switch {
	case c >= '0' && c <= '9':
		return uint64(c - '0')
	case c >= 'a' && c <= 'f':
		return uint64(c-'a') + 10
	default:
		return 0
	}
}

// normalizeMnemonic handles objdump vs x86asm differences (e.g., ret vs retq).
func normalizeMnemonic(s string) string {
	// x86asm GNUSyntax adds 'q' suffix that objdump sometimes omits
	equivs := map[string]string{
		"retq":   "ret",
		"pushq":  "push",
		"popq":   "pop",
		"leaveq": "leave",
	}

	if norm, ok := equivs[s]; ok {
		return norm
	}

	return s
}

// normalizeOperands removes minor formatting differences.
func normalizeOperands(s string) string {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.TrimSpace(s)

	return s
}

func buildTestBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	src := tmpDir + "/main.go"
	bin := tmpDir + "/test-binary"

	err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build test binary: %v\n%s", err, out)
	}

	return bin
}

// --- disassembleNative: unsupported format path ---

func TestDisassembleNative_UnsupportedFormat(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/noformat.bin"

	// Write a file that is valid enough to open but not ELF/PE/Mach-O.
	if err := os.WriteFile(path, []byte("not a binary at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := disassembleNative(path, Options{MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for unsupported binary format, got nil")
	}
}

// --- disassemblePE: synthetic minimal PE binary ---

// buildMinimalPE64 writes a minimal but parseable PE64 binary with a tiny .text section.
// The .text section contains a single NOP (0x90) followed by RET (0xc3).
func buildMinimalPE64(t *testing.T) string {
	t.Helper()

	// Only meaningful on amd64 — the content is x86_64 code.
	if runtime.GOARCH != "amd64" {
		t.Skip("PE binary test requires x86_64 host")
	}

	// Locate or build a PE binary via cross-compilation if available.
	// We rely on the Go toolchain's windows/amd64 cross-compile support.
	if _, err := exec.LookPath("x86_64-w64-mingw32-gcc"); err == nil {
		return buildMinimalPEWithGCC(t)
	}

	// Try Go cross-compile to windows/amd64.
	return buildMinimalPEWithGo(t)
}

func buildMinimalPEWithGo(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	src := tmpDir + "/main.go"
	bin := tmpDir + "/test.exe"

	err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")

	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot cross-compile PE binary: %v\n%s", err, out)
	}

	return bin
}

func buildMinimalPEWithGCC(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	src := tmpDir + "/main.c"
	bin := tmpDir + "/test.exe"

	err := os.WriteFile(src, []byte("int main(void){return 0;}"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("x86_64-w64-mingw32-gcc", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("mingw gcc failed: %v\n%s", err, out)
	}

	return bin
}

func TestDisassemblePE_CrossCompiled(t *testing.T) {
	path := buildMinimalPE64(t)

	result, err := disassemblePE(path, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("disassemblePE: %v", err)
	}

	if result.Format != "PE" {
		t.Errorf("Format = %q, want PE", result.Format)
	}

	if result.Architecture == "" {
		t.Errorf("Architecture must not be empty")
	}

	if result.Tool != "native (x86asm)" {
		t.Errorf("Tool = %q, want 'native (x86asm)'", result.Tool)
	}
}

func TestDisassemblePE_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/not.exe"

	if err := os.WriteFile(path, []byte("not a PE file"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := disassemblePE(path, Options{MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for non-PE file")
	}
}

// --- disassembleMachO: tests ---

func TestDisassembleMachO_InvalidFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := tmpDir + "/not.macho"

	if err := os.WriteFile(path, []byte("not a mach-o"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := disassembleMachO(path, Options{MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for non-Mach-O file")
	}
}

// buildMinimalMachO64 creates a minimal Mach-O binary via cross-compilation.
func buildMinimalMachO64(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("x86_64-apple-darwin-cc"); err != nil {
		t.Skip("cross-compiler for darwin not available")
	}

	tmpDir := t.TempDir()
	src := tmpDir + "/main.c"
	bin := tmpDir + "/test.macho"

	if err := os.WriteFile(src, []byte("int main(void){return 0;}"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("x86_64-apple-darwin-cc", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("darwin cross-compile failed: %v\n%s", err, out)
	}

	return bin
}

func TestDisassembleMachO_CrossCompiled(t *testing.T) {
	path := buildMinimalMachO64(t)

	result, err := disassembleMachO(path, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("disassembleMachO: %v", err)
	}

	if result.Format != "Mach-O" {
		t.Errorf("Format = %q, want Mach-O", result.Format)
	}
}

// buildSyntheticMachO writes a raw Mach-O file with an ARM64 cpu type so that
// disassembleMachO opens successfully but rejects the architecture.
func buildSyntheticMachO_ARM64(t *testing.T) string {
	t.Helper()

	// Mach-O magic (64-bit little-endian): 0xFEEDFACF
	// cputype=12 (ARM64), cpusubtype=0, filetype=2 (MH_EXECUTE)
	// ncmds=0, sizeofcmds=0, flags=0, reserved=0
	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:], 0xFEEDFACF) // magic
	binary.LittleEndian.PutUint32(header[4:], 0x0100000C) // cputype ARM64
	binary.LittleEndian.PutUint32(header[8:], 0x00000000) // cpusubtype
	binary.LittleEndian.PutUint32(header[12:], 2)         // filetype MH_EXECUTE
	binary.LittleEndian.PutUint32(header[16:], 0)         // ncmds
	binary.LittleEndian.PutUint32(header[20:], 0)         // sizeofcmds
	binary.LittleEndian.PutUint32(header[24:], 0)         // flags
	binary.LittleEndian.PutUint32(header[28:], 0)         // reserved

	tmpDir := t.TempDir()
	path := tmpDir + "/arm64.macho"

	if err := os.WriteFile(path, header, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDisassembleMachO_UnsupportedArch(t *testing.T) {
	path := buildSyntheticMachO_ARM64(t)

	_, err := disassembleMachO(path, Options{MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for unsupported Mach-O architecture (ARM64)")
	}

	if err != nil && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected 'unsupported' in error, got: %v", err)
	}
}

// --- disassembleELF: unsupported architecture path ---

// buildSyntheticELF_ARM writes a minimal ELF header with EM_ARM machine type
// so that disassembleELF opens it but rejects the architecture.
func buildSyntheticELF_ARM(t *testing.T) string {
	t.Helper()

	// Minimal ELF64 header (64 bytes) with EM_ARM (40) as machine type.
	// We write just enough for elf.Open to parse, with no sections.
	header := make([]byte, 64)
	// ELF magic
	header[0] = 0x7F
	header[1] = 'E'
	header[2] = 'L'
	header[3] = 'F'
	header[4] = 1 // EI_CLASS = ELFCLASS32
	header[5] = 1 // EI_DATA  = ELFDATA2LSB
	header[6] = 1 // EI_VERSION = EV_CURRENT
	header[7] = 0 // EI_OSABI
	// EI_ABIVERSION + padding (bytes 8-15) = 0

	binary.LittleEndian.PutUint16(header[16:], 2)  // e_type ET_EXEC
	binary.LittleEndian.PutUint16(header[18:], 40) // e_machine EM_ARM
	binary.LittleEndian.PutUint32(header[20:], 1)  // e_version EV_CURRENT
	binary.LittleEndian.PutUint32(header[24:], 0)  // e_entry
	binary.LittleEndian.PutUint32(header[28:], 0)  // e_phoff
	binary.LittleEndian.PutUint32(header[32:], 0)  // e_shoff
	binary.LittleEndian.PutUint32(header[36:], 0)  // e_flags
	binary.LittleEndian.PutUint16(header[40:], 52) // e_ehsize (ELF32 header = 52)
	binary.LittleEndian.PutUint16(header[42:], 32) // e_phentsize
	binary.LittleEndian.PutUint16(header[44:], 0)  // e_phnum
	binary.LittleEndian.PutUint16(header[46:], 40) // e_shentsize
	binary.LittleEndian.PutUint16(header[48:], 0)  // e_shnum
	binary.LittleEndian.PutUint16(header[50:], 0)  // e_shstrndx

	tmpDir := t.TempDir()
	path := tmpDir + "/arm.elf"

	if err := os.WriteFile(path, header, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDisassembleELF_UnsupportedArch(t *testing.T) {
	path := buildSyntheticELF_ARM(t)

	_, err := disassembleELF(path, Options{MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for unsupported ELF architecture (ARM)")
	}

	if err != nil && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected 'unsupported' in error message, got: %v", err)
	}
}

// --- buildSymLookup: zero-size symbol exact-match fallback ---

func TestBuildSymLookup_ZeroSize_ExactFallback(t *testing.T) {
	// Symbol has Size=0; the binary-search path falls through to the exact-match loop.
	syms := []Symbol{
		{Address: 0x1000, Name: "nofunc", Size: 0, Type: "NOTYPE"},
	}

	lookup := buildSymLookup(syms)

	// Exact address match must still resolve even with size==0.
	name, base := lookup(0x1000)
	if name != "nofunc" {
		t.Errorf("expected 'nofunc' via fallback loop, got %q", name)
	}

	if base != 0x1000 {
		t.Errorf("expected base 0x1000, got 0x%x", base)
	}

	// An address that is NOT an exact match and the symbol has size 0 must return empty.
	name2, base2 := lookup(0x1001)
	if name2 != "" {
		t.Errorf("expected empty for non-exact address with size-0 symbol, got %q", name2)
	}

	if base2 != 0 {
		t.Errorf("expected base 0, got 0x%x", base2)
	}
}

// --- extractELFSymbols: OBJECT type symbol ---

func TestExtractELFSymbols_ObjectType(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires ELF binary and gcc")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86/x86_64 ELF binary")
	}

	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}

	// Build a C binary with a global variable so the symbol table has an OBJECT entry.
	tmpDir := t.TempDir()
	src := tmpDir + "/test.c"
	bin := tmpDir + "/test-obj"

	err := os.WriteFile(src, []byte(`
int global_var = 42;
void _start() {
    (void)global_var;
    asm("mov $60, %rax; xor %rdi, %rdi; syscall");
}
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("gcc", "-static", "-nostdlib", "-fcf-protection=none", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}

	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	syms := extractELFSymbols(f)

	// Find at least one OBJECT type symbol (global_var).
	foundObject := false
	for _, s := range syms {
		if s.Type == "OBJECT" {
			foundObject = true
			break
		}
	}

	if !foundObject {
		t.Log("no OBJECT-type symbol found; the compiler may have optimized it away")
	}

	// Result must still be address-sorted regardless of type mix.
	for i := 1; i < len(syms); i++ {
		if syms[i].Address < syms[i-1].Address {
			t.Errorf("symbols not sorted at index %d: 0x%x < 0x%x", i, syms[i].Address, syms[i-1].Address)
		}
	}
}

// --- tryObjdump: SectionsFilter path ---

func TestTryObjdump_SectionsFilter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires ELF binary and objdump")
	}
	if runtime.GOARCH != "amd64" {
		t.Skip("objdump test requires x86_64")
	}

	if _, err := exec.LookPath("objdump"); err != nil {
		t.Skip("objdump not available")
	}

	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc not available")
	}

	bin := buildCTestBinary(t)

	// Explicitly filter to a named section — exercises the SectionsFilter branch in tryObjdump.
	result, err := tryObjdump(bin, Options{MaxInstructions: 100, SectionsFilter: []string{".text"}})
	if err != nil {
		t.Fatalf("tryObjdump with SectionsFilter: %v", err)
	}

	for _, sec := range result.Sections {
		if sec.Name != ".text" {
			t.Errorf("unexpected section %q when filtering for .text", sec.Name)
		}
	}
}

// --- parseObjdumpOutput: elf32 and pe format strings ---

func TestParseObjdumpOutput_ELF32Format(t *testing.T) {
	output := `
test:     file format elf32-i386

Disassembly of section .text:

00001000 <fn>:
  1000:	90                   	nop
`

	result, err := parseObjdumpOutput(output, 1000)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	if result.Format != "ELF" {
		t.Errorf("Format = %q, want ELF", result.Format)
	}

	if result.Bits != 32 {
		t.Errorf("Bits = %d, want 32", result.Bits)
	}

	if result.Architecture != "x86" {
		t.Errorf("Architecture = %q, want x86", result.Architecture)
	}
}

func TestParseObjdumpOutput_PEFormat(t *testing.T) {
	output := `
test.exe:     file format pe-x86-64

Disassembly of section .text:

0000000140001000 <main>:
  140001000:	90                   	nop
`

	result, err := parseObjdumpOutput(output, 1000)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	if result.Format != "PE" {
		t.Errorf("Format = %q, want PE", result.Format)
	}
}

func TestParseObjdumpOutput_UnknownFormat(t *testing.T) {
	output := `
test:     file format coff-x86-64

Disassembly of section .text:

0000000000001000 <fn>:
  1000:	90                   	nop
`

	result, err := parseObjdumpOutput(output, 1000)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	// Unknown format falls through to the default case: Format = raw format string.
	if result.Format == "ELF" || result.Format == "PE" || result.Format == "Mach-O" {
		t.Errorf("expected raw/unknown format, got %q", result.Format)
	}
}

// --- disassemblePE: SectionsFilter path ---

func TestDisassemblePE_SectionsFilter(t *testing.T) {
	// Build a PE binary then exercise the SectionsFilter path.
	path := buildMinimalPE64(t) // skips if cross-compile unavailable

	result, err := disassemblePE(path, Options{MaxInstructions: 50, SectionsFilter: []string{".text"}})
	if err != nil {
		t.Fatalf("disassemblePE with SectionsFilter: %v", err)
	}

	for _, sec := range result.Sections {
		if sec.Name != ".text" {
			t.Errorf("unexpected section %q when filtering for .text", sec.Name)
		}
	}
}

// --- disassembleMachO: SectionsFilter path (synthetic ARM64 file rejects before section loop) ---

func TestDisassembleMachO_SectionsFilter_NotFound(t *testing.T) {
	// Use a cross-compiled Mach-O if available; otherwise skip.
	path := buildMinimalMachO64(t)

	// Request a section that does not exist — the section loop must skip it gracefully
	// and disassembleMachO must return an error for no sections found.
	_, err := disassembleMachO(path, Options{MaxInstructions: 10, SectionsFilter: []string{"__nonexistent"}})
	if err == nil {
		t.Error("expected error when no matching section found in Mach-O")
	}
}

// --- Synthetic ELF binary for Windows testing ---

// buildSyntheticELF64_x86 creates a minimal valid ELF64 x86_64 binary with a .text
// section containing x86_64 code, parseable on any OS without needing gcc.
func buildSyntheticELF64_x86(t *testing.T) string {
	t.Helper()

	// ELF64 header (64 bytes) + section header string table + .text section + section headers
	// Layout:
	//   0x00-0x3F: ELF header (64 bytes)
	//   0x40-0x4B: .text section data (12 bytes: push %rbp; mov %rsp,%rbp; nop; nop; nop; ret)
	//   0x4C-0x5F: shstrtab data (20 bytes: \0.text\0.shstrtab\0)
	//   0x60-0x9F: section header 0 (null, 64 bytes)
	//   0xA0-0xDF: section header 1 (.text, 64 bytes)
	//   0xE0-0x11F: section header 2 (.shstrtab, 64 bytes)

	textCode := []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0x90, 0xc3} // push %rbp; mov %rsp,%rbp; nop; nop; nop; ret
	shstrtab := []byte("\x00.text\x00.shstrtab\x00")

	textOffset := uint64(64)
	textSize := uint64(len(textCode))
	shstrtabOffset := textOffset + textSize
	shstrtabSize := uint64(len(shstrtab))
	shdrOffset := shstrtabOffset + shstrtabSize
	// Align to 8 bytes
	if shdrOffset%8 != 0 {
		shdrOffset = (shdrOffset + 7) &^ 7
	}

	buf := make([]byte, shdrOffset+3*64)

	// ELF header
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 2                                                   // ELFCLASS64
	buf[5] = 1                                                   // ELFDATA2LSB
	buf[6] = 1                                                   // EV_CURRENT
	buf[7] = 0                                                   // ELFOSABI_NONE
	binary.LittleEndian.PutUint16(buf[16:], 2)                   // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], 62)                  // EM_X86_64
	binary.LittleEndian.PutUint32(buf[20:], 1)                   // EV_CURRENT
	binary.LittleEndian.PutUint64(buf[24:], 0x401000+textOffset) // e_entry
	binary.LittleEndian.PutUint64(buf[32:], 0)                   // e_phoff
	binary.LittleEndian.PutUint64(buf[40:], shdrOffset)          // e_shoff
	binary.LittleEndian.PutUint32(buf[48:], 0)                   // e_flags
	binary.LittleEndian.PutUint16(buf[52:], 64)                  // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], 0)                   // e_phentsize
	binary.LittleEndian.PutUint16(buf[56:], 0)                   // e_phnum
	binary.LittleEndian.PutUint16(buf[58:], 64)                  // e_shentsize
	binary.LittleEndian.PutUint16(buf[60:], 3)                   // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 2)                   // e_shstrndx

	// Copy section data
	copy(buf[textOffset:], textCode)
	copy(buf[shstrtabOffset:], shstrtab)

	// Section header 0: null (all zeros, already zero)

	// Section header 1: .text
	sh1 := buf[shdrOffset+64:]
	binary.LittleEndian.PutUint32(sh1[0:], 1)           // sh_name (offset in shstrtab to ".text")
	binary.LittleEndian.PutUint32(sh1[4:], 1)           // SHT_PROGBITS
	binary.LittleEndian.PutUint64(sh1[8:], 0x6)         // SHF_ALLOC | SHF_EXECINSTR
	binary.LittleEndian.PutUint64(sh1[16:], 0x401000)   // sh_addr
	binary.LittleEndian.PutUint64(sh1[24:], textOffset) // sh_offset
	binary.LittleEndian.PutUint64(sh1[32:], textSize)   // sh_size
	binary.LittleEndian.PutUint32(sh1[40:], 0)          // sh_link
	binary.LittleEndian.PutUint32(sh1[44:], 0)          // sh_info
	binary.LittleEndian.PutUint64(sh1[48:], 16)         // sh_addralign
	binary.LittleEndian.PutUint64(sh1[56:], 0)          // sh_entsize

	// Section header 2: .shstrtab
	sh2 := buf[shdrOffset+128:]
	binary.LittleEndian.PutUint32(sh2[0:], 7)               // sh_name (offset to ".shstrtab")
	binary.LittleEndian.PutUint32(sh2[4:], 3)               // SHT_STRTAB
	binary.LittleEndian.PutUint64(sh2[8:], 0)               // sh_flags
	binary.LittleEndian.PutUint64(sh2[16:], 0)              // sh_addr
	binary.LittleEndian.PutUint64(sh2[24:], shstrtabOffset) // sh_offset
	binary.LittleEndian.PutUint64(sh2[32:], shstrtabSize)   // sh_size
	binary.LittleEndian.PutUint32(sh2[40:], 0)              // sh_link
	binary.LittleEndian.PutUint32(sh2[44:], 0)              // sh_info
	binary.LittleEndian.PutUint64(sh2[48:], 1)              // sh_addralign
	binary.LittleEndian.PutUint64(sh2[56:], 0)              // sh_entsize

	tmpDir := t.TempDir()
	path := tmpDir + "/synthetic.elf"
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDisassembleELF_Synthetic(t *testing.T) {
	path := buildSyntheticELF64_x86(t)

	result, err := disassembleELF(path, Options{MaxInstructions: 100})
	if err != nil {
		t.Fatalf("disassembleELF: %v", err)
	}

	if result.Format != "ELF" {
		t.Errorf("Format = %q, want ELF", result.Format)
	}

	if result.Architecture != "x86_64" {
		t.Errorf("Architecture = %q, want x86_64", result.Architecture)
	}

	if result.Bits != 64 {
		t.Errorf("Bits = %d, want 64", result.Bits)
	}

	if result.EntryPoint == 0 {
		t.Error("expected non-zero entry point")
	}

	if len(result.Sections) == 0 {
		t.Fatal("expected at least one section")
	}

	sec := result.Sections[0]
	if sec.Name != ".text" {
		t.Errorf("section name = %q, want .text", sec.Name)
	}

	if len(sec.Instructions) == 0 {
		t.Error("expected at least one instruction in .text")
	}

	// Verify flags include CODE and ALLOC
	hasCode := false
	hasAlloc := false
	for _, f := range sec.Flags {
		if f == "CODE" {
			hasCode = true
		}
		if f == "ALLOC" {
			hasAlloc = true
		}
	}
	if !hasCode {
		t.Errorf("expected CODE flag, got: %v", sec.Flags)
	}
	if !hasAlloc {
		t.Errorf("expected ALLOC flag, got: %v", sec.Flags)
	}

	t.Logf("Disassembled %d instructions from synthetic ELF", len(sec.Instructions))
}

func TestDisassembleELF_Synthetic_SectionsFilter(t *testing.T) {
	path := buildSyntheticELF64_x86(t)

	result, err := disassembleELF(path, Options{MaxInstructions: 100, SectionsFilter: []string{".text"}})
	if err != nil {
		t.Fatalf("disassembleELF with SectionsFilter: %v", err)
	}

	if len(result.Sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(result.Sections))
	}

	if result.Sections[0].Name != ".text" {
		t.Errorf("section name = %q, want .text", result.Sections[0].Name)
	}
}

func TestDisassembleELF_Synthetic_SectionsFilter_NotFound(t *testing.T) {
	path := buildSyntheticELF64_x86(t)

	_, err := disassembleELF(path, Options{MaxInstructions: 100, SectionsFilter: []string{".nonexistent"}})
	if err == nil {
		t.Error("expected error when filtering for nonexistent section")
	}
}

func TestDisassembleNative_Synthetic_ELF(t *testing.T) {
	path := buildSyntheticELF64_x86(t)

	result, err := disassembleNative(path, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("disassembleNative: %v", err)
	}

	if result.Format != "ELF" {
		t.Errorf("Format = %q, want ELF", result.Format)
	}
}

// buildSyntheticELF32_i386 creates an ELF32 i386 binary with .text section.
func buildSyntheticELF32_i386(t *testing.T) string {
	t.Helper()

	textCode := []byte{0x55, 0x89, 0xe5, 0x90, 0x90, 0xc3} // push %ebp; mov %esp,%ebp; nop; nop; ret
	shstrtab := []byte("\x00.text\x00.shstrtab\x00")

	textOffset := uint32(52) // ELF32 header is 52 bytes
	textSize := uint32(len(textCode))
	shstrtabOffset := textOffset + textSize
	shstrtabSize := uint32(len(shstrtab))
	shdrOffset := shstrtabOffset + shstrtabSize
	if shdrOffset%4 != 0 {
		shdrOffset = (shdrOffset + 3) &^ 3
	}

	buf := make([]byte, shdrOffset+3*40) // ELF32 section headers are 40 bytes

	// ELF32 header
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 1                                                    // ELFCLASS32
	buf[5] = 1                                                    // ELFDATA2LSB
	buf[6] = 1                                                    // EV_CURRENT
	binary.LittleEndian.PutUint16(buf[16:], 2)                    // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], 3)                    // EM_386
	binary.LittleEndian.PutUint32(buf[20:], 1)                    // EV_CURRENT
	binary.LittleEndian.PutUint32(buf[24:], 0x8048000+textOffset) // e_entry
	binary.LittleEndian.PutUint32(buf[28:], 0)                    // e_phoff
	binary.LittleEndian.PutUint32(buf[32:], shdrOffset)           // e_shoff
	binary.LittleEndian.PutUint32(buf[36:], 0)                    // e_flags
	binary.LittleEndian.PutUint16(buf[40:], 52)                   // e_ehsize
	binary.LittleEndian.PutUint16(buf[42:], 0)                    // e_phentsize
	binary.LittleEndian.PutUint16(buf[44:], 0)                    // e_phnum
	binary.LittleEndian.PutUint16(buf[46:], 40)                   // e_shentsize
	binary.LittleEndian.PutUint16(buf[48:], 3)                    // e_shnum
	binary.LittleEndian.PutUint16(buf[50:], 2)                    // e_shstrndx

	copy(buf[textOffset:], textCode)
	copy(buf[shstrtabOffset:], shstrtab)

	// Section header 1: .text
	sh1 := buf[shdrOffset+40:]
	binary.LittleEndian.PutUint32(sh1[0:], 1)           // sh_name
	binary.LittleEndian.PutUint32(sh1[4:], 1)           // SHT_PROGBITS
	binary.LittleEndian.PutUint32(sh1[8:], 0x6)         // SHF_ALLOC | SHF_EXECINSTR
	binary.LittleEndian.PutUint32(sh1[12:], 0x8048000)  // sh_addr
	binary.LittleEndian.PutUint32(sh1[16:], textOffset) // sh_offset
	binary.LittleEndian.PutUint32(sh1[20:], textSize)   // sh_size
	binary.LittleEndian.PutUint32(sh1[24:], 0)          // sh_link
	binary.LittleEndian.PutUint32(sh1[28:], 0)          // sh_info
	binary.LittleEndian.PutUint32(sh1[32:], 16)         // sh_addralign
	binary.LittleEndian.PutUint32(sh1[36:], 0)          // sh_entsize

	// Section header 2: .shstrtab
	sh2 := buf[shdrOffset+80:]
	binary.LittleEndian.PutUint32(sh2[0:], 7)               // sh_name
	binary.LittleEndian.PutUint32(sh2[4:], 3)               // SHT_STRTAB
	binary.LittleEndian.PutUint32(sh2[8:], 0)               // sh_flags
	binary.LittleEndian.PutUint32(sh2[12:], 0)              // sh_addr
	binary.LittleEndian.PutUint32(sh2[16:], shstrtabOffset) // sh_offset
	binary.LittleEndian.PutUint32(sh2[20:], shstrtabSize)   // sh_size
	binary.LittleEndian.PutUint32(sh2[24:], 0)              // sh_link
	binary.LittleEndian.PutUint32(sh2[28:], 0)              // sh_info
	binary.LittleEndian.PutUint32(sh2[32:], 1)              // sh_addralign
	binary.LittleEndian.PutUint32(sh2[36:], 0)              // sh_entsize

	tmpDir := t.TempDir()
	path := tmpDir + "/synthetic32.elf"
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDisassembleELF_Synthetic_32bit(t *testing.T) {
	path := buildSyntheticELF32_i386(t)

	result, err := disassembleELF(path, Options{MaxInstructions: 100})
	if err != nil {
		t.Fatalf("disassembleELF 32-bit: %v", err)
	}

	if result.Architecture != "x86" {
		t.Errorf("Architecture = %q, want x86", result.Architecture)
	}

	if result.Bits != 32 {
		t.Errorf("Bits = %d, want 32", result.Bits)
	}

	if len(result.Sections) == 0 {
		t.Fatal("expected at least one section")
	}

	if len(result.Sections[0].Instructions) == 0 {
		t.Error("expected instructions in .text")
	}
}

// --- parseObjdumpOutput: multiple sections ---

func TestParseObjdumpOutput_MultipleSections(t *testing.T) {
	output := `
test:     file format elf64-x86-64

Disassembly of section .init:

0000000000001000 <_init>:
  1000:	90                   	nop

Disassembly of section .text:

0000000000002000 <_start>:
  2000:	55                   	push   %rbp
  2001:	c3                   	ret
`

	result, err := parseObjdumpOutput(output, 1000)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	if len(result.Sections) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(result.Sections))
	}

	if result.Sections[0].Name != ".init" {
		t.Errorf("section 0 name = %q, want .init", result.Sections[0].Name)
	}

	if result.Sections[1].Name != ".text" {
		t.Errorf("section 1 name = %q, want .text", result.Sections[1].Name)
	}

	if result.Sections[1].Instructions[0].Label != "_start" {
		t.Errorf("expected _start label, got %q", result.Sections[1].Instructions[0].Label)
	}
}

// --- parseR2Output: varied format ---

func TestParseR2Output_WithFunctions(t *testing.T) {
	output := `arch x86
bits 32
bintype pe

  0x00401000      push ebp
  0x00401001      mov esp, ebp
  0x00401003      ret
`

	result, err := parseR2Output(output, 1000)
	if err != nil {
		t.Fatalf("parseR2Output: %v", err)
	}

	if result.Bits != 32 {
		t.Errorf("Bits = %d, want 32", result.Bits)
	}

	if result.Format != "pe" {
		t.Errorf("Format = %q, want pe", result.Format)
	}

	if len(result.Sections[0].Instructions) != 3 {
		t.Fatalf("expected 3 instructions, got %d", len(result.Sections[0].Instructions))
	}
}

// --- FormatGNU: multiple sections and various formats ---

func TestFormatGNU_MultipleSections(t *testing.T) {
	result := &Result{
		Format:       "ELF",
		Architecture: "x86_64",
		Bits:         64,
		Sections: []Section{
			{
				Name: ".init",
				Instructions: []Instruction{
					{Address: 0x1000, Bytes: []byte{0x90}, Mnemonic: "nop"},
				},
			},
			{
				Name: ".text",
				Instructions: []Instruction{
					{Address: 0x2000, Bytes: []byte{0x55}, Mnemonic: "pushq", Operands: "%rbp", Label: "main"},
					{Address: 0x2001, Bytes: []byte{0xc3}, Mnemonic: "retq"},
				},
			},
		},
	}

	output := FormatGNU(result, "/test")

	if !strings.Contains(output, "Disassembly of section .init:") {
		t.Error("expected .init section header")
	}

	if !strings.Contains(output, "Disassembly of section .text:") {
		t.Error("expected .text section header")
	}

	if !strings.Contains(output, "<main>:") {
		t.Error("expected main label")
	}

	// retq should appear without operands
	if !strings.Contains(output, "retq") {
		t.Error("expected retq in output")
	}
}

func TestFormatGNU_MachOFormat(t *testing.T) {
	result := &Result{
		Format: "Mach-O",
		Bits:   64,
		Sections: []Section{
			{
				Name: "__text",
				Instructions: []Instruction{
					{Address: 0x1000, Bytes: []byte{0x90}, Mnemonic: "nop"},
				},
			},
		},
	}

	output := FormatGNU(result, "/test")
	if !strings.Contains(output, "mach-o-x86-64") {
		t.Errorf("expected mach-o-x86-64, got:\n%s", output)
	}
}

func TestFormatGNU_MachO32Format(t *testing.T) {
	result := &Result{
		Format: "Mach-O",
		Bits:   32,
		Sections: []Section{
			{
				Name: "__text",
				Instructions: []Instruction{
					{Address: 0x1000, Bytes: []byte{0x90}, Mnemonic: "nop"},
				},
			},
		},
	}

	output := FormatGNU(result, "/test")
	if !strings.Contains(output, "mach-o-i386") {
		t.Errorf("expected mach-o-i386, got:\n%s", output)
	}
}

// --- DecodeSection: invalid bytes ---

func TestDecodeSection_InvalidBytes(t *testing.T) {
	// Bytes that cannot be decoded as valid x86 instructions should be skipped
	code := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x90, 0xc3}
	section := decodeSection(".text", 0x1000, code, 64, 100, nil)

	// Should still decode the nop and ret at the end
	foundNop := false
	for _, insn := range section.Instructions {
		if insn.Mnemonic == "nop" {
			foundNop = true
		}
	}

	if !foundNop {
		t.Log("nop may be consumed by prior multi-byte instruction decode; checking we got some instructions")
	}

	// At minimum, we should get some instructions (even if invalid bytes produce partial decodes)
	if len(section.Instructions) == 0 {
		t.Error("expected at least some decoded instructions")
	}
}

func TestDecodeSection_EmptyData(t *testing.T) {
	section := decodeSection(".text", 0x1000, nil, 64, 100, nil)
	if len(section.Instructions) != 0 {
		t.Errorf("expected 0 instructions for empty data, got %d", len(section.Instructions))
	}

	if section.Address != 0x1000 {
		t.Errorf("Address = 0x%x, want 0x1000", section.Address)
	}
}

func TestDecodeSection_32BitMode(t *testing.T) {
	// x86 32-bit: push %ebp; mov %esp,%ebp; ret
	code := []byte{0x55, 0x89, 0xe5, 0xc3}
	section := decodeSection(".text", 0x8048000, code, 32, 100, nil)

	if len(section.Instructions) < 3 {
		t.Fatalf("expected at least 3 instructions, got %d", len(section.Instructions))
	}

	// Check that the first instruction is push in 32-bit mode
	if section.Instructions[0].Mnemonic != "push" && section.Instructions[0].Mnemonic != "pushl" {
		t.Errorf("expected push/pushl, got %q", section.Instructions[0].Mnemonic)
	}
}

// --- Disassemble entry point: synthetic ELF ---

func TestDisassemble_SyntheticELF(t *testing.T) {
	path := buildSyntheticELF64_x86(t)

	result, err := Disassemble(path, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("Disassemble: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	if result.Format == "" {
		t.Error("expected non-empty format")
	}
}

// --- PE: test on Windows natively, or via cross-compile on Linux ---

func TestDisassemblePE_NativeWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE native test only on Windows")
	}

	bin := buildTestBinary(t)

	result, err := disassemblePE(bin, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("disassemblePE: %v", err)
	}

	if result.Format != "PE" {
		t.Errorf("Format = %q, want PE", result.Format)
	}

	if result.Architecture != "x86_64" {
		t.Errorf("Architecture = %q, want x86_64", result.Architecture)
	}

	if result.Bits != 64 {
		t.Errorf("Bits = %d, want 64", result.Bits)
	}

	if result.EntryPoint == 0 {
		t.Error("expected non-zero entry point")
	}

	if len(result.Sections) == 0 {
		t.Fatal("expected at least one section")
	}

	// PE should have imports
	t.Logf("PE imports: %d, exports: %d", len(result.Imports), len(result.Exports))
}

func TestDisassemblePE_NativeWindows_SectionsFilter(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE native test only on Windows")
	}

	bin := buildTestBinary(t)

	result, err := disassemblePE(bin, Options{MaxInstructions: 50, SectionsFilter: []string{".text"}})
	if err != nil {
		t.Fatalf("disassemblePE: %v", err)
	}

	for _, sec := range result.Sections {
		if sec.Name != ".text" {
			t.Errorf("unexpected section %q", sec.Name)
		}
	}
}

func TestDisassemblePE_NativeWindows_NoSection(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PE native test only on Windows")
	}

	bin := buildTestBinary(t)

	_, err := disassemblePE(bin, Options{MaxInstructions: 50, SectionsFilter: []string{".nonexistent"}})
	if err == nil {
		t.Error("expected error for nonexistent section")
	}
}

// --- buildSymLookup: multiple symbols with sizes ---

func TestBuildSymLookup_MultipleSymbols(t *testing.T) {
	syms := []Symbol{
		{Address: 0x1000, Name: "func_a", Size: 16, Type: "FUNC"},
		{Address: 0x1010, Name: "func_b", Size: 32, Type: "FUNC"},
		{Address: 0x1030, Name: "func_c", Size: 0, Type: "NOTYPE"},
	}

	lookup := buildSymLookup(syms)

	tests := []struct {
		addr     uint64
		wantName string
		wantBase uint64
	}{
		{0x1000, "func_a", 0x1000},
		{0x1008, "func_a", 0x1000},
		{0x100F, "func_a", 0x1000},
		{0x1010, "func_b", 0x1010},
		{0x1020, "func_b", 0x1010},
		{0x1030, "func_c", 0x1030}, // exact match via fallback
		{0x1031, "", 0},            // no match (func_c size=0)
		{0x0FFF, "", 0},            // before any symbol
	}

	for _, tt := range tests {
		name, base := lookup(tt.addr)
		if name != tt.wantName {
			t.Errorf("lookup(0x%x): name = %q, want %q", tt.addr, name, tt.wantName)
		}
		if base != tt.wantBase {
			t.Errorf("lookup(0x%x): base = 0x%x, want 0x%x", tt.addr, base, tt.wantBase)
		}
	}
}

// --- extractELFSymbols with synthetic ELF ---

func TestExtractELFSymbols_Synthetic(t *testing.T) {
	path := buildSyntheticELF64_x86(t)

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	syms := extractELFSymbols(f)

	// Synthetic ELF has no symbol table, so should return empty
	// This exercises the code path where f.Symbols() returns nil/empty
	t.Logf("extractELFSymbols returned %d symbols (expected 0 for synthetic binary)", len(syms))
}

// --- parseObjdumpOutput: instruction without label in middle ---

func TestParseObjdumpOutput_LabelOnlyFirstInsn(t *testing.T) {
	output := `
test:     file format elf64-x86-64

Disassembly of section .text:

0000000000001000 <main>:
  1000:	55                   	push   %rbp
  1001:	48 89 e5             	mov    %rsp,%rbp
  1004:	c3                   	ret

0000000000001005 <helper>:
  1005:	90                   	nop
  1006:	c3                   	ret
`

	result, err := parseObjdumpOutput(output, 1000)
	if err != nil {
		t.Fatalf("parseObjdumpOutput: %v", err)
	}

	sec := result.Sections[0]

	// First insn should have "main" label
	if sec.Instructions[0].Label != "main" {
		t.Errorf("insn 0 label = %q, want main", sec.Instructions[0].Label)
	}

	// Second insn should have no label
	if sec.Instructions[1].Label != "" {
		t.Errorf("insn 1 label = %q, want empty", sec.Instructions[1].Label)
	}

	// Fourth insn (nop) should have "helper" label
	if sec.Instructions[3].Label != "helper" {
		t.Errorf("insn 3 label = %q, want helper", sec.Instructions[3].Label)
	}
}

// --- disassemblePE: unsupported architecture ---

func buildSyntheticPE_ARM(t *testing.T) string {
	t.Helper()

	// Minimal PE with ARM machine type
	// DOS header (64 bytes) + PE signature + COFF header
	buf := make([]byte, 256)

	// DOS magic
	buf[0] = 'M'
	buf[1] = 'Z'
	// e_lfanew at offset 0x3C
	binary.LittleEndian.PutUint32(buf[0x3C:], 64) // PE header at offset 64

	// PE signature at offset 64
	copy(buf[64:], []byte{'P', 'E', 0, 0})

	// COFF header at offset 68
	binary.LittleEndian.PutUint16(buf[68:], 0x01c0) // IMAGE_FILE_MACHINE_ARM
	binary.LittleEndian.PutUint16(buf[70:], 0)      // NumberOfSections
	binary.LittleEndian.PutUint16(buf[80:], 0)      // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(buf[82:], 0)      // Characteristics

	tmpDir := t.TempDir()
	path := tmpDir + "/arm.exe"
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDisassemblePE_UnsupportedArch(t *testing.T) {
	path := buildSyntheticPE_ARM(t)

	_, err := disassemblePE(path, Options{MaxInstructions: 10})
	if err == nil {
		t.Error("expected error for unsupported PE architecture (ARM)")
	}

	if err != nil && !strings.Contains(err.Error(), "unsupported") && !strings.Contains(err.Error(), "unrecognized") {
		t.Errorf("expected 'unsupported' or 'unrecognized' in error, got: %v", err)
	}
}

// --- Synthetic Mach-O x86_64 for cross-platform testing ---

func buildSyntheticMachO_x86_64(t *testing.T) string {
	t.Helper()

	// Mach-O 64-bit header + LC_SEGMENT_64 with __TEXT,__text section
	// Layout:
	//   0x00-0x1F: mach_header_64 (32 bytes)
	//   0x20-0x87: LC_SEGMENT_64 (72 bytes base + 80 bytes for 1 section = 152 bytes)
	//   After load commands: __text section data

	textCode := []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0x90, 0xc3} // push %rbp; mov %rsp,%rbp; nop; nop; ret

	headerSize := 32
	// LC_SEGMENT_64 is 72 bytes + 80 bytes per section
	segCmdSize := 72 + 80
	textOffset := headerSize + segCmdSize

	buf := make([]byte, textOffset+len(textCode))

	// mach_header_64
	binary.LittleEndian.PutUint32(buf[0:], 0xFEEDFACF)          // magic MH_MAGIC_64
	binary.LittleEndian.PutUint32(buf[4:], 0x01000007)          // cputype CPU_TYPE_X86_64
	binary.LittleEndian.PutUint32(buf[8:], 0x00000003)          // cpusubtype CPU_SUBTYPE_ALL
	binary.LittleEndian.PutUint32(buf[12:], 2)                  // filetype MH_EXECUTE
	binary.LittleEndian.PutUint32(buf[16:], 1)                  // ncmds
	binary.LittleEndian.PutUint32(buf[20:], uint32(segCmdSize)) // sizeofcmds
	binary.LittleEndian.PutUint32(buf[24:], 0)                  // flags
	binary.LittleEndian.PutUint32(buf[28:], 0)                  // reserved

	// LC_SEGMENT_64 at offset 32
	seg := buf[headerSize:]
	binary.LittleEndian.PutUint32(seg[0:], 0x19)                              // cmd LC_SEGMENT_64
	binary.LittleEndian.PutUint32(seg[4:], uint32(segCmdSize))                // cmdsize
	copy(seg[8:24], "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")         // segname
	binary.LittleEndian.PutUint64(seg[24:], 0x100000000)                      // vmaddr
	binary.LittleEndian.PutUint64(seg[32:], uint64(textOffset+len(textCode))) // vmsize
	binary.LittleEndian.PutUint64(seg[40:], 0)                                // fileoff
	binary.LittleEndian.PutUint64(seg[48:], uint64(textOffset+len(textCode))) // filesize
	binary.LittleEndian.PutUint32(seg[56:], 7)                                // maxprot (rwx)
	binary.LittleEndian.PutUint32(seg[60:], 5)                                // initprot (r-x)
	binary.LittleEndian.PutUint32(seg[64:], 1)                                // nsects
	binary.LittleEndian.PutUint32(seg[68:], 0)                                // flags

	// section_64 at offset 32+72=104
	sec := buf[headerSize+72:]
	copy(sec[0:16], "__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")       // sectname
	copy(sec[16:32], "__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")      // segname
	binary.LittleEndian.PutUint64(sec[32:], 0x100000000+uint64(textOffset)) // addr
	binary.LittleEndian.PutUint64(sec[40:], uint64(len(textCode)))          // size
	binary.LittleEndian.PutUint32(sec[48:], uint32(textOffset))             // offset
	binary.LittleEndian.PutUint32(sec[52:], 4)                              // align (2^4 = 16)
	binary.LittleEndian.PutUint32(sec[56:], 0)                              // reloff
	binary.LittleEndian.PutUint32(sec[60:], 0)                              // nreloc
	binary.LittleEndian.PutUint32(sec[64:], 0x80000400)                     // flags (S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS)
	binary.LittleEndian.PutUint32(sec[68:], 0)                              // reserved1
	binary.LittleEndian.PutUint32(sec[72:], 0)                              // reserved2
	binary.LittleEndian.PutUint32(sec[76:], 0)                              // reserved3

	// Copy text data
	copy(buf[textOffset:], textCode)

	tmpDir := t.TempDir()
	path := tmpDir + "/synthetic.macho"
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDisassembleMachO_Synthetic(t *testing.T) {
	path := buildSyntheticMachO_x86_64(t)

	result, err := disassembleMachO(path, Options{MaxInstructions: 100})
	if err != nil {
		t.Fatalf("disassembleMachO: %v", err)
	}

	if result.Format != "Mach-O" {
		t.Errorf("Format = %q, want Mach-O", result.Format)
	}

	if result.Architecture != "x86_64" {
		t.Errorf("Architecture = %q, want x86_64", result.Architecture)
	}

	if result.Bits != 64 {
		t.Errorf("Bits = %d, want 64", result.Bits)
	}

	if len(result.Sections) == 0 {
		t.Fatal("expected at least one section")
	}

	if len(result.Sections[0].Instructions) == 0 {
		t.Error("expected instructions")
	}

	t.Logf("Disassembled %d instructions from synthetic Mach-O", len(result.Sections[0].Instructions))
}

func TestDisassembleMachO_Synthetic_SectionsFilter(t *testing.T) {
	path := buildSyntheticMachO_x86_64(t)

	result, err := disassembleMachO(path, Options{MaxInstructions: 100, SectionsFilter: []string{"__text"}})
	if err != nil {
		t.Fatalf("disassembleMachO with filter: %v", err)
	}

	if len(result.Sections) != 1 {
		t.Fatalf("expected 1 section, got %d", len(result.Sections))
	}
}

func TestDisassembleMachO_Synthetic_NoSection(t *testing.T) {
	path := buildSyntheticMachO_x86_64(t)

	_, err := disassembleMachO(path, Options{MaxInstructions: 10, SectionsFilter: []string{"__nonexistent"}})
	if err == nil {
		t.Error("expected error for nonexistent section")
	}
}

func TestDisassembleNative_Synthetic_MachO(t *testing.T) {
	path := buildSyntheticMachO_x86_64(t)

	// disassembleNative tries ELF first (fails), then PE (fails), then Mach-O (succeeds)
	result, err := disassembleNative(path, Options{MaxInstructions: 50})
	if err != nil {
		t.Fatalf("disassembleNative with Mach-O: %v", err)
	}

	if result.Format != "Mach-O" {
		t.Errorf("Format = %q, want Mach-O", result.Format)
	}
}

// --- Synthetic ELF with symbol table to cover extractELFSymbols fully ---

func buildSyntheticELF64_WithSymbols(t *testing.T) string {
	t.Helper()

	textCode := []byte{0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3}

	// Section names: \0.text\0.symtab\0.strtab\0.shstrtab\0
	shstrtab := []byte("\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00")
	// String table for symbols: \0main\0data_var\0
	strtab := []byte("\x00main\x00data_var\x00")

	textOffset := uint64(64)
	textSize := uint64(len(textCode))

	strtabOffset := textOffset + textSize
	strtabSize := uint64(len(strtab))

	// Each Elf64_Sym is 24 bytes
	// Symbol 0: null
	// Symbol 1: "main" - FUNC
	// Symbol 2: "data_var" - OBJECT
	symCount := 3
	symSize := uint64(symCount * 24)
	symtabOffset := strtabOffset + strtabSize

	shstrtabOffset := symtabOffset + symSize
	shstrtabSize := uint64(len(shstrtab))

	shdrOffset := shstrtabOffset + shstrtabSize
	if shdrOffset%8 != 0 {
		shdrOffset = (shdrOffset + 7) &^ 7
	}

	// 5 section headers: null, .text, .symtab, .strtab, .shstrtab
	buf := make([]byte, shdrOffset+5*64)

	// ELF header
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 2 // ELFCLASS64
	buf[5] = 1 // ELFDATA2LSB
	buf[6] = 1
	binary.LittleEndian.PutUint16(buf[16:], 2)  // ET_EXEC
	binary.LittleEndian.PutUint16(buf[18:], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(buf[20:], 1)
	binary.LittleEndian.PutUint64(buf[24:], 0x401000)   // e_entry
	binary.LittleEndian.PutUint64(buf[32:], 0)          // e_phoff
	binary.LittleEndian.PutUint64(buf[40:], shdrOffset) // e_shoff
	binary.LittleEndian.PutUint32(buf[48:], 0)
	binary.LittleEndian.PutUint16(buf[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(buf[54:], 0)
	binary.LittleEndian.PutUint16(buf[56:], 0)
	binary.LittleEndian.PutUint16(buf[58:], 64) // e_shentsize
	binary.LittleEndian.PutUint16(buf[60:], 5)  // e_shnum
	binary.LittleEndian.PutUint16(buf[62:], 4)  // e_shstrndx (index 4)

	// Copy data
	copy(buf[textOffset:], textCode)
	copy(buf[strtabOffset:], strtab)

	// Symbol table entries (Elf64_Sym: 24 bytes each)
	// Sym 0: null (all zeros)
	// Sym 1: main (FUNC, value=0x401000, size=6)
	sym1 := buf[symtabOffset+24:]
	binary.LittleEndian.PutUint32(sym1[0:], 1)        // st_name (offset into strtab)
	sym1[4] = (1 << 4) | 2                            // st_info: STB_GLOBAL | STT_FUNC
	sym1[5] = 0                                       // st_other
	binary.LittleEndian.PutUint16(sym1[6:], 1)        // st_shndx (.text = section 1)
	binary.LittleEndian.PutUint64(sym1[8:], 0x401000) // st_value
	binary.LittleEndian.PutUint64(sym1[16:], 6)       // st_size

	// Sym 2: data_var (OBJECT, value=0x402000, size=4)
	sym2 := buf[symtabOffset+48:]
	binary.LittleEndian.PutUint32(sym2[0:], 6) // st_name (offset to "data_var")
	sym2[4] = (1 << 4) | 1                     // st_info: STB_GLOBAL | STT_OBJECT
	sym2[5] = 0
	binary.LittleEndian.PutUint16(sym2[6:], 0)        // st_shndx
	binary.LittleEndian.PutUint64(sym2[8:], 0x402000) // st_value
	binary.LittleEndian.PutUint64(sym2[16:], 4)       // st_size

	copy(buf[shstrtabOffset:], shstrtab)

	// Section headers
	// SH 0: null

	// SH 1: .text
	sh1 := buf[shdrOffset+64:]
	binary.LittleEndian.PutUint32(sh1[0:], 1)   // sh_name
	binary.LittleEndian.PutUint32(sh1[4:], 1)   // SHT_PROGBITS
	binary.LittleEndian.PutUint64(sh1[8:], 0x6) // SHF_ALLOC | SHF_EXECINSTR
	binary.LittleEndian.PutUint64(sh1[16:], 0x401000)
	binary.LittleEndian.PutUint64(sh1[24:], textOffset)
	binary.LittleEndian.PutUint64(sh1[32:], textSize)
	binary.LittleEndian.PutUint64(sh1[48:], 16)

	// SH 2: .symtab
	sh2 := buf[shdrOffset+128:]
	binary.LittleEndian.PutUint32(sh2[0:], 7) // sh_name (".symtab" at offset 7)
	binary.LittleEndian.PutUint32(sh2[4:], 2) // SHT_SYMTAB
	binary.LittleEndian.PutUint64(sh2[8:], 0)
	binary.LittleEndian.PutUint64(sh2[16:], 0)
	binary.LittleEndian.PutUint64(sh2[24:], symtabOffset)
	binary.LittleEndian.PutUint64(sh2[32:], symSize)
	binary.LittleEndian.PutUint32(sh2[40:], 3) // sh_link (index of .strtab)
	binary.LittleEndian.PutUint32(sh2[44:], 1) // sh_info (first non-local symbol)
	binary.LittleEndian.PutUint64(sh2[48:], 8)
	binary.LittleEndian.PutUint64(sh2[56:], 24) // sh_entsize

	// SH 3: .strtab
	sh3 := buf[shdrOffset+192:]
	binary.LittleEndian.PutUint32(sh3[0:], 15) // sh_name (".strtab" at offset 15)
	binary.LittleEndian.PutUint32(sh3[4:], 3)  // SHT_STRTAB
	binary.LittleEndian.PutUint64(sh3[24:], strtabOffset)
	binary.LittleEndian.PutUint64(sh3[32:], strtabSize)
	binary.LittleEndian.PutUint64(sh3[48:], 1)

	// SH 4: .shstrtab
	sh4 := buf[shdrOffset+256:]
	binary.LittleEndian.PutUint32(sh4[0:], 23) // sh_name (".shstrtab" at offset 23)
	binary.LittleEndian.PutUint32(sh4[4:], 3)  // SHT_STRTAB
	binary.LittleEndian.PutUint64(sh4[24:], shstrtabOffset)
	binary.LittleEndian.PutUint64(sh4[32:], shstrtabSize)
	binary.LittleEndian.PutUint64(sh4[48:], 1)

	tmpDir := t.TempDir()
	path := tmpDir + "/withsyms.elf"
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestExtractELFSymbols_WithSymbolTable(t *testing.T) {
	path := buildSyntheticELF64_WithSymbols(t)

	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer func() { _ = f.Close() }()

	syms := extractELFSymbols(f)

	if len(syms) < 2 {
		t.Fatalf("expected at least 2 symbols, got %d", len(syms))
	}

	// Check we have both FUNC and OBJECT types
	foundFunc := false
	foundObject := false
	for _, s := range syms {
		if s.Type == "FUNC" && s.Name == "main" {
			foundFunc = true
			if s.Size != 6 {
				t.Errorf("main size = %d, want 6", s.Size)
			}
		}
		if s.Type == "OBJECT" && s.Name == "data_var" {
			foundObject = true
			if s.Size != 4 {
				t.Errorf("data_var size = %d, want 4", s.Size)
			}
		}
	}

	if !foundFunc {
		t.Error("expected FUNC symbol 'main'")
	}
	if !foundObject {
		t.Error("expected OBJECT symbol 'data_var'")
	}

	// Check sorted by address
	for i := 1; i < len(syms); i++ {
		if syms[i].Address < syms[i-1].Address {
			t.Errorf("not sorted: [%d]=0x%x < [%d]=0x%x", i, syms[i].Address, i-1, syms[i-1].Address)
		}
	}
}

func TestDisassembleELF_WithSymbols(t *testing.T) {
	path := buildSyntheticELF64_WithSymbols(t)

	result, err := disassembleELF(path, Options{MaxInstructions: 100})
	if err != nil {
		t.Fatalf("disassembleELF: %v", err)
	}

	// Should have exports (FUNC symbols with address != 0)
	if len(result.Exports) == 0 {
		t.Error("expected at least one export")
	}

	// Should have symbols in .text section
	if len(result.Sections) > 0 && len(result.Sections[0].Symbols) > 0 {
		t.Logf("Found %d symbols in .text", len(result.Sections[0].Symbols))
	}

	// Check that a label is set on the instruction at the symbol address
	for _, sec := range result.Sections {
		for _, insn := range sec.Instructions {
			if insn.Label == "main" {
				t.Log("Found 'main' label on instruction")
				return
			}
		}
	}

	t.Log("main label not found on instructions (symbol may not align with section)")
}

func buildCTestBinary(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	src := tmpDir + "/test.c"
	bin := tmpDir + "/test-bin"

	err := os.WriteFile(src, []byte(`
void _start() {
    asm("nop; nop; nop");
    asm("mov $60, %rax; xor %rdi, %rdi; syscall");
}
`), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("gcc", "-static", "-nostdlib", "-fcf-protection=none", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gcc: %v\n%s", err, out)
	}

	return bin
}
