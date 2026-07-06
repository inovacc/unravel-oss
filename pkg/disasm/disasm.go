/*
Copyright (c) 2026 Security Research
*/
package disasm

import "fmt"

// Options controls disassembly behavior.
type Options struct {
	MaxInstructions int      // max instructions to decode (0 = default 1000)
	SectionsFilter  []string // only disassemble these sections (empty = .text)
	ExternalOnly    bool     // skip native fallback, only use external tools
}

// Result holds the disassembly output.
type Result struct {
	Architecture string    `json:"architecture"`
	Format       string    `json:"format"` // ELF, PE, Mach-O
	Bits         int       `json:"bits"`   // 32 or 64
	EntryPoint   uint64    `json:"entry_point"`
	Sections     []Section `json:"sections"`
	Imports      []string  `json:"imports,omitempty"`
	Exports      []string  `json:"exports,omitempty"`
	Tool         string    `json:"tool"` // which tool produced the result
	Errors       []string  `json:"errors,omitempty"`
}

// Symbol represents a symbol from the binary's symbol table.
type Symbol struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
	Size    uint64 `json:"size"`
	Type    string `json:"type"` // FUNC, OBJECT, NOTYPE
}

// Section holds disassembled instructions for a binary section.
type Section struct {
	Name         string        `json:"name"`
	Address      uint64        `json:"address"`
	Size         uint64        `json:"size"`
	Flags        []string      `json:"flags,omitempty"`
	Symbols      []Symbol      `json:"symbols,omitempty"`
	Instructions []Instruction `json:"instructions,omitempty"`
}

// Instruction represents a single disassembled instruction.
type Instruction struct {
	Address  uint64 `json:"address"`
	Bytes    []byte `json:"bytes"`
	Mnemonic string `json:"mnemonic"`
	Operands string `json:"operands,omitempty"`
	Label    string `json:"label,omitempty"`
	Comment  string `json:"comment,omitempty"`
}

// Disassemble tries external tools first, then falls back to native Go decoding.
func Disassemble(path string, opts Options) (*Result, error) {
	if opts.MaxInstructions <= 0 {
		opts.MaxInstructions = 1000
	}

	// Try external tools first
	if result, err := tryObjdump(path, opts); err == nil {
		return result, nil
	}

	if result, err := tryRadare2(path, opts); err == nil {
		return result, nil
	}

	if opts.ExternalOnly {
		return nil, fmt.Errorf("no external disassembly tools found (tried objdump, radare2)")
	}

	// Fall back to native Go disassembly
	return disassembleNative(path, opts)
}
