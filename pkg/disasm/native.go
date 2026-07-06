/*
Copyright (c) 2026 Security Research
*/
package disasm

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"sort"

	"golang.org/x/arch/x86/x86asm"
)

// disassembleNative uses Go's debug/* packages and x86asm to decode instructions.
func disassembleNative(path string, opts Options) (*Result, error) {
	// Try ELF
	if r, err := disassembleELF(path, opts); err == nil {
		return r, nil
	}

	// Try PE
	if r, err := disassemblePE(path, opts); err == nil {
		return r, nil
	}

	// Try Mach-O
	if r, err := disassembleMachO(path, opts); err == nil {
		return r, nil
	}

	return nil, fmt.Errorf("unsupported binary format for native disassembly")
}

// extractELFSymbols reads all symbols from an ELF binary, sorted by address.
func extractELFSymbols(f *elf.File) []Symbol {
	var syms []Symbol

	allSyms, _ := f.Symbols()
	for _, s := range allSyms {
		if s.Name == "" {
			continue
		}

		typ := "NOTYPE"
		switch elf.ST_TYPE(s.Info) {
		case elf.STT_FUNC:
			typ = "FUNC"
		case elf.STT_OBJECT:
			typ = "OBJECT"
		}

		syms = append(syms, Symbol{
			Address: s.Value,
			Name:    s.Name,
			Size:    s.Size,
			Type:    typ,
		})
	}

	sort.Slice(syms, func(i, j int) bool { return syms[i].Address < syms[j].Address })

	return syms
}

// elfSectionFlags converts ELF section flags to human-readable strings.
func elfSectionFlags(flags elf.SectionFlag) []string {
	var out []string

	if flags&elf.SHF_ALLOC != 0 {
		out = append(out, "ALLOC")
	}

	if flags&elf.SHF_EXECINSTR != 0 {
		out = append(out, "CODE")
	}

	if flags&elf.SHF_WRITE != 0 {
		out = append(out, "DATA")
	}

	return out
}

// symbolsInRange returns symbols within an address range, sorted by address.
func symbolsInRange(syms []Symbol, start, end uint64) []Symbol {
	var out []Symbol

	for _, s := range syms {
		if s.Address >= start && s.Address < end {
			out = append(out, s)
		}
	}

	return out
}

// buildSymLookup creates a function that resolves an address to a symbol name.
func buildSymLookup(syms []Symbol) func(uint64) (string, uint64) {
	return func(addr uint64) (string, uint64) {
		// Binary search for the symbol containing or at this address
		idx := sort.Search(len(syms), func(i int) bool { return syms[i].Address > addr })
		if idx > 0 {
			s := syms[idx-1]
			if s.Address == addr {
				return s.Name, s.Address
			}

			if s.Size > 0 && addr < s.Address+s.Size {
				return s.Name, s.Address
			}
		}

		// Exact match check
		for _, s := range syms {
			if s.Address == addr {
				return s.Name, s.Address
			}
		}

		return "", 0
	}
}

func disassembleELF(path string, opts Options) (*Result, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	result := &Result{
		Format: "ELF",
		Tool:   "native (x86asm)",
	}

	var mode int
	switch f.Machine {
	case elf.EM_X86_64:
		result.Architecture = "x86_64"
		result.Bits = 64
		mode = 64
	case elf.EM_386:
		result.Architecture = "x86"
		result.Bits = 32
		mode = 32
	default:
		return nil, fmt.Errorf("unsupported ELF architecture: %v", f.Machine)
	}

	result.EntryPoint = f.Entry

	// Extract full symbol table
	allSyms := extractELFSymbols(f)

	// Extract imports
	dynSyms, _ := f.DynamicSymbols()
	for _, s := range dynSyms {
		if s.Value == 0 && s.Name != "" {
			result.Imports = append(result.Imports, s.Name)
		}
	}

	// Extract exports
	for _, s := range allSyms {
		if s.Address != 0 && s.Type == "FUNC" {
			result.Exports = append(result.Exports, s.Name)
		}
	}

	// Determine which sections to disassemble
	if len(opts.SectionsFilter) > 0 {
		// User-specified sections
		for _, name := range opts.SectionsFilter {
			sec := f.Section(name)
			if sec == nil {
				continue
			}

			data, err := sec.Data()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("read section %s: %v", name, err))

				continue
			}

			secSyms := symbolsInRange(allSyms, sec.Addr, sec.Addr+sec.Size)
			section := decodeSection(name, sec.Addr, data, mode, opts.MaxInstructions, secSyms)
			section.Flags = elfSectionFlags(sec.Flags)
			section.Symbols = secSyms
			result.Sections = append(result.Sections, section)
		}
	} else {
		// Auto-detect: all executable sections (matches objdump -d)
		for _, sec := range f.Sections {
			if sec.Flags&elf.SHF_EXECINSTR == 0 {
				continue
			}

			data, err := sec.Data()
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("read section %s: %v", sec.Name, err))

				continue
			}

			secSyms := symbolsInRange(allSyms, sec.Addr, sec.Addr+sec.Size)
			section := decodeSection(sec.Name, sec.Addr, data, mode, opts.MaxInstructions, secSyms)
			section.Flags = elfSectionFlags(sec.Flags)
			section.Symbols = secSyms
			result.Sections = append(result.Sections, section)
		}
	}

	if len(result.Sections) == 0 {
		return nil, fmt.Errorf("no disassemblable sections found")
	}

	return result, nil
}

func disassemblePE(path string, opts Options) (*Result, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	result := &Result{
		Format: "PE",
		Tool:   "native (x86asm)",
	}

	var mode int
	var imageBase uint64

	switch f.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		result.Architecture = "x86_64"
		result.Bits = 64
		mode = 64
	case pe.IMAGE_FILE_MACHINE_I386:
		result.Architecture = "x86"
		result.Bits = 32
		mode = 32
	default:
		return nil, fmt.Errorf("unsupported PE architecture: %v", f.Machine)
	}

	// Entry point
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		result.EntryPoint = uint64(oh.AddressOfEntryPoint) + oh.ImageBase
		imageBase = oh.ImageBase
	case *pe.OptionalHeader32:
		result.EntryPoint = uint64(oh.AddressOfEntryPoint) + uint64(oh.ImageBase)
		imageBase = uint64(oh.ImageBase)
	}

	// Extract PE symbols
	var allSyms []Symbol
	for _, s := range f.Symbols {
		if s.Name == "" {
			continue
		}

		allSyms = append(allSyms, Symbol{
			Address: imageBase + uint64(s.Value),
			Name:    s.Name,
			Type:    "NOTYPE",
		})
	}

	sort.Slice(allSyms, func(i, j int) bool { return allSyms[i].Address < allSyms[j].Address })

	// Extract imports
	importSyms, _ := f.ImportedSymbols()
	for _, s := range importSyms {
		result.Imports = append(result.Imports, s)
	}

	// Disassemble sections
	sectionNames := opts.SectionsFilter
	if len(sectionNames) == 0 {
		sectionNames = []string{".text"}
	}

	for _, name := range sectionNames {
		for _, sec := range f.Sections {
			if sec.Name == name {
				data, err := sec.Data()
				if err != nil {
					result.Errors = append(result.Errors, fmt.Sprintf("read section %s: %v", name, err))

					continue
				}

				baseAddr := imageBase + uint64(sec.VirtualAddress)
				secSyms := symbolsInRange(allSyms, baseAddr, baseAddr+uint64(sec.VirtualSize))
				section := decodeSection(name, baseAddr, data, mode, opts.MaxInstructions, secSyms)
				section.Symbols = secSyms
				result.Sections = append(result.Sections, section)
			}
		}
	}

	if len(result.Sections) == 0 {
		return nil, fmt.Errorf("no disassemblable sections found")
	}

	return result, nil
}

func disassembleMachO(path string, opts Options) (*Result, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}

	defer func() { _ = f.Close() }()

	result := &Result{
		Format: "Mach-O",
		Tool:   "native (x86asm)",
	}

	var mode int
	switch f.Cpu {
	case macho.CpuAmd64:
		result.Architecture = "x86_64"
		result.Bits = 64
		mode = 64
	case macho.Cpu386:
		result.Architecture = "x86"
		result.Bits = 32
		mode = 32
	default:
		return nil, fmt.Errorf("unsupported Mach-O architecture: %v (native disassembly only supports x86/x86_64)", f.Cpu)
	}

	// Extract Mach-O symbols
	var allSyms []Symbol
	if f.Symtab != nil {
		for _, s := range f.Symtab.Syms {
			if s.Name == "" {
				continue
			}

			allSyms = append(allSyms, Symbol{
				Address: s.Value,
				Name:    s.Name,
				Type:    "NOTYPE",
			})
		}
	}

	sort.Slice(allSyms, func(i, j int) bool { return allSyms[i].Address < allSyms[j].Address })

	// Extract imports
	importSyms, _ := f.ImportedSymbols()
	for _, s := range importSyms {
		result.Imports = append(result.Imports, s)
	}

	// Disassemble sections
	sectionNames := opts.SectionsFilter
	if len(sectionNames) == 0 {
		sectionNames = []string{"__text"}
	}

	for _, name := range sectionNames {
		sec := f.Section(name)
		if sec == nil {
			continue
		}

		data, err := sec.Data()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read section %s: %v", name, err))

			continue
		}

		secSyms := symbolsInRange(allSyms, sec.Addr, sec.Addr+sec.Size)
		section := decodeSection(name, sec.Addr, data, mode, opts.MaxInstructions, secSyms)
		section.Symbols = secSyms
		result.Sections = append(result.Sections, section)
	}

	if len(result.Sections) == 0 {
		return nil, fmt.Errorf("no disassemblable sections found")
	}

	return result, nil
}

// decodeSection decodes x86/x86_64 instructions from raw bytes using AT&T (GNU) syntax.
func decodeSection(name string, baseAddr uint64, data []byte, mode int, maxInsn int, syms []Symbol) Section {
	section := Section{
		Name:    name,
		Address: baseAddr,
		Size:    uint64(len(data)),
	}

	symLookup := buildSymLookup(syms)

	// Build a set of symbol addresses for label insertion
	symAddrMap := make(map[uint64]string, len(syms))
	for _, s := range syms {
		symAddrMap[s.Address] = s.Name
	}

	// symname callback for GNUSyntax
	gnuSymName := func(addr uint64) (string, uint64) {
		return symLookup(addr)
	}

	offset := 0
	count := 0

	for offset < len(data) && count < maxInsn {
		inst, err := x86asm.Decode(data[offset:], mode)
		if err != nil {
			// Skip 1 byte on decode failure
			offset++

			continue
		}

		pc := baseAddr + uint64(offset)

		insn := Instruction{
			Address: pc,
			Bytes:   data[offset : offset+inst.Len],
		}

		// Insert symbol label if this address matches a symbol
		if label, ok := symAddrMap[pc]; ok {
			insn.Label = label
		}

		// Use GNUSyntax for AT&T output matching objdump
		gnuText := x86asm.GNUSyntax(inst, pc, gnuSymName)

		// Split mnemonic from operands
		if idx := findMnemonicEnd(gnuText); idx > 0 {
			insn.Mnemonic = gnuText[:idx]
			insn.Operands = gnuText[idx+1:]
		} else {
			insn.Mnemonic = gnuText
		}

		section.Instructions = append(section.Instructions, insn)
		offset += inst.Len
		count++
	}

	return section
}

// findMnemonicEnd finds the index of the first space/tab after the mnemonic.
func findMnemonicEnd(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return i
		}
	}

	return -1
}
