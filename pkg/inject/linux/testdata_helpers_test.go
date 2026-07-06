/*
Copyright (c) 2026 Security Research
*/
package linux

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ELF e_machine values.
const (
	emX8664   uint16 = 62
	emAarch64 uint16 = 183
)

// ELF e_type values.
const (
	etExec uint16 = 2
	etDyn  uint16 = 3
)

// Program header types.
const (
	ptLoad     uint32 = 1
	ptDynamic  uint32 = 2
	ptInterp   uint32 = 3
	ptPhdr     uint32 = 6
	ptGnuStack uint32 = 0x6474e551
)

// Program header flags.
const (
	pfX uint32 = 1
	pfW uint32 = 2
	pfR uint32 = 4
)

// Section header types.
const (
	shtNull     uint32 = 0
	shtProgbits uint32 = 1
	shtStrtab   uint32 = 3
	shtDynamic  uint32 = 6
)

// Dynamic tag values (Elf64_Dyn.d_tag).
const (
	dtNull    int64 = 0
	dtNeeded  int64 = 1
	dtStrtab  int64 = 5
	dtStrsz   int64 = 10
	dtRpath   int64 = 15
	dtRunpath int64 = 29
)

// writeFixture writes raw bytes to a tempfile and returns the path. The
// final chmod ensures setuid/setgid bits survive umask.
func writeFixture(t *testing.T, name string, data []byte, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod fixture %s: %v", name, err)
	}
	return p
}

// buildSpec configures buildThinELF64 to produce one of the three Phase
// 25 fixture variants.
type buildSpec struct {
	machine      uint16
	eType        uint16
	interp       string   // empty -> no PT_INTERP, no .interp
	needed       []string // each -> one DT_NEEDED
	rpath        string   // empty -> no DT_RPATH
	runpath      string   // empty -> no DT_RUNPATH
	gnuStackExec bool     // true -> PT_GNU_STACK with PF_X
}

// buildThinX86_64WithRpath returns a 64-bit x86_64 ET_DYN ELF with
// PT_INTERP, PT_DYNAMIC, one DT_NEEDED ("libc.so.6") and one DT_RPATH
// ("/opt/lib"). Bytes parse cleanly via debug/elf.
func buildThinX86_64WithRpath() []byte {
	return buildThinELF64(buildSpec{
		machine: emX8664,
		eType:   etDyn,
		interp:  "/lib64/ld-linux-x86-64.so.2",
		needed:  []string{"libc.so.6"},
		rpath:   "/opt/lib",
	})
}

// buildThinAarch64Setuid returns a 64-bit aarch64 ET_DYN ELF with
// PT_INTERP and one DT_NEEDED ("libc.so.6"). Caller writes with mode
// 04755 to exercise the setuid → ptrace_eligible_binary=false path.
func buildThinAarch64Setuid() []byte {
	return buildThinELF64(buildSpec{
		machine: emAarch64,
		eType:   etDyn,
		interp:  "/lib/ld-linux-aarch64.so.1",
		needed:  []string{"libc.so.6"},
	})
}

// buildThinX86_64Static returns a 64-bit x86_64 ET_EXEC ELF with NO
// PT_INTERP segment and no .dynamic section (statically linked).
// Exercises the advisory `static_linkage` ptrace flag.
func buildThinX86_64Static() []byte {
	return buildThinELF64(buildSpec{
		machine: emX8664,
		eType:   etExec,
	})
}

// buildThinELF64 constructs a minimal valid 64-bit little-endian ELF
// whose layout satisfies debug/elf parsing for DynString queries. Layout:
//
//	[0]   ELF header (64 bytes)
//	[64]  Program headers (PHDR, optional INTERP, LOAD, optional DYNAMIC,
//	      optional GNU_STACK) — each 56 bytes
//	      then variable-length payload sections:
//	        - .interp (if interp != "")
//	        - .dynstr  (string table for needed/rpath/runpath; first byte 0)
//	        - .dynamic (Elf64_Dyn entries: STRTAB, STRSZ, NEEDED*, RPATH?,
//	          RUNPATH?, NULL)
//	      then section headers (SHT_NULL, optional .dynstr, optional
//	      .dynamic, .shstrtab) — each 64 bytes
//	      then .shstrtab payload
func buildThinELF64(spec buildSpec) []byte {
	const ehSize = 64
	const phEntrySize uint16 = 56
	const shEntrySize uint16 = 64
	le := binary.LittleEndian

	// --- Phase 1: build .dynstr (string table) ---
	// First byte is 0 (NULL string). Track offsets for every literal.
	dynstr := []byte{0}
	addStr := func(s string) uint64 {
		off := uint64(len(dynstr))
		dynstr = append(dynstr, []byte(s)...)
		dynstr = append(dynstr, 0)
		return off
	}

	hasDynamic := len(spec.needed) > 0 || spec.rpath != "" || spec.runpath != ""

	var neededOffs []uint64
	for _, n := range spec.needed {
		neededOffs = append(neededOffs, addStr(n))
	}
	var rpathOff uint64
	if spec.rpath != "" {
		rpathOff = addStr(spec.rpath)
	}
	var runpathOff uint64
	if spec.runpath != "" {
		runpathOff = addStr(spec.runpath)
	}

	// --- Phase 2: build .dynamic (Elf64_Dyn entries: 16 bytes each) ---
	var dyn []byte
	addDyn := func(tag, val int64) {
		entry := make([]byte, 16)
		le.PutUint64(entry[0:8], uint64(tag))
		le.PutUint64(entry[8:16], uint64(val))
		dyn = append(dyn, entry...)
	}
	if hasDynamic {
		// DT_STRTAB and DT_STRSZ are filled with placeholder values now;
		// strtab d_un (offset of .dynstr in memory) is patched after we
		// know the .dynstr file offset (we emit it as that offset since
		// our virtual addresses == file offsets).
		dynStrtabIdx := len(dyn)
		addDyn(dtStrtab, 0) // patched later
		addDyn(dtStrsz, int64(len(dynstr)))
		for _, off := range neededOffs {
			addDyn(dtNeeded, int64(off))
		}
		if spec.rpath != "" {
			addDyn(dtRpath, int64(rpathOff))
		}
		if spec.runpath != "" {
			addDyn(dtRunpath, int64(runpathOff))
		}
		addDyn(dtNull, 0)
		_ = dynStrtabIdx
	}

	// --- Phase 3: count program headers ---
	// Always: PHDR + LOAD. Optionals: INTERP, DYNAMIC, GNU_STACK.
	phCount := uint16(2)
	if spec.interp != "" {
		phCount++
	}
	if hasDynamic {
		phCount++
	}
	if spec.gnuStackExec {
		phCount++
	}

	phOff := uint64(ehSize)
	phSize := uint64(phCount) * uint64(phEntrySize)

	// --- Phase 4: lay out payload sections after program headers ---
	// We use file_offset == virtual_address == p_vaddr so debug/elf can
	// resolve DT_STRTAB by reading the matching PT_LOAD region.
	cursor := phOff + phSize

	var interpOff uint64
	var interpSize uint64
	if spec.interp != "" {
		interpOff = cursor
		interpSize = uint64(len(spec.interp) + 1) // include null terminator
		cursor += interpSize
	}

	dynstrOff := cursor
	cursor += uint64(len(dynstr))

	var dynOff uint64
	var dynSize uint64
	if hasDynamic {
		dynOff = cursor
		dynSize = uint64(len(dyn))
		cursor += dynSize
		// Patch DT_STRTAB d_un = dynstrOff.
		le.PutUint64(dyn[8:16], dynstrOff)
	}

	// --- Phase 5: section headers ---
	// SH_NULL is mandatory. Then optional .dynstr, .dynamic, then .shstrtab.
	shCount := uint16(2) // SH_NULL + .shstrtab
	if hasDynamic {
		shCount += 2 // .dynstr + .dynamic
	}

	// .shstrtab content: ".shstrtab\0.dynstr\0.dynamic\0.interp\0"
	shstrtab := []byte{0}
	addShStr := func(s string) uint32 {
		off := uint32(len(shstrtab))
		shstrtab = append(shstrtab, []byte(s)...)
		shstrtab = append(shstrtab, 0)
		return off
	}
	// pre-add labels we'll reference
	dynstrName := uint32(0)
	dynamicName := uint32(0)
	if hasDynamic {
		dynstrName = addShStr(".dynstr")
		dynamicName = addShStr(".dynamic")
	}
	shstrtabName := addShStr(".shstrtab")

	// Section headers placed after .dynamic, .shstrtab is at the very end.
	shOff := cursor
	shSize := uint64(shCount) * uint64(shEntrySize)
	cursor += shSize

	shstrOff := cursor
	cursor += uint64(len(shstrtab))

	totalSize := cursor

	// --- Phase 6: assemble program headers ---
	ph := make([]byte, 0, phSize)
	writePh := func(ptype, flags uint32, off, vaddr, paddr, filesz, memsz, align uint64) {
		entry := make([]byte, phEntrySize)
		le.PutUint32(entry[0:4], ptype)
		le.PutUint32(entry[4:8], flags)
		le.PutUint64(entry[8:16], off)
		le.PutUint64(entry[16:24], vaddr)
		le.PutUint64(entry[24:32], paddr)
		le.PutUint64(entry[32:40], filesz)
		le.PutUint64(entry[40:48], memsz)
		le.PutUint64(entry[48:56], align)
		ph = append(ph, entry...)
	}

	// PT_PHDR: describes the program header table itself.
	writePh(ptPhdr, pfR, phOff, phOff, phOff, phSize, phSize, 8)
	if spec.interp != "" {
		writePh(ptInterp, pfR, interpOff, interpOff, interpOff, interpSize, interpSize, 1)
	}
	// PT_LOAD covering the entire file from 0..totalSize so DT_STRTAB
	// (which is encoded as a virtual address == file offset) is reachable.
	writePh(ptLoad, pfR|pfX, 0, 0, 0, totalSize, totalSize, 0x1000)
	if hasDynamic {
		writePh(ptDynamic, pfR|pfW, dynOff, dynOff, dynOff, dynSize, dynSize, 8)
	}
	if spec.gnuStackExec {
		writePh(ptGnuStack, pfR|pfW|pfX, 0, 0, 0, 0, 0, 0)
	}

	// --- Phase 7: assemble section headers ---
	sh := make([]byte, 0, shSize)
	writeSh := func(name, stype uint32, flags, addr, off, size uint64, link, info uint32, addralign, entsize uint64) {
		entry := make([]byte, shEntrySize)
		le.PutUint32(entry[0:4], name)
		le.PutUint32(entry[4:8], stype)
		le.PutUint64(entry[8:16], flags)
		le.PutUint64(entry[16:24], addr)
		le.PutUint64(entry[24:32], off)
		le.PutUint64(entry[32:40], size)
		le.PutUint32(entry[40:44], link)
		le.PutUint32(entry[44:48], info)
		le.PutUint64(entry[48:56], addralign)
		le.PutUint64(entry[56:64], entsize)
		sh = append(sh, entry...)
	}

	// Section index assignments depend on hasDynamic.
	var dynstrIdx, dynamicIdx, shstrIdx uint16
	if hasDynamic {
		dynstrIdx = 1
		dynamicIdx = 2
		shstrIdx = 3
	} else {
		shstrIdx = 1
	}
	_ = dynamicIdx

	// SH_NULL.
	writeSh(0, shtNull, 0, 0, 0, 0, 0, 0, 0, 0)
	if hasDynamic {
		// .dynstr
		writeSh(dynstrName, shtStrtab, 0, dynstrOff, dynstrOff, uint64(len(dynstr)), 0, 0, 1, 0)
		// .dynamic — sh_link points at .dynstr, sh_entsize = 16.
		writeSh(dynamicName, shtDynamic, 0, dynOff, dynOff, dynSize, uint32(dynstrIdx), 0, 8, 16)
	}
	// .shstrtab
	writeSh(shstrtabName, shtStrtab, 0, shstrOff, shstrOff, uint64(len(shstrtab)), 0, 0, 1, 0)

	// --- Phase 8: assemble ELF header ---
	eh := make([]byte, ehSize)
	// e_ident
	eh[0] = 0x7f
	eh[1] = 'E'
	eh[2] = 'L'
	eh[3] = 'F'
	eh[4] = 2 // ELFCLASS64
	eh[5] = 1 // ELFDATA2LSB
	eh[6] = 1 // EV_CURRENT
	eh[7] = 0 // ELFOSABI_NONE
	// remaining 8 bytes of e_ident are zero (padding)
	le.PutUint16(eh[16:18], spec.eType)   // e_type
	le.PutUint16(eh[18:20], spec.machine) // e_machine
	le.PutUint32(eh[20:24], 1)            // e_version
	le.PutUint64(eh[24:32], 0)            // e_entry
	le.PutUint64(eh[32:40], phOff)        // e_phoff
	le.PutUint64(eh[40:48], shOff)        // e_shoff
	le.PutUint32(eh[48:52], 0)            // e_flags
	le.PutUint16(eh[52:54], ehSize)       // e_ehsize
	le.PutUint16(eh[54:56], phEntrySize)  // e_phentsize
	le.PutUint16(eh[56:58], phCount)      // e_phnum
	le.PutUint16(eh[58:60], shEntrySize)  // e_shentsize
	le.PutUint16(eh[60:62], shCount)      // e_shnum
	le.PutUint16(eh[62:64], shstrIdx)     // e_shstrndx

	// --- Phase 9: stitch the file together ---
	out := make([]byte, totalSize)
	copy(out[0:], eh)
	copy(out[phOff:], ph)
	if spec.interp != "" {
		copy(out[interpOff:], []byte(spec.interp))
		out[interpOff+uint64(len(spec.interp))] = 0
	}
	copy(out[dynstrOff:], dynstr)
	if hasDynamic {
		copy(out[dynOff:], dyn)
	}
	copy(out[shOff:], sh)
	copy(out[shstrOff:], shstrtab)
	return out
}
