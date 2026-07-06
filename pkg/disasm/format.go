/*
Copyright (c) 2026 Security Research
*/
package disasm

import (
	"fmt"
	"strings"
)

// FormatGNU produces objdump-compatible text output from a disassembly result.
func FormatGNU(r *Result, path string) string {
	var b strings.Builder

	// Header matching objdump
	fileFormat := gnuFileFormat(r)
	fmt.Fprintf(&b, "\n%s:     file format %s\n", path, fileFormat)

	for _, sec := range r.Sections {
		fmt.Fprintf(&b, "\n\nDisassembly of section %s:\n", sec.Name)

		// Determine address width from the section
		addrWidth := 8
		if r.Bits == 64 {
			addrWidth = 16
		}

		for _, insn := range sec.Instructions {
			// Insert symbol label before instruction
			if insn.Label != "" {
				fmt.Fprintf(&b, "\n%0*x <%s>:\n", addrWidth, insn.Address, insn.Label)
			}

			// Format: "  addr:\tbytes\tmnemonic operands"
			bytesHex := formatBytes(insn.Bytes)

			var insnText string
			if insn.Operands != "" {
				insnText = insn.Mnemonic + " " + insn.Operands
			} else {
				insnText = insn.Mnemonic
			}

			fmt.Fprintf(&b, "%*x:\t%-24s\t%s\n", addrWidth/2, insn.Address, bytesHex, insnText)
		}
	}

	return b.String()
}

// formatBytes formats instruction bytes as space-separated hex.
func formatBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}

	return strings.Join(parts, " ")
}

// gnuFileFormat returns the file format string matching objdump output.
func gnuFileFormat(r *Result) string {
	switch r.Format {
	case "ELF":
		if r.Bits == 64 {
			return "elf64-x86-64"
		}

		return "elf32-i386"
	case "PE":
		if r.Bits == 64 {
			return "pei-x86-64"
		}

		return "pei-i386"
	case "Mach-O":
		if r.Bits == 64 {
			return "mach-o-x86-64"
		}

		return "mach-o-i386"
	default:
		return r.Format
	}
}
