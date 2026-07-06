/*
Copyright (c) 2026 Security Research
*/
package disasm

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// tryObjdump attempts disassembly via objdump.
func tryObjdump(path string, opts Options) (*Result, error) {
	objdump, err := exec.LookPath("objdump")
	if err != nil {
		return nil, fmt.Errorf("objdump not found: %w", err)
	}

	// Absolutize the (untrusted) binary path so it can never be parsed as a
	// flag by objdump (argument injection, CWE-88).
	if abs, absErr := filepath.Abs(path); absErr == nil {
		path = abs
	}

	args := []string{"-d"}
	if len(opts.SectionsFilter) > 0 {
		for _, s := range opts.SectionsFilter {
			args = append(args, "-j", s)
		}
	} else {
		args = append(args, "-j", ".text")
	}

	args = append(args, path)

	cmd := exec.Command(objdump, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("objdump failed: %w", err)
	}

	return parseObjdumpOutput(string(output), opts.MaxInstructions)
}

var (
	objdumpFileFormat = regexp.MustCompile(`file format\s+(\S+)`)
	objdumpSection    = regexp.MustCompile(`^Disassembly of section (\S+):`)
	objdumpSymLabel   = regexp.MustCompile(`^([0-9a-f]+)\s+<(.+)>:`)
	objdumpInsn       = regexp.MustCompile(`^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s)+)\s*(.+)`)
)

func parseObjdumpOutput(output string, maxInsn int) (*Result, error) {
	result := &Result{Tool: "objdump"}

	scanner := bufio.NewScanner(strings.NewReader(output))

	// Detect format from header
	for scanner.Scan() {
		line := scanner.Text()
		if m := objdumpFileFormat.FindStringSubmatch(line); m != nil {
			format := m[1]
			switch {
			case strings.Contains(format, "elf64"):
				result.Format = "ELF"
				result.Architecture = "x86_64"
				result.Bits = 64
			case strings.Contains(format, "elf32"):
				result.Format = "ELF"
				result.Architecture = "x86"
				result.Bits = 32
			case strings.Contains(format, "pe"):
				result.Format = "PE"
				result.Architecture = "x86_64"
				result.Bits = 64
			default:
				result.Format = format
			}

			break
		}
	}

	var currentSection *Section
	var pendingLabel string
	totalInsn := 0

	for scanner.Scan() {
		if totalInsn >= maxInsn {
			break
		}

		line := scanner.Text()

		if m := objdumpSection.FindStringSubmatch(line); m != nil {
			if currentSection != nil {
				finalizeSectionBounds(currentSection)
				result.Sections = append(result.Sections, *currentSection)
			}

			currentSection = &Section{Name: m[1]}
			pendingLabel = ""

			continue
		}

		if currentSection == nil {
			continue
		}

		// Parse symbol labels (e.g., "0000000000401000 <main>:")
		if m := objdumpSymLabel.FindStringSubmatch(line); m != nil {
			pendingLabel = m[2]

			continue
		}

		if m := objdumpInsn.FindStringSubmatch(line); m != nil {
			addr, _ := strconv.ParseUint(m[1], 16, 64)
			rawBytes := parseHexBytes(m[2])
			asmText := strings.TrimSpace(m[3])
			parts := strings.Fields(asmText)

			insn := Instruction{Address: addr, Bytes: rawBytes}
			if len(parts) > 0 {
				insn.Mnemonic = parts[0]
			}

			if len(parts) > 1 {
				insn.Operands = strings.Join(parts[1:], " ")
			}

			if pendingLabel != "" {
				insn.Label = pendingLabel
				pendingLabel = ""
			}

			currentSection.Instructions = append(currentSection.Instructions, insn)
			totalInsn++
		}
	}

	if currentSection != nil {
		finalizeSectionBounds(currentSection)
		result.Sections = append(result.Sections, *currentSection)
	}

	if len(result.Sections) == 0 {
		return nil, fmt.Errorf("no instructions parsed from objdump output")
	}

	return result, nil
}

// parseHexBytes parses space-separated hex bytes (e.g., "55 48 89 e5 ") into a byte slice.
func parseHexBytes(s string) []byte {
	fields := strings.Fields(strings.TrimSpace(s))
	out := make([]byte, 0, len(fields))

	for _, f := range fields {
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			continue
		}

		out = append(out, byte(v))
	}

	return out
}

// finalizeSectionBounds sets the section Address and Size from parsed instructions.
func finalizeSectionBounds(s *Section) {
	if len(s.Instructions) == 0 {
		return
	}

	first := s.Instructions[0]
	last := s.Instructions[len(s.Instructions)-1]
	s.Address = first.Address
	// Approximate size: span from first to last instruction + last instruction's bytes
	lastLen := uint64(len(last.Bytes))
	if lastLen == 0 {
		lastLen = 1 // minimum estimate when bytes aren't available
	}

	s.Size = last.Address - first.Address + lastLen
}

// tryRadare2 attempts disassembly via radare2.
func tryRadare2(path string, opts Options) (*Result, error) {
	r2, err := exec.LookPath("r2")
	if err != nil {
		return nil, fmt.Errorf("radare2 not found: %w", err)
	}

	// Absolutize the (untrusted) binary path so it can never be parsed as a
	// flag by radare2 (argument injection, CWE-88).
	if abs, absErr := filepath.Abs(path); absErr == nil {
		path = abs
	}

	maxInsn := opts.MaxInstructions
	cmd := exec.Command(r2, "-q", "-c", fmt.Sprintf("aaa; iI; afl; pd %d @ entry0", maxInsn), path)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("radare2 failed: %w", err)
	}

	return parseR2Output(string(output), maxInsn)
}

var r2Insn = regexp.MustCompile(`^\s*(0x[0-9a-f]+)\s+(.+)`)

func parseR2Output(output string, maxInsn int) (*Result, error) {
	result := &Result{Tool: "radare2"}
	scanner := bufio.NewScanner(strings.NewReader(output))

	// Parse iI output for arch info
	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "arch"); ok {
			result.Architecture = strings.TrimSpace(v)
		}

		if v, ok := strings.CutPrefix(line, "bits"); ok {
			bits, _ := strconv.Atoi(strings.TrimSpace(v))
			result.Bits = bits
		}

		if v, ok := strings.CutPrefix(line, "bintype"); ok {
			result.Format = strings.TrimSpace(v)
		}
	}

	// Re-scan for instructions
	scanner = bufio.NewScanner(strings.NewReader(output))
	section := Section{Name: ".text"}
	totalInsn := 0

	for scanner.Scan() {
		if totalInsn >= maxInsn {
			break
		}

		line := scanner.Text()
		if m := r2Insn.FindStringSubmatch(line); m != nil {
			addr, _ := strconv.ParseUint(strings.TrimPrefix(m[1], "0x"), 16, 64)
			parts := strings.Fields(m[2])

			insn := Instruction{Address: addr}
			if len(parts) > 0 {
				insn.Mnemonic = parts[0]
			}

			if len(parts) > 1 {
				insn.Operands = strings.Join(parts[1:], " ")
			}

			section.Instructions = append(section.Instructions, insn)
			totalInsn++
		}
	}

	if len(section.Instructions) > 0 {
		finalizeSectionBounds(&section)
		result.Sections = append(result.Sections, section)
	}

	if len(result.Sections) == 0 {
		return nil, fmt.Errorf("no instructions parsed from radare2 output")
	}

	return result, nil
}
