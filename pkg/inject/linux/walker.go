/*
Copyright (c) 2026 Security Research
*/
package linux

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// elfMagic is the ELF identifier per CONTEXT D-03: 0x7f 'E' 'L' 'F'.
var elfMagic = [4]byte{0x7f, 'E', 'L', 'F'}

// IsELF returns true when path's first 4 bytes match the ELF magic.
func IsELF(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	var buf [4]byte
	n, _ := f.Read(buf[:])
	if n < 4 {
		return false
	}
	return buf == elfMagic
}

// WalkELF parses the ELF at path and returns a single-element ArchReport
// (D-09: ELF is single-arch per file; the 1-element wrap matches Phase
// 24's per-arch shape). Each DT_NEEDED / DT_RPATH / DT_RUNPATH entry
// becomes one inject.Seam.
func WalkELF(path string) ([]inject.ArchReport, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("elf open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	seams, err := walkOne(path, f)
	if err != nil {
		return nil, err
	}

	// Phase 25 D-13: stamp every seam with ptrace classification from
	// binary attrs only. Host ptrace_scope is a runtime concern (D-10).
	eligible, flags, note := ClassifyPtrace(path, f)
	seams = applyPtrace(seams, eligible, flags, note)

	arch := f.Machine.String() // e.g. "EM_X86_64", "EM_AARCH64"
	arch = strings.TrimPrefix(arch, "EM_")
	arch = strings.ToLower(arch)
	return []inject.ArchReport{{Arch: arch, Seams: seams}}, nil
}

// walkOne extracts dynamic-section entries from a single ELF file.
// DT_NEEDED, DT_RPATH, and DT_RUNPATH each yield one seam per entry.
// A missing dynamic section (static binary) yields zero seams without
// error.
func walkOne(path string, f *elf.File) ([]inject.Seam, error) {
	var seams []inject.Seam

	needed, err := f.DynString(elf.DT_NEEDED)
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("DT_NEEDED: %w", err)
	}
	for _, n := range needed {
		seams = append(seams, mkSeam(path, "dt_needed", n))
	}

	// DynString already splits semicolon-delimited path lists for
	// DT_RPATH / DT_RUNPATH, so each path becomes its own seam.
	rpath, err := f.DynString(elf.DT_RPATH)
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("DT_RPATH: %w", err)
	}
	for _, p := range rpath {
		seams = append(seams, mkSeam(path, "dt_rpath", p))
	}

	runpath, err := f.DynString(elf.DT_RUNPATH)
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("DT_RUNPATH: %w", err)
	}
	for _, p := range runpath {
		seams = append(seams, mkSeam(path, "dt_runpath", p))
	}

	return seams, nil
}

// mkSeam builds a baseline inject.Seam for one dynamic-section entry.
// Confidence defaults to Medium; ptrace fields are stamped post-hoc by
// applyPtrace.
func mkSeam(path, kind, target string) inject.Seam {
	return inject.Seam{
		Kind:       kind,
		Confidence: inject.ConfidenceMedium,
		Framework:  inject.FrameworkLinux,
		Evidence: []inject.Evidence{{
			Type:    inject.EvidenceFileContent,
			Path:    path,
			Snippet: target,
		}},
	}
}
