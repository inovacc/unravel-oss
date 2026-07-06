/*
Copyright (c) 2026 Security Research
*/
package linux

import (
	"debug/elf"
	"os"
	"sort"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// PtraceNote is the fixed Phase 25 D-14 disclaimer text. Frida autogen
// (Phase 26) reads this as the preflight contract.
const PtraceNote = "host ptrace_scope policy (kernel.yama.ptrace_scope) applies at runtime; check via /proc/sys/kernel/yama/ptrace_scope before attempting attach"

// Advisory flag names per CONTEXT D-11. Sorted alphabetically when
// stamped onto a Seam (Claude's Discretion in CONTEXT).
const (
	flagPtGnuStackExec = "pt_gnu_stack_exec"
	flagNonPIE         = "non_pie"
	flagStaticLinkage  = "static_linkage"
)

// ClassifyPtrace inspects a binary's static attributes and returns:
//   - eligible: nil if attrs unreadable; false if setuid; true otherwise
//   - flags:    advisory list (alphabetically sorted) of binary attrs
//     observed (pt_gnu_stack_exec, non_pie, static_linkage)
//   - note:     PtraceNote when eligible is non-nil; "" otherwise (D-16)
//
// Per CONTEXT D-12 the decision rule is `eligible = !setuid`. The other
// three signals are advisory metadata only — they appear in the seam's
// PtraceFlags but do not flip the boolean.
func ClassifyPtrace(path string, f *elf.File) (eligible *bool, flags []string, note string) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, ""
	}

	// Primary signal: setuid bit (mode & 0o4000).
	setuid := info.Mode()&os.ModeSetuid != 0
	val := !setuid
	eligible = &val
	note = PtraceNote

	// Advisory: PT_GNU_STACK with PF_X.
	for _, p := range f.Progs {
		if p.Type == elf.PT_GNU_STACK {
			if p.Flags&elf.PF_X != 0 {
				flags = append(flags, flagPtGnuStackExec)
			}
			break
		}
	}

	// Advisory: non-PIE (ET_EXEC). ET_DYN is PIE/shared.
	if f.Type == elf.ET_EXEC {
		flags = append(flags, flagNonPIE)
	}

	// Advisory: static linkage (no PT_INTERP segment).
	hasInterp := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			hasInterp = true
			break
		}
	}
	if !hasInterp {
		flags = append(flags, flagStaticLinkage)
	}

	sort.Strings(flags)
	return eligible, flags, note
}

// applyPtrace stamps every seam in seams with the ptrace classification
// produced by ClassifyPtrace. Idempotent — called once per binary by
// WalkELF after walkOne.
func applyPtrace(seams []inject.Seam, eligible *bool, flags []string, note string) []inject.Seam {
	for i := range seams {
		if eligible != nil {
			v := *eligible
			seams[i].PtraceEligibleBinary = &v
			seams[i].PtraceEligibleBinaryNote = note
		}
		if len(flags) > 0 {
			// Copy slice so seams don't share underlying array.
			seams[i].PtraceFlags = append([]string(nil), flags...)
		}
	}
	return seams
}
