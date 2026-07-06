/*
Copyright (c) 2026 Security Research
*/
package linux

import (
	"bytes"
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestIsELF(t *testing.T) {
	good := writeFixture(t, "good.bin", buildThinX86_64WithRpath(), 0o644)
	bad := writeFixture(t, "bad.bin", []byte("not an elf at all"), 0o644)
	if !IsELF(good) {
		t.Errorf("IsELF(good) = false; want true")
	}
	if IsELF(bad) {
		t.Errorf("IsELF(bad) = true; want false")
	}
}

func TestBuilder_ParsesViaDebugELF(t *testing.T) {
	// Sanity-check that the hand-built bytes parse cleanly via debug/elf
	// before walker tests rely on them. Catches layout drift early.
	cases := []struct {
		name    string
		data    []byte
		machine elf.Machine
		etype   elf.Type
	}{
		{"x86_64+rpath", buildThinX86_64WithRpath(), elf.EM_X86_64, elf.ET_DYN},
		{"aarch64", buildThinAarch64Setuid(), elf.EM_AARCH64, elf.ET_DYN},
		{"x86_64+static", buildThinX86_64Static(), elf.EM_X86_64, elf.ET_EXEC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := elf.NewFile(bytes.NewReader(tc.data))
			if err != nil {
				t.Fatalf("elf.NewFile: %v", err)
			}
			defer func() { _ = f.Close() }()
			if f.Machine != tc.machine {
				t.Errorf("Machine = %v; want %v", f.Machine, tc.machine)
			}
			if f.Type != tc.etype {
				t.Errorf("Type = %v; want %v", f.Type, tc.etype)
			}
		})
	}
}

func TestWalkELF_X86_64WithRpath(t *testing.T) {
	p := writeFixture(t, "rpath.bin", buildThinX86_64WithRpath(), 0o644)
	arches, err := WalkELF(p)
	if err != nil {
		t.Fatalf("WalkELF: %v", err)
	}
	if len(arches) != 1 {
		t.Fatalf("len(arches) = %d; want 1 (D-09 single-arch wrap)", len(arches))
	}
	if arches[0].Arch != "x86_64" {
		t.Errorf("arch = %q; want x86_64", arches[0].Arch)
	}
	kinds := map[string]int{}
	for _, s := range arches[0].Seams {
		if s.Framework != inject.FrameworkLinux {
			t.Errorf("seam framework = %q; want linux", s.Framework)
		}
		kinds[s.Kind]++
	}
	if kinds["dt_needed"] != 1 {
		t.Errorf("dt_needed count = %d; want 1 (got kinds=%v)", kinds["dt_needed"], kinds)
	}
	if kinds["dt_rpath"] != 1 {
		t.Errorf("dt_rpath count = %d; want 1 (got kinds=%v)", kinds["dt_rpath"], kinds)
	}
}

func TestWalkELF_Aarch64(t *testing.T) {
	p := writeFixture(t, "aarch64.bin", buildThinAarch64Setuid(), 0o644)
	arches, err := WalkELF(p)
	if err != nil {
		t.Fatalf("WalkELF: %v", err)
	}
	if len(arches) != 1 || arches[0].Arch != "aarch64" {
		t.Fatalf("arch = %v; want [aarch64]", arches)
	}
}

func TestWalkELF_RejectsNonELF(t *testing.T) {
	p := writeFixture(t, "bogus.bin", []byte("MZ......not an elf"), 0o644)
	if _, err := WalkELF(p); err == nil {
		t.Errorf("WalkELF on non-ELF: want error, got nil")
	}
}

func TestScanWithPlatform_Linux_AttachesArches(t *testing.T) {
	// Stage a fixture in a fresh temp dir so ScanWithPlatform's findELF
	// can discover it via filepath.Walk. ROADMAP success criterion #1
	// end-to-end coverage.
	dir := t.TempDir()
	bin := filepath.Join(dir, "stub.elf")
	if err := os.WriteFile(bin, buildThinX86_64WithRpath(), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := inject.ScanWithPlatform(context.Background(), dir, "linux")
	if err != nil {
		t.Fatalf("ScanWithPlatform: %v", err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
	if len(result.Arches) != 1 {
		t.Errorf("len(Arches) = %d; want 1 (single-arch wrap, D-09)", len(result.Arches))
	}
	if len(result.Seams) == 0 {
		t.Error("Seams empty — expected flatten of arches[0].Seams")
	}
	if len(result.Arches) > 0 && len(result.Seams) != len(result.Arches[0].Seams) {
		t.Errorf("Seams flatten mismatch: top=%d arches[0]=%d", len(result.Seams), len(result.Arches[0].Seams))
	}
	if result.Framework != inject.FrameworkLinux {
		t.Errorf("Framework = %q; want linux", result.Framework)
	}
	// Ptrace fields propagate from walker (Phase 25 D-13).
	for i, s := range result.Seams {
		if s.PtraceEligibleBinary == nil {
			t.Errorf("Seams[%d].PtraceEligibleBinary = nil; want non-nil", i)
		}
		if s.PtraceEligibleBinaryNote == "" {
			t.Errorf("Seams[%d].PtraceEligibleBinaryNote empty; want PtraceNote", i)
		}
	}
}
