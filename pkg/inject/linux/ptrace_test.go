/*
Copyright (c) 2026 Security Research
*/
package linux

import (
	"bytes"
	"debug/elf"
	"os"
	"sort"
	"testing"
)

// openFixture writes the supplied bytes to disk with the given mode and
// also returns an in-memory *elf.File for ClassifyPtrace.
func openFixture(t *testing.T, data []byte, mode os.FileMode) (string, *elf.File) {
	t.Helper()
	p := writeFixture(t, "fixture.bin", data, mode)
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("elf.NewFile: %v", err)
	}
	return p, f
}

func TestClassifyPtrace_Normal(t *testing.T) {
	p, f := openFixture(t, buildThinX86_64WithRpath(), 0o644)
	eligible, flags, note := ClassifyPtrace(p, f)
	if eligible == nil {
		t.Fatal("eligible = nil; want non-nil")
	}
	if !*eligible {
		t.Errorf("eligible = false; want true (no setuid)")
	}
	if note != PtraceNote {
		t.Errorf("note = %q; want PtraceNote", note)
	}
	for _, fl := range flags {
		if fl == flagNonPIE || fl == flagStaticLinkage {
			t.Errorf("unexpected advisory flag %q on PIE+dynamic fixture", fl)
		}
	}
}

func TestClassifyPtrace_Setuid(t *testing.T) {
	// The on-disk setuid bit drives ClassifyPtrace via os.Stat. Some
	// filesystems (notably NTFS on Windows dev hosts) silently drop the
	// setuid bit, which would cause a false negative. Verify the bit
	// landed on disk and skip with a clear reason if not — the gate is
	// meaningful on Linux CI where the bit always survives.
	p, f := openFixture(t, buildThinAarch64Setuid(), 0o4755)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("os.Stat: %v", err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skipf("setuid bit not preserved on this filesystem (mode=%v); test runs on POSIX CI", info.Mode())
	}
	eligible, _, note := ClassifyPtrace(p, f)
	if eligible == nil {
		t.Fatal("eligible = nil; want non-nil")
	}
	if *eligible {
		t.Errorf("eligible = true; want false (setuid bit set)")
	}
	if note != PtraceNote {
		t.Errorf("note = %q; want PtraceNote", note)
	}
}

func TestClassifyPtrace_Static(t *testing.T) {
	p, f := openFixture(t, buildThinX86_64Static(), 0o755)
	eligible, flags, _ := ClassifyPtrace(p, f)
	if eligible == nil || !*eligible {
		t.Errorf("eligible = %v; want true (no setuid on static binary)", eligible)
	}
	hasStatic := false
	hasNonPIE := false
	for _, fl := range flags {
		if fl == flagStaticLinkage {
			hasStatic = true
		}
		if fl == flagNonPIE {
			hasNonPIE = true
		}
	}
	if !hasStatic {
		t.Errorf("flags = %v; want containing static_linkage", flags)
	}
	if !hasNonPIE {
		t.Errorf("flags = %v; want containing non_pie (ET_EXEC)", flags)
	}
}

func TestPtraceFlagsSorted(t *testing.T) {
	// buildThinX86_64Static triggers both non_pie + static_linkage.
	p, f := openFixture(t, buildThinX86_64Static(), 0o755)
	_, flags, _ := ClassifyPtrace(p, f)
	if len(flags) < 2 {
		t.Fatalf("flags len = %d; want >= 2", len(flags))
	}
	sorted := append([]string(nil), flags...)
	sort.Strings(sorted)
	for i := range flags {
		if flags[i] != sorted[i] {
			t.Errorf("flags not sorted: got %v, want %v", flags, sorted)
			break
		}
	}
}

func TestSeamsCarryFixedNote(t *testing.T) {
	p := writeFixture(t, "rpath.bin", buildThinX86_64WithRpath(), 0o644)
	arches, err := WalkELF(p)
	if err != nil {
		t.Fatalf("WalkELF: %v", err)
	}
	if len(arches) != 1 || len(arches[0].Seams) == 0 {
		t.Fatal("no seams emitted")
	}
	for i, s := range arches[0].Seams {
		if s.PtraceEligibleBinary == nil {
			t.Errorf("seam[%d].PtraceEligibleBinary = nil; want non-nil", i)
		}
		if s.PtraceEligibleBinaryNote != PtraceNote {
			t.Errorf("seam[%d].PtraceEligibleBinaryNote = %q; want PtraceNote", i, s.PtraceEligibleBinaryNote)
		}
	}
}
