/*
Copyright (c) 2026 Security Research
*/
package macos

import (
	"bytes"
	"context"
	"debug/macho"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestIsMachO(t *testing.T) {
	t.Parallel()
	thinPath := writeFixture(t, buildThinARM64Stub(t, "@rpath/A.dylib", "@rpath/B.dylib", "/p"))
	if !IsMachO(thinPath) {
		t.Fatalf("IsMachO(thin) = false, want true")
	}
	bogus := filepath.Join(t.TempDir(), "bogus")
	if err := os.WriteFile(bogus, []byte{0xde, 0xad, 0xbe, 0xef}, 0o644); err != nil {
		t.Fatal(err)
	}
	if IsMachO(bogus) {
		t.Fatalf("IsMachO(bogus) = true, want false")
	}
}

func TestThinStubParses(t *testing.T) {
	t.Parallel()
	b := buildThinARM64Stub(t, "@rpath/Foo.dylib", "@rpath/Weak.dylib", "/usr/local/lib")
	f, err := macho.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	defer func() { _ = f.Close() }()
	if got := f.Ncmd; got != 3 {
		t.Errorf("Ncmd = %d, want 3", got)
	}
}

func TestWalkThin(t *testing.T) {
	t.Parallel()
	p := writeFixture(t, buildThinARM64Stub(t, "@rpath/Foo.dylib", "@rpath/Weak.dylib", "/usr/local/lib"))
	arches, err := WalkMachO(p)
	if err != nil {
		t.Fatalf("WalkMachO: %v", err)
	}
	if len(arches) != 1 {
		t.Fatalf("len(arches) = %d, want 1", len(arches))
	}
	a := arches[0]
	if !strings.Contains(strings.ToLower(a.Arch), "arm64") {
		t.Errorf("Arch = %q, want substring 'arm64'", a.Arch)
	}
	got := map[string]string{}
	for _, s := range a.Seams {
		got[s.Kind] = s.Evidence[0].Snippet
	}
	if got["LC_LOAD_DYLIB"] != "@rpath/Foo.dylib" {
		t.Errorf("LC_LOAD_DYLIB = %q", got["LC_LOAD_DYLIB"])
	}
	if got["LC_LOAD_WEAK_DYLIB"] != "@rpath/Weak.dylib" {
		t.Errorf("LC_LOAD_WEAK_DYLIB = %q", got["LC_LOAD_WEAK_DYLIB"])
	}
	if got["LC_RPATH"] != "/usr/local/lib" {
		t.Errorf("LC_RPATH = %q", got["LC_RPATH"])
	}
}

func TestWalkFat(t *testing.T) {
	t.Parallel()
	p := writeFixture(t, buildFatX86_64ARM64Stub(t))
	arches, err := WalkMachO(p)
	if err != nil {
		t.Fatalf("WalkMachO: %v", err)
	}
	if len(arches) != 2 {
		t.Fatalf("len(arches) = %d, want 2", len(arches))
	}
	if arches[0].Arch == arches[1].Arch {
		t.Errorf("expected distinct Arch strings, got %q twice", arches[0].Arch)
	}
	for i, a := range arches {
		if len(a.Seams) == 0 {
			t.Errorf("arch[%d] %q has zero seams", i, a.Arch)
		}
	}
}

func TestWalkThin_Hardened(t *testing.T) {
	t.Parallel()
	flags := uint32(FlagHardenedRuntime | FlagLibraryValidation)
	plain := writeFixture(t, buildThinARM64Stub(t, "@rpath/A.dylib", "@rpath/W.dylib", "/p"))
	hardened := writeFixture(t, buildHardenedThinStub(t, "@rpath/A.dylib", "@rpath/W.dylib", "/p", flags))

	plainAr, err := WalkMachO(plain)
	if err != nil {
		t.Fatalf("walk plain: %v", err)
	}
	hardAr, err := WalkMachO(hardened)
	if err != nil {
		t.Fatalf("walk hardened: %v", err)
	}
	if len(plainAr) != 1 || len(hardAr) != 1 {
		t.Fatalf("expected single arch each, got plain=%d hard=%d", len(plainAr), len(hardAr))
	}

	// Every hardened seam carries both signing-block strings.
	for _, s := range hardAr[0].Seams {
		want := []string{"hardened-runtime", "library-validation"}
		if len(s.SigningBlocks) != 2 {
			t.Errorf("seam %q SigningBlocks=%v want %v", s.Kind, s.SigningBlocks, want)
			continue
		}
		if s.SigningBlocks[0] != want[0] || s.SigningBlocks[1] != want[1] {
			t.Errorf("seam %q SigningBlocks=%v want %v", s.Kind, s.SigningBlocks, want)
		}
	}

	// Every hardened seam confidence is exactly one tier below the plain
	// sibling. Plain seams default to ConfidenceMedium; hardened therefore
	// must be ConfidenceLow.
	for _, s := range plainAr[0].Seams {
		if s.Confidence != inject.ConfidenceMedium {
			t.Errorf("plain seam %q Confidence=%q want medium", s.Kind, s.Confidence)
		}
	}
	for _, s := range hardAr[0].Seams {
		if s.Confidence != inject.ConfidenceLow {
			t.Errorf("hardened seam %q Confidence=%q want low", s.Kind, s.Confidence)
		}
	}
}

func TestScanWithPlatform_AttachesArches(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "thin")
	if err := os.WriteFile(bin, buildThinARM64Stub(t, "@rpath/Foo.dylib", "@rpath/Weak.dylib", "/usr/local/lib"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := inject.ScanWithPlatform(context.Background(), dir, "macos")
	if err != nil {
		t.Fatalf("ScanWithPlatform: %v", err)
	}
	if len(res.Arches) != 1 {
		t.Fatalf("len(Arches) = %d, want 1", len(res.Arches))
	}
	if len(res.Seams) != len(res.Arches[0].Seams) {
		t.Errorf("len(Seams)=%d != len(Arches[0].Seams)=%d", len(res.Seams), len(res.Arches[0].Seams))
	}
	if res.Framework != inject.FrameworkMacOS {
		t.Errorf("Framework=%q want %q", res.Framework, inject.FrameworkMacOS)
	}
}
