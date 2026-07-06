/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNativeCLRModules_PopulatesFromManagedPE proves the native pure-Go CLR
// reader yields >=1 TypeModule from the synth managed-PE fixture. This is the
// in-memory feed for KB cil-module ingest (FIX #1); a zero result would mean
// the capture path silently drops .NET modules.
func TestNativeCLRModules_PopulatesFromManagedPE(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "Sample.dll")
	synthManagedAssemblyForDissect(t, asm)

	mods := nativeCLRModules(asm)
	if len(mods) == 0 {
		t.Fatal("nativeCLRModules returned 0 modules for a managed PE — silent-empty regression")
	}

	var greeter bool
	for _, m := range mods {
		if m.Name == "Demo.Greeter" {
			greeter = true
		}
	}
	if !greeter {
		t.Errorf("Demo.Greeter not found among %d modules", len(mods))
	}
}

// TestAnalyzeDotNetDecompile_AttachesCLRModules proves the supplemental TypePE
// analyzer threads native modules onto DissectResult.CLRModules for a managed
// PE — the field KB ingest reads. The ilspy beautify track may no-op (no
// ilspycmd / no AI) without affecting this native attachment.
func TestAnalyzeDotNetDecompile_AttachesCLRModules(t *testing.T) {
	dir := t.TempDir()
	asm := filepath.Join(dir, "Sample.dll")
	synthManagedAssemblyForDissect(t, asm)

	r := &DissectResult{FileName: "Sample.dll"}
	analyzeDotNetDecompile(r, asm, Options{TeardownDir: dir})

	if len(r.CLRModules) == 0 {
		t.Fatal("analyzer did not populate DissectResult.CLRModules for a managed PE")
	}
}

// TestNativeCLRModules_NonManagedIsEmpty proves a non-managed input yields no
// modules and never panics — the analyzer's IsManagedPE guard plus the helper's
// warn-and-continue contract keep the capture path safe.
func TestNativeCLRModules_NonManagedIsEmpty(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "not-a-pe.bin")
	if err := os.WriteFile(junk, []byte("definitely not a managed PE"), 0o644); err != nil {
		t.Fatalf("write junk: %v", err)
	}
	if mods := nativeCLRModules(junk); len(mods) != 0 {
		t.Errorf("expected 0 modules for non-managed input, got %d", len(mods))
	}
}
