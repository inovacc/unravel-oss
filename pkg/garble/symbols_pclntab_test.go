/* Copyright (c) 2026 Security Research */
package garble

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestAnalyzeSymbols_PclntabFallback_StrippedELF verifies AnalyzeSymbols falls
// back to the pure-Go pclntab recovery backend (pkg/garble/goresym) when the
// classic ELF symbol table is stripped, recovering a real function set and
// setting SymbolSource honestly to "pclntab" instead of silently reporting
// zero symbols.
func TestAnalyzeSymbols_PclntabFallback_StrippedELF(t *testing.T) {
	path := filepath.Join("goresym", "testdata", "app_linux_stripped")

	result, err := AnalyzeSymbols(path)
	if err != nil {
		t.Fatalf("AnalyzeSymbols(%s): %v", path, err)
	}

	if result.FunctionCount == 0 {
		t.Error("expected FunctionCount > 0 for stripped binary via pclntab fallback")
	}

	if result.SymbolSource != "pclntab" {
		t.Errorf("expected SymbolSource %q, got %q", "pclntab", result.SymbolSource)
	}

	if len(result.Packages) == 0 {
		t.Error("expected at least one recovered package")
	}

	t.Logf("stripped ELF via AnalyzeSymbols: function_count=%d symbol_source=%s packages=%v",
		result.FunctionCount, result.SymbolSource, result.Packages)
}

// TestAnalyzeSymbols_SymtabSource_NonStripped verifies a binary that still
// carries a classic symbol table reports SymbolSource "symtab" — i.e. the new
// pclntab fallback never overrides a working symtab read. Builds a trivial Go
// program with plain `go build` (no -s -w), which retains a symbol table.
func TestAnalyzeSymbols_SymtabSource_NonStripped(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "386" {
		t.Skip("requires x86")
	}

	tmpDir := t.TempDir()
	src := filepath.Join(tmpDir, "main.go")
	bin := filepath.Join(tmpDir, "test-binary-symtab")

	if err := os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "build", "-o", bin, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	result, err := AnalyzeSymbols(bin)
	if err != nil {
		t.Fatalf("AnalyzeSymbols: %v", err)
	}

	if result.FunctionCount == 0 {
		t.Error("expected FunctionCount > 0 for non-stripped binary")
	}

	if result.SymbolSource != "symtab" {
		t.Errorf("expected SymbolSource %q, got %q", "symtab", result.SymbolSource)
	}
}
