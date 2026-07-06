/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/debug"
)

// TestAnalyzeGoBinary_GoSymbolsRecovered pins the new default (tool-free)
// contract: the pure-Go pclntab parser (recover_pure.go) now backs
// goresym.Recover, so dissecting a real Go binary recovers its function symbols
// instead of degrading to nil. The test binary itself is a real Go binary, so
// it is a convenient fixture for the Go-binary analyzer without committing a
// sample.
//
// Invariants asserted:
//   - r.GoSymbols is populated (non-nil, at least one symbol).
//   - no "go symbol recovery" error is recorded — recovery succeeded, so the
//     analyzer must not pollute r.Errors.
func TestAnalyzeGoBinary_GoSymbolsRecovered(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	r := &DissectResult{
		debugRec: debug.NopRecorder(),
	}

	analyzeGoBinary(r, self, Options{})

	if r.GoSymbols == nil {
		t.Fatal("expected GoSymbols to be recovered from the (real Go) test binary, got nil")
	}
	if len(r.GoSymbols.Symbols) == 0 {
		t.Errorf("expected at least one recovered Go symbol, got 0")
	}
	for _, e := range r.Errors {
		if strings.Contains(e, "go symbol recovery") {
			t.Errorf("successful recovery must not record a go symbol recovery error, got: %q", e)
		}
	}
}

// TestAnalyzeGoBinary_GoSymbolsGracefulDegrade verifies the "go symbols" step
// still degrades cleanly for a genuinely non-Go input: goresym.Recover finds no
// pclntab and returns ErrNotImplemented, so r.GoSymbols stays nil and no "go
// symbol recovery" entry pollutes r.Errors. The dissect pipeline must never
// fail because a file turned out not to be a recoverable Go binary.
func TestAnalyzeGoBinary_GoSymbolsGracefulDegrade(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-go-binary.bin")
	if err := os.WriteFile(p, []byte("this is not a Go binary at all\x00\x01\x02\x03"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	r := &DissectResult{
		debugRec: debug.NopRecorder(),
	}

	analyzeGoBinary(r, p, Options{})

	if r.GoSymbols != nil {
		t.Errorf("expected GoSymbols nil for non-Go input, got %+v", r.GoSymbols)
	}
	for _, e := range r.Errors {
		if strings.Contains(e, "go symbol recovery") {
			t.Errorf("non-Go input must not record a go symbol recovery error, got: %q", e)
		}
	}
}
