//go:build goresym

package goresym_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
)

// requireTool skips the test when the GoReSym executable is absent, so
// the tagged suite stays green on machines without the optional tool. It
// resolves the tool through the backend's own candidate-name logic
// (LookupGoresymForTest → lookupGoresym) so the skip is honest on
// case-sensitive Linux/macOS where the canonical install is `GoReSym`.
func requireTool(t *testing.T) {
	t.Helper()
	if _, err := goresym.LookupGoresymForTest(); err != nil {
		t.Skip("GoReSym executable not on PATH; skipping live recovery test")
	}
}

// strippedELF is a committed stripped (-s -w) Go ELF fixture. GoReSym
// recovers its symbols from the pclntab even though the symtab/DWARF are
// gone (see docs/design/2026-goresym-backend.md §4).
const strippedELF = "app_linux_stripped"

func TestRecover_LiveStrippedELF(t *testing.T) {
	requireTool(t)

	path := filepath.Join("testdata", strippedELF)
	res, err := goresym.Recover(context.Background(), path, goresym.Options{})
	if err != nil {
		t.Fatalf("Recover returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Recover returned nil result")
	}
	if len(res.Symbols) < 1 {
		t.Fatalf("expected >=1 recovered symbol, got %d", len(res.Symbols))
	}
}

func TestRecover_RedressBackend_NotImplemented(t *testing.T) {
	_, err := goresym.Recover(context.Background(), filepath.Join("testdata", strippedELF), goresym.Options{Backend: "redress"})
	if !errors.Is(err, goresym.ErrNotImplemented) {
		t.Errorf("redress backend: errors.Is(err, ErrNotImplemented) = false; err = %v", err)
	}
}

func TestRecover_BogusPath_NonImplementedError(t *testing.T) {
	requireTool(t)

	// A path that exists is not required for the tool to fail; GoReSym is
	// invoked on a non-binary and must exit non-zero. The error must be a
	// real (wrapped) error, NOT the ErrNotImplemented sentinel.
	_, err := goresym.Recover(context.Background(), filepath.Join("testdata", "does_not_exist.bin"), goresym.Options{})
	if err == nil {
		t.Fatal("expected error for bogus path, got nil")
	}
	if errors.Is(err, goresym.ErrNotImplemented) {
		t.Errorf("bogus path must not return ErrNotImplemented; got %v", err)
	}
}

func TestRecover_EmptyPath_Tagged(t *testing.T) {
	_, err := goresym.Recover(context.Background(), "", goresym.Options{})
	if err == nil {
		t.Fatal("expected error for empty path, got nil")
	}
	if errors.Is(err, goresym.ErrNotImplemented) {
		t.Errorf("empty path must be a validation error, not ErrNotImplemented; got %v", err)
	}
}
