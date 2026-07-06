//go:build !goresym

package goresym_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
)

// These tests pin the default tool-free Recover, which now runs the pure-Go
// pclntab parser (recover_pure.go). It returns ErrNotImplemented only when the
// parser finds no Go pclntab — i.e. for genuinely non-Go / no-pclntab inputs
// such as the missing/bogus paths below. Under the `goresym` build tag the CLI
// backend runs instead (see recover_goresym_test.go), so these assertions are
// scoped to the default build only.

func TestRecover_NotImplemented(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		opts    goresym.Options
		wantErr error
	}{
		{
			name:    "non-empty path returns ErrNotImplemented",
			path:    "/some/binary",
			opts:    goresym.Options{},
			wantErr: goresym.ErrNotImplemented,
		},
		{
			name:    "pure backend still not implemented",
			path:    "/tmp/binary",
			opts:    goresym.Options{Backend: "pure"},
			wantErr: goresym.ErrNotImplemented,
		},
		{
			name:    "goresym backend still not implemented",
			path:    "/tmp/binary",
			opts:    goresym.Options{Backend: "goresym"},
			wantErr: goresym.ErrNotImplemented,
		},
		{
			name:    "redress backend still not implemented",
			path:    "/tmp/binary",
			opts:    goresym.Options{Backend: "redress"},
			wantErr: goresym.ErrNotImplemented,
		},
		{
			name:    "IncludeStdLib flag still not implemented",
			path:    "/tmp/binary",
			opts:    goresym.Options{IncludeStdLib: true},
			wantErr: goresym.ErrNotImplemented,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := goresym.Recover(context.Background(), tc.path, tc.opts)
			if result != nil {
				t.Errorf("expected nil result, got %+v", result)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("errors.Is(err, %v) = false; err = %v", tc.wantErr, err)
			}
		})
	}
}

func TestRecover_NilContext(t *testing.T) {
	// A cancelled context on a non-existent path still yields ErrNotImplemented
	// because the pure parser cannot open the file (no pclntab to recover).
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	_, err := goresym.Recover(ctx, "/any/path", goresym.Options{})
	if !errors.Is(err, goresym.ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented with cancelled context, got %v", err)
	}
}

// TestRecover_StrippedELF_NowRecovers pins the new default behavior: a real
// stripped Go binary is recovered by the pure-Go parser, no longer returning
// ErrNotImplemented.
func TestRecover_StrippedELF_NowRecovers(t *testing.T) {
	path := filepath.Join("testdata", "app_linux_stripped")
	res, err := goresym.Recover(context.Background(), path, goresym.Options{IncludeStdLib: true})
	if err != nil {
		t.Fatalf("Recover(stripped) returned error: %v", err)
	}
	if res == nil || len(res.Symbols) == 0 {
		t.Fatal("expected the stripped Go binary to recover >= 1 symbol")
	}
}

// TestRecover_NonGoInput_NotImplemented keeps the sentinel contract for a
// genuine non-Go / no-pclntab input.
func TestRecover_NonGoInput_NotImplemented(t *testing.T) {
	p := filepath.Join(t.TempDir(), "not-a-binary.bin")
	if err := os.WriteFile(p, []byte("definitely not a Go binary\x00\x01"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	res, err := goresym.Recover(context.Background(), p, goresym.Options{})
	if res != nil {
		t.Errorf("expected nil result for non-Go input, got %+v", res)
	}
	if !errors.Is(err, goresym.ErrNotImplemented) {
		t.Errorf("expected ErrNotImplemented for non-Go input, got %v", err)
	}
}
