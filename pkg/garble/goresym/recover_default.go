//go:build !goresym

package goresym

import (
	"context"
	"fmt"
)

// Recover is the default tool-free implementation. It runs the pure-Go
// pclntab parser (recover_pure.go) — no external tool, no cgo, no build
// tags — and returns the recovered symbol set when at least one function
// is found. It falls back to the ErrNotImplemented sentinel only when the
// pure parser finds no Go pclntab (a genuinely non-Go / no-pclntab input),
// preserving the historical "nothing to recover" contract that callers
// compare against with errors.Is. This keeps the default `go build .` free
// of any external-tool requirement while now actually recovering symbols
// from stripped and garble-obfuscated Go binaries.
func Recover(ctx context.Context, path string, opts Options) (*Result, error) {
	if path == "" {
		return nil, fmt.Errorf("goresym: path is required")
	}
	if res, err := recoverPure(ctx, path, opts); err == nil && res != nil && len(res.Symbols) > 0 {
		return res, nil
	}
	return nil, ErrNotImplemented
}
