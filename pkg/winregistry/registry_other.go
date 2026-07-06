//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package winregistry

import "runtime"

// Dump on non-Windows returns Result with a single error so the MCP
// tool stays in the surface advertisement on every host.
func Dump(opts DumpOptions) (*Result, error) {
	return &Result{
		Platform: runtime.GOOS,
		Errors:   []string{"registry dump not supported on " + runtime.GOOS},
	}, ErrNotSupported
}
