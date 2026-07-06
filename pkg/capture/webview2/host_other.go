//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"context"
	"log/slog"
)

// unsupportedHost is the non-Windows stub. Every method returns
// ErrUnsupportedPlatform — Linux/macOS callers fail loudly at the seam
// rather than spawning anything. The real Windows host is 83-04.
type unsupportedHost struct {
	logger *slog.Logger
}

// newPlatformHost is the !windows-tagged factory used by NewHost.
func newPlatformHost(logger *slog.Logger) ProcessHost {
	return &unsupportedHost{logger: logger}
}

func (h *unsupportedHost) Find(_ context.Context, _ string) ([]int, error) {
	return nil, ErrUnsupportedPlatform
}

func (h *unsupportedHost) Kill(_ context.Context, _ int) error {
	return ErrUnsupportedPlatform
}

func (h *unsupportedHost) ResolveExe(_ context.Context, _ string) (string, error) {
	return "", ErrUnsupportedPlatform
}

func (h *unsupportedHost) Spawn(_ context.Context, _ string, _ []string, _ []string) (Process, error) {
	return nil, ErrUnsupportedPlatform
}

func (h *unsupportedHost) SpawnAUMID(_ context.Context, _ string, _ int) (Process, error) {
	return nil, ErrUnsupportedPlatform
}

func (h *unsupportedHost) CleanupHKCUEnv(_ context.Context) error {
	return ErrUnsupportedPlatform
}
