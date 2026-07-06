/*
Copyright (c) 2026 Security Research
*/
// Package macos enumerates Mach-O code-injection seams (LC_LOAD_DYLIB,
// LC_LOAD_WEAK_DYLIB, LC_RPATH) for macOS .app bundles using stdlib
// debug/macho only. Hardened-runtime + library-validation flags are
// recorded in Seam.SigningBlocks and trigger a confidence downgrade.
// No CGO. No imports of pkg/inject/linux/.
package macos

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// Scanner implements inject.Scanner for macOS Mach-O binaries.
type Scanner struct{}

// Framework returns inject.FrameworkMacOS.
func (Scanner) Framework() inject.Framework { return inject.FrameworkMacOS }

// Detect returns true when appDir holds a Mach-O binary (thin or fat).
func (Scanner) Detect(appDir string) bool {
	return findMachO(appDir) != ""
}

// Scan walks Mach-O load commands and returns injection seams flattened
// across all arches. The per-arch grouping is exposed separately via
// inject.RegisterArchProvider so inject.ScanWithPlatform can attach
// ScanResult.Arches without an import cycle.
func (Scanner) Scan(ctx context.Context, appDir string) ([]inject.Seam, error) {
	bin := findMachO(appDir)
	if bin == "" {
		return nil, nil
	}
	arches, err := WalkMachO(bin)
	if err != nil {
		return nil, err
	}
	_ = ctx
	var flat []inject.Seam
	for _, a := range arches {
		flat = append(flat, a.Seams...)
	}
	return flat, nil
}

// findMachO walks appDir and returns the first plausible Mach-O binary
// path, or "" if none. If appDir itself is a regular file, its magic is
// checked directly.
func findMachO(appDir string) string {
	info, err := os.Stat(appDir)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		if IsMachO(appDir) {
			return appDir
		}
		return ""
	}
	var found string
	_ = filepath.Walk(appDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if IsMachO(p) {
			found = p
			return io.EOF
		}
		return nil
	})
	return found
}

func init() {
	inject.RegisterScanner(Scanner{})
	inject.RegisterArchProvider(func(appDir string) ([]inject.ArchReport, error) {
		bin := findMachO(appDir)
		if bin == "" {
			return nil, nil
		}
		return WalkMachO(bin)
	})
}
