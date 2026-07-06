/*
Copyright (c) 2026 Security Research
*/
// Package linux scans ELF binaries for code-injection seams (DT_NEEDED,
// DT_RPATH, DT_RUNPATH) and classifies ptrace eligibility from binary
// attributes only. Host ptrace_scope policy is a runtime concern and is
// NOT captured here — see SCHEMA.md.
//
// Pure Go via stdlib debug/elf. No CGO. No imports of pkg/inject/macos.
package linux

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// Scanner implements inject.Scanner for Linux ELF binaries.
type Scanner struct{}

// Framework returns inject.FrameworkLinux.
func (Scanner) Framework() inject.Framework { return inject.FrameworkLinux }

// Detect returns true when appDir holds an ELF binary (or appDir itself
// is an ELF file).
func (Scanner) Detect(appDir string) bool {
	return findELF(appDir) != ""
}

// Scan walks ELF dynamic-section entries and returns injection seams
// flattened across the (single) arch. Per-arch grouping is exposed
// separately via inject.RegisterLinuxArchProvider so
// inject.ScanWithPlatform can attach ScanResult.Arches without an
// import cycle (wired in 25-04).
func (Scanner) Scan(ctx context.Context, appDir string) ([]inject.Seam, error) {
	_ = ctx
	bin := findELF(appDir)
	if bin == "" {
		return nil, nil
	}
	arches, err := WalkELF(bin)
	if err != nil {
		return nil, err
	}
	var flat []inject.Seam
	for _, a := range arches {
		flat = append(flat, a.Seams...)
	}
	return flat, nil
}

// findELF walks appDir and returns the first plausible ELF binary path,
// or "" if none. If appDir itself is a regular file, its magic is
// checked directly.
func findELF(appDir string) string {
	info, err := os.Stat(appDir)
	if err != nil {
		return ""
	}
	if !info.IsDir() {
		if IsELF(appDir) {
			return appDir
		}
		return ""
	}
	var found string
	_ = filepath.Walk(appDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if IsELF(p) {
			found = p
			return io.EOF // stop early
		}
		return nil
	})
	return found
}

func init() {
	inject.RegisterScanner(Scanner{})
	// 25-04 wires the linux arch provider so inject.ScanWithPlatform can
	// attach per-arch reports. We register here in the scanner's init so
	// the registry blank-import is sufficient to populate both hooks.
	inject.RegisterLinuxArchProvider(func(appDir string) ([]inject.ArchReport, error) {
		bin := findELF(appDir)
		if bin == "" {
			return nil, nil
		}
		return WalkELF(bin)
	})
}
