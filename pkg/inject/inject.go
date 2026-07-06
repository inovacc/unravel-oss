/*
Copyright (c) 2026 Security Research
*/
package inject

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Scan iterates the scanner registry, runs every scanner whose Detect(appDir)
// returns true, and merges results into a single ScanResult. Per-scanner
// errors are swallowed so one bad scanner cannot fail the whole run.
//
// Framework selection rule (16-CONTEXT D-02):
//   - 0 scanners detect → Framework == ""
//   - 1 scanner detects  → Framework == that scanner's framework
//   - 2+ scanners detect → Framework == FrameworkHybrid (single token)
func Scan(ctx context.Context, appDir string) (*ScanResult, error) {
	result := &ScanResult{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Seams:       []Seam{},
	}

	var detectedFrameworks []Framework
	for _, s := range Scanners() {
		if !s.Detect(appDir) {
			continue
		}
		detectedFrameworks = append(detectedFrameworks, s.Framework())
		seams, err := s.Scan(ctx, appDir)
		if err != nil {
			// Swallow: never fail the whole scan because one scanner errored.
			continue
		}
		result.Seams = append(result.Seams, seams...)
	}

	switch len(detectedFrameworks) {
	case 0:
		result.Framework = ""
	case 1:
		result.Framework = detectedFrameworks[0]
	default:
		result.Framework = FrameworkHybrid
	}

	result.Summary = computeSummary(result.Seams)
	return result, nil
}

// computeSummary aggregates seams into a Summary keyed by kind + confidence.
func computeSummary(seams []Seam) Summary {
	s := Summary{
		ByKind:       map[string]int{},
		ByConfidence: map[string]int{},
	}
	for _, seam := range seams {
		s.TotalSeams++
		s.ByKind[seam.Kind]++
		s.ByConfidence[string(seam.Confidence)]++
	}
	return s
}

// ArchProvider is the function signature the macos package registers via
// RegisterArchProvider. Decoupled to avoid a direct import cycle.
type ArchProvider func(appDir string) ([]ArchReport, error)

var archProvider ArchProvider

// RegisterArchProvider is called from pkg/inject/macos/init() to expose
// its per-arch walker to ScanWithPlatform without a direct import.
func RegisterArchProvider(p ArchProvider) { archProvider = p }

var linuxArchProvider ArchProvider

// RegisterLinuxArchProvider is called from pkg/inject/linux/init() to
// expose its per-arch walker to ScanWithPlatform without a direct
// import. Mirror of RegisterArchProvider for macOS (Phase 25 D-22 keeps
// the two registries decoupled so the CI grep gate stays meaningful).
func RegisterLinuxArchProvider(p ArchProvider) { linuxArchProvider = p }

// ResolvePlatform turns a user --platform value into a canonical token.
// "auto" peeks file magic to pick "macos" for Mach-O binaries; otherwise
// returns the empty string (caller falls back to existing Scan).
func ResolvePlatform(appDir, platform string) string {
	switch platform {
	case "macos", "linux", "windows":
		return platform
	case "", "auto":
		// fall through
	default:
		return platform
	}

	info, err := os.Stat(appDir)
	if err != nil {
		return ""
	}
	// peekKind returns "macos" for Mach-O magic, "linux" for ELF magic
	// (Phase 25 CONTEXT D-03), or "" otherwise.
	peekKind := func(p string) string {
		fh, err := os.Open(p)
		if err != nil {
			return ""
		}
		defer func() { _ = fh.Close() }()
		var buf [4]byte
		if _, err := io.ReadFull(fh, buf[:]); err != nil {
			return ""
		}
		// ELF: 0x7f 'E' 'L' 'F' (Phase 25 D-03).
		if buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F' {
			return "linux"
		}
		m := binary.BigEndian.Uint32(buf[:])
		switch m {
		case 0xfeedface, 0xfeedfacf,
			0xcafebabe, 0xbebafeca,
			0xcefaedfe, 0xcffaedfe:
			return "macos"
		}
		return ""
	}
	if !info.IsDir() {
		return peekKind(appDir)
	}
	var hit string
	_ = filepath.Walk(appDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		if k := peekKind(p); k != "" {
			hit = k
			return io.EOF
		}
		return nil
	})
	return hit
}

// ScanWithPlatform runs platform-specific dispatch. When platform=="macos"
// the macOS arch provider is invoked directly and its per-arch report is
// attached to ScanResult.Arches in addition to the flattened Seams. For
// any other value it delegates to the framework-driven Scan.
func ScanWithPlatform(ctx context.Context, appDir, platform string) (*ScanResult, error) {
	switch platform {
	case "macos":
		return scanWithArchProvider(ctx, appDir, FrameworkMacOS, archProvider)
	case "linux":
		return scanWithArchProvider(ctx, appDir, FrameworkLinux, linuxArchProvider)
	default:
		return Scan(ctx, appDir)
	}
}

// scanWithArchProvider runs the supplied per-arch provider and packages
// its output into a ScanResult — Arches grouped, Seams flattened. Used by
// both macOS (Phase 24) and Linux (Phase 25 D-13) dispatch paths.
func scanWithArchProvider(ctx context.Context, appDir string, fw Framework, p ArchProvider) (*ScanResult, error) {
	result := &ScanResult{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Framework:   fw,
		Seams:       []Seam{},
	}
	if p == nil {
		result.Summary = computeSummary(result.Seams)
		return result, nil
	}
	arches, err := p(appDir)
	if err != nil {
		return nil, err
	}
	result.Arches = arches
	for _, a := range arches {
		result.Seams = append(result.Seams, a.Seams...)
	}
	result.Summary = computeSummary(result.Seams)
	_ = ctx
	return result, nil
}
