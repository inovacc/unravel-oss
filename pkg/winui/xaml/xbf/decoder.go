/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// MaxFileSize caps DecodeXBF's input. T-04-04 mitigation: refuse oversized
// files before any parsing work begins.
const MaxFileSize = 64 << 20 // 64 MiB

// DecodedXAML is the public result type for XBF decoding.
type DecodedXAML struct {
	Version        string   `json:"version"`
	Recovered      string   `json:"recovered"`
	UnknownOpcodes []byte   `json:"unknown_opcodes,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	SourceBytes    int64    `json:"source_bytes"`
}

// DecodeXBF reads an XBF file from disk and returns its decoded form.
// Path-traversal segments are rejected before any I/O.
func DecodeXBF(path string) (*DecodedXAML, error) {
	if path == "" {
		return nil, fmt.Errorf("xbf path empty")
	}
	cleaned := filepath.Clean(path)
	// Reject literal `..` segments. Detection covers both cleaned forms and
	// raw input (where Clean might collapse them away).
	if containsTraversal(path) || containsTraversal(cleaned) {
		return nil, fmt.Errorf("xbf path rejected: %s", path)
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve xbf path: %w", err)
	}
	data, err := os.ReadFile(abs) //nolint:gosec // path sanitized above
	if err != nil {
		return nil, fmt.Errorf("read xbf: %w", err)
	}
	return DecodeXBFBytes(data)
}

// DecodeXBFBytes decodes an XBF byte slice. Top-level defer/recover converts
// any missed panic into a wrapped error (T-04-04 belt-and-suspenders).
func DecodeXBFBytes(data []byte) (out *DecodedXAML, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("xbf decode panic: %v", r)
			out = nil
		}
	}()

	if len(data) > 64<<20 {
		return nil, fmt.Errorf("xbf size exceeds limit: %d bytes (cap %d)", len(data), MaxFileSize)
	}
	if len(data) < HeaderSize {
		return nil, fmt.Errorf("xbf truncated: %d bytes < header size %d", len(data), HeaderSize)
	}

	// Branch on on-disk header signature: WindowsAppSDK 1.6.x v2.1 uses a
	// completely different layout from the synthetic v2.1 fixtures produced
	// by newXBFBuilder. Detect via IsWAS16XBF and route to the dedicated
	// decoder; on any failure there, fall through to the legacy parser so
	// callers still get a structured error.
	if IsWAS16XBF(data) {
		res, err := DecodeWAS16V21(data)
		if err != nil {
			return nil, err
		}
		warnings := append([]string{}, res.Warnings...)
		return &DecodedXAML{
			Version:     fmt.Sprintf("%d.%d", res.Header.Major, res.Header.Minor),
			Recovered:   res.Recovered,
			Warnings:    warnings,
			SourceBytes: int64(len(data)),
		}, nil
	}

	r := bytes.NewReader(data)
	hdr, err := ParseHeader(r)
	if err != nil {
		return nil, err
	}
	tables, err := ParseTables(r, hdr)
	if err != nil {
		return nil, err
	}

	streamStart := hdr.MaxRegionEnd()
	if int64(streamStart) > int64(len(data)) {
		return nil, fmt.Errorf("xbf truncated: stream start %d > file size %d", streamStart, len(data))
	}
	if _, err := r.Seek(int64(streamStart), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek stream: %w", err)
	}
	tree, err := DecodeNodeStream(r, tables)
	if err != nil {
		return nil, err
	}
	recovered := RenderXAML(tree, tables)

	warnings := append([]string{}, hdr.Warnings...)
	warnings = append(warnings, tables.Warnings...)
	warnings = append(warnings, tree.Warnings()...)

	return &DecodedXAML{
		Version:        fmt.Sprintf("%d.%d", hdr.Major, hdr.Minor),
		Recovered:      recovered,
		UnknownOpcodes: tree.UnknownOpcodes,
		Warnings:       warnings,
		SourceBytes:    int64(len(data)),
	}, nil
}

// ToXAMLEntry adapts a DecodedXAML into the consumer winui.XAMLEntry shape
// for plan 05's analyzer wiring.
func ToXAMLEntry(d *DecodedXAML, source string) winui.XAMLEntry {
	if d == nil {
		return winui.XAMLEntry{Path: source, Kind: "xbf"}
	}
	errs := append([]string{}, d.Warnings...)
	if len(d.UnknownOpcodes) > 0 {
		errs = append(errs, fmt.Sprintf("unknown opcodes: %x", d.UnknownOpcodes))
	}
	return winui.XAMLEntry{
		Path:        source,
		Kind:        "xbf",
		Recovered:   d.Recovered,
		SourceBytes: d.SourceBytes,
		Errors:      errs,
	}
}

// DecodeXBFForEntry is the high-level helper used by the analyzer pipeline.
// It decodes data, and on failure emits a "xbf-raw" graceful-fallback entry
// containing the first 256 bytes hex-encoded plus an assemblies-table size
// hint when one is available. The two-tier output lets downstream tooling
// distinguish a clean decode from a best-effort raw dump without scraping
// the warnings slice.
func DecodeXBFForEntry(data []byte, source string) winui.XAMLEntry {
	// Phase 20 (XBF-V3-01): detect-only forward-compat. v3 inputs short-circuit
	// to a raw-fallback entry with VersionHint set so downstream tooling knows
	// to route them to a future v3 decoder (deferred to v2.4 when production
	// targets ship). Tracked in .planning/phases/20-xbf-v3-decoder/20-CONTEXT.md.
	if IsXBFv3(data) {
		return winui.XAMLEntry{
			Path:        source,
			Kind:        "xbf-raw",
			SourceBytes: int64(len(data)),
			Errors:      []string{"xbf v3 not yet supported — production target unobserved as of 2026-05; tracked in .planning/phases/20-xbf-v3-decoder/20-CONTEXT.md D-01"},
			RawBytesHex: rawHexPrefix(data, 256),
			VersionHint: XBFv3MinorHint(data),
		}
	}
	d, err := DecodeXBFBytes(data)
	if err == nil {
		return ToXAMLEntry(d, source)
	}
	// Compute the assemblies-size hint best-effort: legacy layout keeps the
	// assemblies region size at offset 16. Real WAS-1.6 v2.1 has no such
	// field so the hint stays zero in that path.
	var hint uint64
	if len(data) >= 20 {
		// Legacy: bytes 12..16 = strings.Offset, 16..20 = strings.Size, but
		// for the failure that produced "assemblies table truncated: need N
		// bytes have 120" the relevant field is the assemblies region size,
		// stored at offset 20..24 in the legacy 7-region TOC.
		if len(data) >= 24 {
			hint = uint64(uint32(data[20]) | uint32(data[21])<<8 | uint32(data[22])<<16 | uint32(data[23])<<24)
		}
	}
	return winui.XAMLEntry{
		Path:               source,
		Kind:               "xbf-raw",
		SourceBytes:        int64(len(data)),
		Errors:             []string{err.Error()},
		RawBytesHex:        rawHexPrefix(data, 256),
		AssembliesSizeHint: hint,
	}
}

// containsTraversal reports whether p has any `..` path segment.
func containsTraversal(p string) bool {
	parts := strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	return slices.Contains(parts, "..")
}
