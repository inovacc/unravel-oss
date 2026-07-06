/*
Copyright (c) 2026 Security Research
*/

// Package detect provides UWP detection from AppxManifest.xml content.
//
// Note on XML safety: Go's encoding/xml package does not process external
// entities by default (no XXE risk; T-04-04 mitigation), and structurally
// malformed input is reported as an error rather than a panic.
package detect

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// maxManifestSize is the upper bound applied to AppxManifest.xml reads.
// 2 MiB matches the practical schema ceiling cited in Microsoft docs and
// bounds T-04-02 (DoS via oversized manifest).
const maxManifestSize int64 = 2 * 1024 * 1024

// DetectFromManifest reads an AppxManifest.xml file at path and returns
// FrameworkInfo entries describing the UWP signal strength. The path is
// cleaned, rejected if it contains ".." segments after cleaning, resolved
// to an absolute location, and Stat'd to ensure it is a regular file
// (T-04-01 path-traversal mitigation, V5 ASVS).
func DetectFromManifest(path string) ([]winui.FrameworkInfo, error) {
	if path == "" {
		return nil, errors.New("empty manifest path")
	}
	cleaned := filepath.Clean(path)
	// Reject obvious traversal — both raw and post-clean.
	if strings.Contains(path, "..") || strings.Contains(cleaned, "..") {
		return nil, errors.New("path contains traversal segments")
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve manifest path: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat manifest: %w", err)
	}
	// Reject symlinks and non-regular files outright.
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("manifest path is a symlink")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("manifest path is not a regular file")
	}

	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open manifest: %w", err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, maxManifestSize+1))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	if int64(len(data)) > maxManifestSize {
		return nil, fmt.Errorf("manifest exceeds %d byte cap", maxManifestSize)
	}
	return DetectFromManifestBytes(data)
}

// DetectFromManifestBytes parses AppxManifest XML content and returns
// FrameworkInfo entries. Never panics on malformed input — encoding/xml
// reports errors via return values.
//
// Detection rules (D-03, RESEARCH.md):
//   - xmlns:uap* declared AND <TargetDeviceFamily Name="Windows.Universal">
//     present -> "confirmed".
//   - xmlns:uap* declared without Windows.Universal target -> "high".
//   - foundation-only manifest (no uap*) -> empty (insufficient signal).
func DetectFromManifestBytes(data []byte) (out []winui.FrameworkInfo, err error) {
	defer func() {
		// Defensive guard: encoding/xml returns errors, but a panic in any
		// transitive code path must not propagate (V5 ASVS).
		if rec := recover(); rec != nil {
			err = fmt.Errorf("parse appx manifest: panic recovered: %v", rec)
			out = nil
		}
	}()

	if len(data) == 0 {
		return nil, errors.New("empty manifest data")
	}

	// First pass: scan the root <Package ...> element for namespace
	// attributes. encoding/xml exposes raw attribute names so we can detect
	// xmlns:uap, xmlns:uap2, ..., xmlns:uap15 without enumerating them.
	hasUAP := false
	hasWindowsUniversal := false

	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// Stdlib disables external DTD processing by default; the explicit
	// nil charset reader below ensures non-UTF-8 declarations don't widen
	// the attack surface.
	dec.Strict = false
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		// Accept UTF-8 / US-ASCII; reject anything that would require
		// loading a third-party charset table.
		switch strings.ToLower(charset) {
		case "", "utf-8", "us-ascii", "ascii":
			return input, nil
		}
		return nil, fmt.Errorf("unsupported charset %q", charset)
	}

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return nil, fmt.Errorf("parse appx manifest: %w", terr)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "Package":
			for _, a := range se.Attr {
				// xmlns:uap, xmlns:uap2, ... live in attr.Name with
				// Space="xmlns" and Local="uap" / "uap2" / ...
				if a.Name.Space == "xmlns" && strings.HasPrefix(a.Name.Local, "uap") {
					hasUAP = true
				}
				// Some streams expose the prefix flattened into Local.
				if a.Name.Space == "" && strings.HasPrefix(a.Name.Local, "xmlns:uap") {
					hasUAP = true
				}
			}
		case "TargetDeviceFamily":
			for _, a := range se.Attr {
				if a.Name.Local == "Name" && a.Value == "Windows.Universal" {
					hasWindowsUniversal = true
				}
			}
		}
	}

	if !hasUAP {
		// Foundation-only manifest — not a strong UWP claim.
		return nil, nil
	}

	conf := "high"
	evidence := []string{"xmlns:uap"}
	if hasWindowsUniversal {
		conf = "confirmed"
		evidence = append(evidence, "TargetDeviceFamily Windows.Universal")
	}

	return []winui.FrameworkInfo{{
		Name:       "UWP",
		Confidence: conf,
		Evidence:   evidence,
		Source:     "appx-manifest",
	}}, nil
}
