/*
Copyright (c) 2026 Security Research
*/

package pri

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// PRIResource is a single decoded resource entry from a PRI file.
type PRIResource struct {
	Name       string            `json:"name"`
	Qualifiers map[string]string `json:"qualifiers,omitempty"`
	Value      string            `json:"value,omitempty"`
	Section    string            `json:"section"`
}

// PRIResult is the top-level read-only parse result.
type PRIResult struct {
	Magic       string        `json:"magic"`
	Version     uint32        `json:"version"`
	Sections    []SectionRef  `json:"sections,omitempty"`
	Resources   []PRIResource `json:"resources,omitempty"`
	Warnings    []string      `json:"warnings,omitempty"`
	SourceBytes int64         `json:"source_bytes"`
}

// Parse reads a resources.pri file from disk. Path-traversal segments
// are rejected before any I/O.
func Parse(path string) (*PRIResult, error) {
	if path == "" {
		return nil, fmt.Errorf("pri path empty")
	}
	if containsTraversal(path) {
		return nil, fmt.Errorf("pri path rejected: %s", path)
	}
	cleaned := filepath.Clean(path)
	if containsTraversal(cleaned) {
		return nil, fmt.Errorf("pri path rejected: %s", path)
	}
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve pri path: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat pri: %w", err)
	}
	if st.Size() > MaxFileSize {
		return nil, fmt.Errorf("pri size exceeds limit: %d > %d", st.Size(), MaxFileSize)
	}
	data, err := os.ReadFile(abs) //nolint:gosec // path sanitized above
	if err != nil {
		return nil, fmt.Errorf("read pri: %w", err)
	}
	return ParseBytes(data)
}

// ParseBytes decodes a PRI byte slice. The top-level defer/recover
// converts any missed panic into a wrapped error (T-04-04 mitigation).
func ParseBytes(data []byte) (out *PRIResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("pri parse panic: %v", r)
			out = nil
		}
	}()

	if int64(len(data)) > MaxFileSize {
		return nil, fmt.Errorf("pri size exceeds limit: %d > %d", len(data), MaxFileSize)
	}

	hdr, err := ParseHeader(data)
	if err != nil {
		return nil, err
	}

	res := &PRIResult{
		Magic:       hdr.Magic,
		Version:     hdr.Version,
		Warnings:    append([]string{}, hdr.Warnings...),
		SourceBytes: int64(len(data)),
	}

	sections, err := ParseSections(data, hdr)
	if err != nil {
		return nil, err
	}
	res.Sections = sections

	// Walk each section. Recognised section name patterns:
	//   "[mrm_hsdt]" — string pool (HSDT)
	//   "[mrm_hsch]" — schema (resource names; same string-pool layout in fixture)
	//   "[mrm_cdef]" — candidate definitions (skipped — exotic; recorded as warning)
	//   "[mrm_hmap]" — map (skipped)
	for _, s := range sections {
		if uint64(s.Offset)+uint64(s.Size) > uint64(len(data)) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("section %q out of bounds — skipped", s.Name))
			continue
		}
		payload := data[s.Offset : s.Offset+s.Size]
		switch normaliseSectionName(s.Name) {
		case "[mrm_hsdt]", "hsdt":
			pool, perr := ParseStrings(payload)
			if perr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("section %q: %v", s.Name, perr))
				continue
			}
			for i, v := range pool {
				if len(res.Resources) >= MaxResources {
					res.Warnings = append(res.Warnings, fmt.Sprintf("resource cap %d hit — remaining entries dropped", MaxResources))
					break
				}
				res.Resources = append(res.Resources, PRIResource{
					Name:    fmt.Sprintf("hsdt_%d", i),
					Value:   v,
					Section: "HSDT",
				})
			}
		case "[mrm_hsch]", "hsch":
			pool, perr := ParseStrings(payload)
			if perr != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("section %q: %v", s.Name, perr))
				continue
			}
			// Use HSCH as resource names; pair with existing HSDT entries.
			for i, name := range pool {
				if i < len(res.Resources) {
					res.Resources[i].Name = name
				} else {
					if len(res.Resources) >= MaxResources {
						res.Warnings = append(res.Warnings, fmt.Sprintf("resource cap %d hit — remaining entries dropped", MaxResources))
						break
					}
					res.Resources = append(res.Resources, PRIResource{
						Name:    name,
						Section: "HSCH",
					})
				}
			}
		case "[mrm_cdef]", "cdef":
			res.Warnings = append(res.Warnings, fmt.Sprintf("section %q: candidate-definitions skipped (exotic, v1)", s.Name))
		case "[mrm_hmap]", "hmap":
			res.Warnings = append(res.Warnings, fmt.Sprintf("section %q: map skipped (exotic, v1)", s.Name))
		default:
			// Unknown but recognised by name: record a blob reference if
			// the payload exceeds the inline cap, otherwise skip silently.
			if int(s.Size) > MaxBlobInline {
				res.Resources = append(res.Resources, PRIResource{
					Name:    s.Name,
					Value:   fmt.Sprintf("blob:%d:%d", s.Offset, s.Size),
					Section: s.Name,
				})
			}
		}
	}

	return res, nil
}

// normaliseSectionName lowercases and trims a section name for switch
// matching. Real PRIs sometimes pad the 16-byte slot with nulls or
// spaces, sometimes omit the brackets — we accept both forms.
func normaliseSectionName(s string) string {
	out := strings.ToLower(strings.TrimSpace(s))
	return out
}

// containsTraversal reports whether p has any `..` path segment.
func containsTraversal(p string) bool {
	parts := strings.FieldsFunc(p, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	return slices.Contains(parts, "..")
}
