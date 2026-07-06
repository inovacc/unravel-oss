package sourcemap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// SourceMap represents a parsed JavaScript source map (v3).
type SourceMap struct {
	Version        int      `json:"version"`
	File           string   `json:"file,omitempty"`
	SourceRoot     string   `json:"sourceRoot,omitempty"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
	Names          []string `json:"names,omitempty"`
	Mappings       string   `json:"mappings"`
}

// ParseResult holds parsed metadata from a source map.
type ParseResult struct {
	Version          int           `json:"version"`
	File             string        `json:"file,omitempty"`
	SourceRoot       string        `json:"source_root,omitempty"`
	SourceCount      int           `json:"source_count"`
	NameCount        int           `json:"name_count"`
	HasInlineContent bool          `json:"has_inline_content"`
	Sources          []SourceEntry `json:"sources"`
	MappingSegments  int           `json:"mapping_segments"`
}

// SourceEntry describes one source file referenced by the map.
type SourceEntry struct {
	Path       string `json:"path"`
	HasContent bool   `json:"has_content"`
	Size       int    `json:"size,omitempty"`
}

// ExtractResult reports the outcome of ExtractSources.
type ExtractResult struct {
	SourceMap    string `json:"source_map"`
	OutputDir    string `json:"output_dir"`
	Extracted    int    `json:"extracted"`
	Skipped      int    `json:"skipped"`
	TotalSources int    `json:"total_sources"`
}

// readSourceMap reads and decodes a .map file from disk.
func readSourceMap(path string) (*SourceMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source map: %w", err)
	}

	var sm SourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, fmt.Errorf("parse source map JSON: %w", err)
	}

	if sm.Version != 3 {
		return nil, fmt.Errorf("unsupported source map version: %d (expected 3)", sm.Version)
	}

	return &sm, nil
}

// countMappingSegments counts the number of VLQ segments in a mappings string.
// Each segment is separated by ',' within a line, and lines are separated by ';'.
// An empty mappings string has 0 segments.
func countMappingSegments(mappings string) int {
	if len(mappings) == 0 {
		return 0
	}

	count := 0
	inSegment := false

	for _, ch := range mappings {
		switch ch {
		case ';', ',':
			if inSegment {
				count++
				inSegment = false
			}
		default:
			inSegment = true
		}
	}

	// count the last segment if it didn't end with a separator
	if inSegment {
		count++
	}

	return count
}

// Parse reads a .map file and returns parsed metadata.
func Parse(path string) (*ParseResult, error) {
	sm, err := readSourceMap(path)
	if err != nil {
		return nil, err
	}

	result := &ParseResult{
		Version:          sm.Version,
		File:             sm.File,
		SourceRoot:       sm.SourceRoot,
		SourceCount:      len(sm.Sources),
		NameCount:        len(sm.Names),
		HasInlineContent: len(sm.SourcesContent) > 0,
		MappingSegments:  countMappingSegments(sm.Mappings),
	}

	result.Sources = make([]SourceEntry, len(sm.Sources))
	for i, src := range sm.Sources {
		entry := SourceEntry{
			Path: src,
		}
		if i < len(sm.SourcesContent) && sm.SourcesContent[i] != "" {
			entry.HasContent = true
			entry.Size = len(sm.SourcesContent[i])
		}
		result.Sources[i] = entry
	}

	return result, nil
}

// sanitizePath cleans a source path for safe extraction to the filesystem.
// It handles file:// URLs, removes leading slashes and path traversal components.
func sanitizePath(source string) string {
	// Handle file:// URLs
	if strings.HasPrefix(source, "file://") {
		if u, err := url.Parse(source); err == nil {
			source = u.Path
		}
	}

	// Handle webpack-style paths like webpack:///src/foo.js
	for _, prefix := range []string{
		"webpack:///", "webpack://", "webpack:/",
		"/@fs/", "/@vite/",
	} {
		if after, ok := strings.CutPrefix(source, prefix); ok {
			source = after
			break
		}
	}

	// Remove leading slashes
	source = strings.TrimLeft(source, "/")

	// Replace backslashes with forward slashes
	source = strings.ReplaceAll(source, "\\", "/")

	// Remove path traversal components
	parts := strings.Split(source, "/")
	var clean []string
	for _, p := range parts {
		if p == ".." || p == "." || p == "" {
			continue
		}
		clean = append(clean, p)
	}

	if len(clean) == 0 {
		return "unknown_source"
	}

	return filepath.Join(clean...)
}

// ExtractSources extracts original source files from a source map to outputDir.
// Only extracts sources that have inline content (sourcesContent).
func ExtractSources(path string, outputDir string) (*ExtractResult, error) {
	sm, err := readSourceMap(path)
	if err != nil {
		return nil, err
	}

	result := &ExtractResult{
		SourceMap:    path,
		OutputDir:    outputDir,
		TotalSources: len(sm.Sources),
	}

	for i, src := range sm.Sources {
		// Check if inline content is available
		if i >= len(sm.SourcesContent) || sm.SourcesContent[i] == "" {
			result.Skipped++
			continue
		}

		safePath := sanitizePath(src)
		outPath := filepath.Join(outputDir, safePath)

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return nil, fmt.Errorf("create directory for %s: %w", safePath, err)
		}

		// Write source content
		if err := os.WriteFile(outPath, []byte(sm.SourcesContent[i]), 0o644); err != nil {
			return nil, fmt.Errorf("write source %s: %w", safePath, err)
		}

		result.Extracted++
	}

	return result, nil
}
