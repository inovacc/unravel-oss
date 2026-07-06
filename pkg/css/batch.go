/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// BatchExtract processes multiple paths sequentially, collecting results.
// Individual failures are non-fatal: the error is recorded in the result
// and processing continues with the next path.
func BatchExtract(paths []string, opts Options) ([]*Result, error) {
	if len(paths) == 0 {
		return nil, nil
	}

	results := make([]*Result, 0, len(paths))

	for _, p := range paths {
		pathOpts := opts
		if opts.OutputDir != "" {
			// Create a subdirectory per input path to avoid collisions.
			base := sanitizeDirName(filepath.Base(p))
			pathOpts.OutputDir = filepath.Join(opts.OutputDir, base)
		}

		result, err := Extract(p, pathOpts)
		if err != nil {
			// Non-fatal: record error and continue.
			result = &Result{
				Errors:    []string{fmt.Sprintf("extract %s: %v", p, err)},
				OutputDir: pathOpts.OutputDir,
			}
		}

		results = append(results, result)
	}

	return results, nil
}

// Manifest is the JSON structure written to manifest.json in the output directory.
type Manifest struct {
	Components  []Component         `json:"components"`
	ImportGraph map[string][]string `json:"import_graph"`
	Stats       ExtractionStats     `json:"stats"`
	Errors      []string            `json:"errors,omitempty"`
}

// WriteManifest writes a manifest.json summarizing the extraction result.
func WriteManifest(result *Result, outputDir string) error {
	if result == nil {
		return fmt.Errorf("nil result")
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	m := Manifest{
		Components:  result.Components,
		ImportGraph: result.ImportGraph,
		Stats:       result.Stats,
		Errors:      result.Errors,
	}

	if m.Components == nil {
		m.Components = []Component{}
	}
	if m.ImportGraph == nil {
		m.ImportGraph = make(map[string][]string)
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}

	path := filepath.Join(outputDir, "manifest.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	return nil
}

// sanitizeDirName replaces characters unsafe for directory names.
func sanitizeDirName(name string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"\\", "_",
		"/", "_",
		"?", "_",
		"*", "_",
		"<", "_",
		">", "_",
		"|", "_",
		"\"", "_",
	)
	return replacer.Replace(name)
}
