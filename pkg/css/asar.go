/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/asar"
)

// cssExtensions are file extensions treated as stylesheets.
var cssExtensions = map[string]bool{
	".css":  true,
	".scss": true,
	".less": true,
	".sass": true,
	".styl": true,
}

// webExtensions includes all web-relevant extensions for discovery.
var webExtensions = map[string]bool{
	".css":  true,
	".scss": true,
	".less": true,
	".sass": true,
	".styl": true,
	".html": true,
	".htm":  true,
	".js":   true,
	".jsx":  true,
	".ts":   true,
	".tsx":  true,
}

// extractFromASAR extracts CSS and related files from an ASAR archive.
// If the path is a directory (already extracted), it falls back to directory scanning.
func extractFromASAR(asarPath string, opts Options) ([]Stylesheet, []string, error) {
	info, err := os.Stat(asarPath)
	if err != nil {
		return nil, nil, err
	}

	// If already a directory, fall back to dir scanning
	if info.IsDir() {
		return extractFromDir(asarPath, opts)
	}

	// Parse ASAR header to list entries
	file, header, _, dataOffset, err := asar.OpenAndParse(asarPath)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = file.Close() }()

	// Extract to temp dir
	tmpDir, err := os.MkdirTemp("", "unravel-css-asar-*")
	if err != nil {
		return nil, nil, err
	}

	report := asar.Extract(file, header, dataOffset, tmpDir, asarPath, opts.Verbose)
	if report.Files == 0 {
		return nil, nil, nil
	}

	// Scan extracted directory for CSS and HTML files
	return extractFromDir(tmpDir, opts)
}

// extractFromDir recursively discovers CSS and HTML files in a directory.
func extractFromDir(dir string, opts Options) ([]Stylesheet, []string, error) {
	var sheets []Stylesheet
	var htmlFiles []string

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip errors, non-fatal
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))

		if cssExtensions[ext] {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil // skip unreadable files
			}
			relPath, _ := filepath.Rel(dir, path)
			sheets = append(sheets, Stylesheet{
				Path:         relPath,
				Source:       SourceFile,
				Content:      content,
				OriginalSize: int64(len(content)),
			})
		}

		if ext == ".html" || ext == ".htm" {
			htmlFiles = append(htmlFiles, path)
		}

		return nil
	})
	if err != nil {
		return sheets, htmlFiles, err
	}

	return sheets, htmlFiles, nil
}
