/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// Extract discovers and collects all CSS sources from the given path.
// It routes to ASAR, directory, or Tauri extraction based on file type detection.
func Extract(path string, opts Options) (*Result, error) {
	result := &Result{
		ImportGraph: make(map[string][]string),
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	var sheets []Stylesheet
	var htmlFiles []string

	if info.IsDir() {
		// Detect directory type
		dr, detectErr := detect.Detect(path)
		if detectErr == nil && dr != nil {
			switch dr.FileType {
			case detect.TypeTauriApp:
				sheets, htmlFiles, err = extractFromTauri(path, opts)
			case detect.TypeElectronApp:
				sheets, htmlFiles, err = extractFromDir(path, opts)
			default:
				sheets, htmlFiles, err = extractFromDir(path, opts)
			}
		} else {
			sheets, htmlFiles, err = extractFromDir(path, opts)
		}
	} else {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".asar" {
			sheets, htmlFiles, err = extractFromASAR(path, opts)
		} else if ext == ".html" || ext == ".htm" {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("read html %s: %w", path, readErr)
			}
			styles, htmlErr := extractFromHTML(data, path)
			if htmlErr != nil {
				result.Errors = append(result.Errors, htmlErr.Error())
			} else {
				sheets = htmlStylesToStylesheets(styles, path)
				htmlFiles = []string{path}
			}
		} else if cssExtensions[ext] {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, fmt.Errorf("read css %s: %w", path, readErr)
			}
			sheets = []Stylesheet{{
				Path:         path,
				Source:       SourceFile,
				Content:      data,
				OriginalSize: int64(len(data)),
			}}
		} else {
			sheets, htmlFiles, err = extractFromDir(filepath.Dir(path), opts)
		}
	}

	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}

	// Process HTML files for embedded styles
	for _, htmlPath := range htmlFiles {
		data, readErr := os.ReadFile(htmlPath)
		if readErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("read html %s: %v", htmlPath, readErr))
			continue
		}
		styles, htmlErr := extractFromHTML(data, htmlPath)
		if htmlErr != nil {
			result.Errors = append(result.Errors, htmlErr.Error())
			continue
		}
		htmlSheets := htmlStylesToStylesheets(styles, htmlPath)
		sheets = append(sheets, htmlSheets...)
	}

	// Resolve @imports if requested
	if opts.ResolveImports {
		basePath := path
		if !info.IsDir() {
			basePath = filepath.Dir(path)
		}
		resolver := NewImportResolver(basePath, opts.NodeModulesPath)
		for i := range sheets {
			if sheets[i].Source == SourceFile && len(sheets[i].Content) > 0 {
				resolved, resolveErr := resolveSheetImports(&sheets[i], resolver, basePath)
				if resolveErr != nil {
					result.Errors = append(result.Errors, resolveErr.Error())
				} else if resolved != nil {
					sheets[i].Content = resolved
					result.Stats.ImportsResolved++
				}
			}
		}
		result.ImportGraph = resolver.Graph()
	}

	result.Stylesheets = sheets

	// Compute stats
	result.Stats.CSSFiles = len(sheets)
	result.Stats.HTMLFiles = len(htmlFiles)
	result.Stats.TotalFiles = result.Stats.CSSFiles + result.Stats.HTMLFiles
	result.OutputDir = opts.OutputDir

	return result, nil
}

// resolveSheetImports resolves @import statements in a stylesheet.
func resolveSheetImports(sheet *Stylesheet, resolver *ImportResolver, basePath string) ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "unravel-css-resolve-*.css")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write(sheet.Content); err != nil {
		return nil, err
	}
	_ = tmpFile.Close()

	// Only resolve if there are @import statements
	if !importPattern.Match(sheet.Content) {
		return nil, nil
	}

	resolved, err := resolver.Resolve(tmpFile.Name())
	if err != nil {
		return nil, fmt.Errorf("resolve imports for %s: %w", sheet.Path, err)
	}
	return resolved, nil
}
