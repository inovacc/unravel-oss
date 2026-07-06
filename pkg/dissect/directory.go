/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/detect"
	"github.com/inovacc/unravel-oss/pkg/dotnet"
	"github.com/inovacc/unravel-oss/pkg/winsvc"
)

// DirectoryResult holds results from analyzing an entire directory.
type DirectoryResult struct {
	Path          string            `json:"path"`
	TotalFiles    int               `json:"total_files"`
	AnalyzedFiles int               `json:"analyzed_files"`
	SkippedFiles  int               `json:"skipped_files"`
	Duration      time.Duration     `json:"duration"`
	FileResults   []FileResult      `json:"file_results"`
	Summary       *DirectorySummary `json:"summary"`
	Errors        []string          `json:"errors,omitempty"`
}

// FileResult holds the analysis result for a single file in the directory.
type FileResult struct {
	Path     string              `json:"path"`
	RelPath  string              `json:"rel_path"`
	Size     int64               `json:"size"`
	Type     detect.FileType     `json:"type"`
	Category detect.FileCategory `json:"category"`
	Dissect  *DissectResult      `json:"dissect,omitempty"`
	Error    string              `json:"error,omitempty"`
}

// DirectorySummary provides aggregate statistics.
type DirectorySummary struct {
	TypeCounts     map[string]int       `json:"type_counts"`
	CategoryCounts map[string]int       `json:"category_counts"`
	TotalSize      int64                `json:"total_size"`
	Executables    []string             `json:"executables,omitempty"`
	Libraries      []string             `json:"libraries,omitempty"`
	Configs        []string             `json:"configs,omitempty"`
	IsDotNet       bool                 `json:"is_dotnet,omitempty"`
	IsElectron     bool                 `json:"is_electron,omitempty"`
	Services       []winsvc.ServiceInfo `json:"services,omitempty"`
	Drivers        []winsvc.DriverInfo  `json:"drivers,omitempty"`
}

// maxFileSize is the upper limit for files to analyze (500 MB).
const maxFileSize int64 = 500 * 1024 * 1024

// maxDepth limits directory traversal to top-level + 1 depth.
const maxDepth = 2

// skipDirNames contains directory names to skip during traversal.
var skipDirNames = map[string]bool{
	"node_modules": true,
	".git":         true,
	"__pycache__":  true,
	".idea":        true,
	".vscode":      true,
	".svn":         true,
	".hg":          true,
	"vendor":       true,
	".gradle":      true,
	"build":        true,
	"dist":         true,
}

// RunDirectory analyzes all files in a directory, discovering and dissecting
// each recognized file type. It limits traversal to maxDepth levels and skips
// files larger than maxFileSize.
func RunDirectory(dirPath string, opts Options) (*DirectoryResult, error) {
	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", absPath)
	}

	start := time.Now()

	result := &DirectoryResult{
		Path:        absPath,
		FileResults: []FileResult{},
		Errors:      []string{},
		Summary: &DirectorySummary{
			TypeCounts:     make(map[string]int),
			CategoryCounts: make(map[string]int),
		},
	}

	// Check for framework markers before scanning files.
	result.Summary.IsDotNet = dotnet.IsDotNetApp(absPath)
	result.Summary.IsElectron = isElectronDir(absPath)

	// Walk directory with depth limit.
	_ = filepath.WalkDir(absPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, walkErr))
			return nil
		}

		// Calculate depth relative to root.
		rel, _ := filepath.Rel(absPath, path)
		depth := 0
		if rel != "." {
			depth = strings.Count(filepath.ToSlash(rel), "/") + 1
		}

		if d.IsDir() {
			if path != absPath && skipDirNames[d.Name()] {
				return filepath.SkipDir
			}
			if depth >= maxDepth {
				return filepath.SkipDir
			}
			return nil
		}

		result.TotalFiles++

		// Get file info for size check.
		fInfo, statErr := d.Info()
		if statErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: stat: %v", path, statErr))
			return nil
		}

		if fInfo.Size() > maxFileSize {
			result.SkippedFiles++
			return nil
		}

		result.Summary.TotalSize += fInfo.Size()

		// Detect file type.
		dr, detectErr := detect.Detect(path)
		if detectErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: detect: %v", path, detectErr))
			return nil
		}

		// Track the file in type/category counts regardless of dissect.
		if dr.FileType != detect.TypeUnknown {
			result.Summary.TypeCounts[string(dr.FileType)]++
			result.Summary.CategoryCounts[string(dr.Category)]++
		}

		// Classify into summary lists.
		classifyFile(result.Summary, dr, rel)

		// Skip unknown types — nothing to dissect.
		if dr.FileType == detect.TypeUnknown {
			result.SkippedFiles++
			return nil
		}

		// Run dissect on the file.
		fr := FileResult{
			Path:     path,
			RelPath:  rel,
			Size:     fInfo.Size(),
			Type:     dr.FileType,
			Category: dr.Category,
		}

		dissectResult, dissectErr := Run(path, opts)
		if dissectErr != nil {
			fr.Error = dissectErr.Error()
			result.Errors = append(result.Errors, fmt.Sprintf("[dissect] %s: %v", rel, dissectErr))
		} else {
			fr.Dissect = dissectResult
		}

		result.FileResults = append(result.FileResults, fr)
		result.AnalyzedFiles++

		return nil
	})

	// Scan for Windows services whose binaries reside in the directory.
	if svcResult, svcErr := winsvc.ScanForServices(absPath); svcErr == nil && len(svcResult.Services) > 0 {
		result.Summary.Services = svcResult.Services
	}

	// Analyze any .sys driver files found during the walk.
	if drivers, drvErr := winsvc.FindDrivers(absPath); drvErr == nil && len(drivers) > 0 {
		result.Summary.Drivers = drivers
	}

	result.Duration = time.Since(start)

	return result, nil
}

// isElectronDir checks for Electron app markers in a directory.
func isElectronDir(dir string) bool {
	markers := []string{
		filepath.Join("resources", "app.asar"),
		filepath.Join("resources", "app"),
		"electron.exe",
	}

	for _, marker := range markers {
		if _, err := os.Stat(filepath.Join(dir, marker)); err == nil {
			return true
		}
	}

	// Check for package.json with electron dependency.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}

	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if name == "electron" || name == "electron.exe" || name == "electron.app" {
			return true
		}
	}

	return false
}

// classifyFile adds the file to the appropriate summary list based on its type.
func classifyFile(summary *DirectorySummary, dr *detect.DetectResult, relPath string) {
	switch dr.FileType {
	case detect.TypePE, detect.TypeELF, detect.TypeMachO, detect.TypeMachOFat, detect.TypeGoBinary:
		summary.Executables = append(summary.Executables, relPath)
	case detect.TypeJSON, detect.TypeYAML, detect.TypeXML:
		summary.Configs = append(summary.Configs, relPath)
	default:
		// Check extension for libraries.
		ext := strings.ToLower(filepath.Ext(relPath))
		switch ext {
		case ".dll", ".so", ".dylib":
			summary.Libraries = append(summary.Libraries, relPath)
		}
	}
}
