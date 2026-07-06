package reconstruct

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// supportedExtensions lists file extensions eligible for reconstruction.
var supportedExtensions = map[string]bool{
	".java": true,
	".js":   true,
	".ts":   true,
	".cs":   true,
	".go":   true,
	".py":   true,
}

// RunBatch walks a directory recursively, running the reconstruction pipeline
// on each supported source file. The progress callback is called for each file
// with format: [current/total] path ... status.
func RunBatch(dir string, opts Options, progress func(current, total int, path, status string)) ([]*Result, error) {
	// Collect eligible files.
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if supportedExtensions[ext] {
			files = append(files, path)
			return nil
		}

		// For extensionless files, try content-based detection.
		if ext == "" {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			lang := DetectLanguage(string(data), "")
			if lang != LangUnknown {
				files = append(files, path)
			}
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reconstruct batch: walk %s: %w", dir, err)
	}

	if len(files) == 0 {
		return nil, nil
	}

	total := len(files)
	var results []*Result

	for i, path := range files {
		relPath, _ := filepath.Rel(dir, path)
		if relPath == "" {
			relPath = path
		}

		result, runErr := Run(path, opts)
		if runErr != nil {
			result = &Result{
				Stage:  "failed",
				Errors: []string{runErr.Error()},
			}
		}

		chunkInfo := ""
		if result != nil && len(result.Chunks) > 0 {
			chunkInfo = fmt.Sprintf(" (%d chunks)", len(result.Chunks))
		}

		status := result.Stage + chunkInfo
		if progress != nil {
			progress(i+1, total, relPath, status)
		}

		results = append(results, result)
	}

	return results, nil
}
