package sourcemap

import (
	"os"
	"path/filepath"
	"strings"
)

// ScanResult holds the results of scanning a directory for source maps.
type ScanResult struct {
	Directory    string         `json:"directory"`
	Maps         []MapInfo      `json:"maps"`
	TotalMaps    int            `json:"total_maps"`
	TotalSources int            `json:"total_sources"`
	Bundlers     map[string]int `json:"bundlers"`
}

// MapInfo holds metadata about a single discovered source map file.
type MapInfo struct {
	Path        string      `json:"path"`
	Size        int64       `json:"size"`
	SourceCount int         `json:"source_count"`
	Bundler     BundlerType `json:"bundler,omitempty"`
}

// ScanDir finds all .map files in a directory tree and returns metadata.
func ScanDir(dir string) (*ScanResult, error) {
	result := &ScanResult{
		Directory: dir,
		Bundlers:  make(map[string]int),
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible entries
		}

		if info.IsDir() {
			// Skip common large directories that won't contain useful source maps
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(strings.ToLower(info.Name()), ".map") {
			return nil
		}

		mapInfo := MapInfo{
			Path: path,
			Size: info.Size(),
		}

		// Parse the source map for metadata
		parsed, parseErr := Parse(path)
		if parseErr == nil {
			mapInfo.SourceCount = parsed.SourceCount
			result.TotalSources += parsed.SourceCount
		}

		// Detect bundler from the source map
		sm, readErr := readSourceMap(path)
		if readErr == nil {
			bundlerResult := DetectBundlerFromMap(sm)
			mapInfo.Bundler = bundlerResult.Bundler
			if bundlerResult.Bundler != BundlerUnknown {
				result.Bundlers[string(bundlerResult.Bundler)]++
			}
		}

		result.Maps = append(result.Maps, mapInfo)
		return nil
	})

	if err != nil {
		return nil, err
	}

	result.TotalMaps = len(result.Maps)
	return result, nil
}
