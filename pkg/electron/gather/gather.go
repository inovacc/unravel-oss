/*
Copyright (c) 2026 Security Research
*/
package gather

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

// ErrNoGatherer is returned by GatherE when the current platform has no
// registered gatherer (no usable search paths) or when the manifest is nil.
// Callers that want to distinguish "platform unsupported" from "platform
// supported, no apps found" can check via errors.Is(err, ErrNoGatherer).
var ErrNoGatherer = errors.New("electron/gather: no gatherer registered for platform")

// AppEntry represents a discovered Electron/Tauri application.
type AppEntry struct {
	Path            string   `json:"path"`
	Type            string   `json:"type"`
	DisplayName     string   `json:"display_name"`
	Version         string   `json:"version,omitempty"`
	Score           int      `json:"score"`
	ElectronVersion string   `json:"electron_version,omitempty"`
	ChromiumVersion string   `json:"chromium_version,omitempty"`
	NodeVersion     string   `json:"node_version,omitempty"`
	TauriVersion    string   `json:"tauri_version,omitempty"`
	Frameworks      []string `json:"frameworks,omitempty"`
}

// skipDirs are directory names to skip during scanning.
var skipDirs = map[string]bool{
	"node_modules": true,
	"__pycache__":  true,
	".git":         true,
	".cache":       true,
	".npm":         true,
	"go":           true,
	"Python":       true,
	"perl":         true,
	"ruby":         true,
	"R":            true,
	"texlive":      true,
}

// Gather scans common system directories and returns all detected
// Electron/Tauri apps. It NEVER returns nil — an empty result is an empty
// (non-nil) slice. Errors from the underlying gatherE helper are intentionally
// swallowed to preserve the public signature; callers wanting typed errors
// should use GatherE.
func Gather(m *manifest.Manifest, verbose bool) []AppEntry {
	entries, _ := gatherE(m, verbose)
	if entries == nil {
		entries = []AppEntry{}
	}
	return entries
}

// GatherE is the typed-error variant of Gather. It returns ErrNoGatherer
// (wrappable via errors.Is) when the current platform has no registered
// search paths or when the manifest is nil. The result slice is always
// non-nil.
func GatherE(m *manifest.Manifest, verbose bool) ([]AppEntry, error) {
	entries, err := gatherE(m, verbose)
	if entries == nil {
		entries = []AppEntry{}
	}
	return entries, err
}

// gatherE is the internal implementation. It performs the registry-permutation
// defensive guard at the API entry (D-01) and returns ErrNoGatherer when no
// gatherer is registered for the current platform (D-03..D-05).
func gatherE(m *manifest.Manifest, verbose bool) ([]AppEntry, error) {
	if m == nil {
		return []AppEntry{}, ErrNoGatherer
	}

	roots := searchPaths()
	if len(roots) == 0 {
		return []AppEntry{}, ErrNoGatherer
	}

	detector := manifest.NewDetector(m, false)

	seen := make(map[string]bool)
	entries := make([]AppEntry, 0)

	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}

		if verbose {
			fmt.Printf("[GATHER] Scanning %s\n", root)
		}

		walkDepth(root, 3, func(path string, d fs.DirEntry) error {
			if !d.IsDir() {
				return nil
			}

			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}

			if seen[path] {
				return fs.SkipDir
			}

			result, err := detector.Detect(path)
			if err != nil || result.Type == "unknown" {
				return nil
			}

			if result.Score < 50 {
				return nil
			}

			seen[path] = true
			entry := AppEntry{
				Path:        path,
				Type:        result.Type,
				DisplayName: result.DisplayName,
				Version:     result.Version,
				Score:       result.Score,
			}
			enrichEntry(&entry)
			entries = append(entries, entry)

			if verbose {
				fmt.Printf("[GATHER] Found: %s (%s v%s, score=%d)\n", path, result.DisplayName, result.Version, result.Score)
			}

			return fs.SkipDir
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Path < entries[j].Path
	})

	return entries, nil
}

func walkDepth(root string, maxDepth int, fn func(path string, d fs.DirEntry) error) {
	walkRecursive(root, 0, maxDepth, fn)
}

func walkRecursive(dir string, depth, maxDepth int, fn func(path string, d fs.DirEntry) error) {
	if depth > maxDepth {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		path := filepath.Join(dir, e.Name())

		err := fn(path, e)
		if err == fs.SkipDir {
			continue
		}
		if err != nil {
			continue
		}

		if e.IsDir() {
			walkRecursive(path, depth+1, maxDepth, fn)
		}
	}
}
