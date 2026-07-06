/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// importPattern matches CSS @import statements.
var importPattern = regexp.MustCompile(`@import\s+(?:url\(\s*['"]?([^'")]+)['"]?\s*\)|['"]([^'"]+)['"]);?`)

// ImportResolver resolves @import chains with cycle detection.
type ImportResolver struct {
	basePath        string
	nodeModulesPath string
	visited         map[string]bool
	graph           map[string][]string
}

// NewImportResolver creates a new resolver.
func NewImportResolver(basePath, nodeModules string) *ImportResolver {
	return &ImportResolver{
		basePath:        basePath,
		nodeModulesPath: nodeModules,
		visited:         make(map[string]bool),
		graph:           make(map[string][]string),
	}
}

// Resolve reads cssPath, inlines all @import statements recursively, and returns
// the fully resolved CSS content. It detects cycles and returns an error if found.
func (r *ImportResolver) Resolve(cssPath string) ([]byte, error) {
	absPath, err := filepath.Abs(cssPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path %s: %w", cssPath, err)
	}

	if r.visited[absPath] {
		return nil, fmt.Errorf("import cycle detected at %s", absPath)
	}
	r.visited[absPath] = true

	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", absPath, err)
	}

	dir := filepath.Dir(absPath)
	result := importPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		groups := importPattern.FindSubmatch(match)
		var importPath string
		if len(groups) > 1 && len(groups[1]) > 0 {
			importPath = string(groups[1]) // url() form
		} else if len(groups) > 2 && len(groups[2]) > 0 {
			importPath = string(groups[2]) // quoted form
		}

		if importPath == "" {
			return match
		}

		// Skip remote URL imports -- preserve them as-is
		if isRemoteURL(importPath) {
			return match
		}

		resolved := r.resolveImportPath(importPath, dir)
		if resolved == "" {
			return match // cannot resolve, keep original
		}

		absResolved, _ := filepath.Abs(resolved)
		// Track in graph
		if r.graph[absPath] == nil {
			r.graph[absPath] = []string{}
		}
		r.graph[absPath] = append(r.graph[absPath], absResolved)

		content, resolveErr := r.Resolve(resolved)
		if resolveErr != nil {
			// Propagate cycle errors
			if strings.Contains(resolveErr.Error(), "import cycle") {
				err = resolveErr
			}
			return match
		}

		return append(content, '\n')
	})

	if err != nil {
		return nil, err
	}

	return result, nil
}

// Graph returns the import dependency graph.
func (r *ImportResolver) Graph() map[string][]string {
	return r.graph
}

// resolveImportPath tries to find the actual file for an import reference.
// Priority: exact -> +.css -> /index.css -> node_modules lookup
func (r *ImportResolver) resolveImportPath(importPath, fromDir string) string {
	// 1. Relative path resolution
	if strings.HasPrefix(importPath, ".") || strings.HasPrefix(importPath, "/") {
		candidate := filepath.Join(fromDir, importPath)
		if found := r.tryResolve(candidate); found != "" {
			return found
		}
		return ""
	}

	// 2. Node modules lookup
	if r.nodeModulesPath != "" {
		candidate := filepath.Join(r.nodeModulesPath, importPath)
		if found := r.tryResolve(candidate); found != "" {
			return found
		}
		// Try as directory with index.css
		indexPath := filepath.Join(r.nodeModulesPath, importPath, "index.css")
		if fileExists(indexPath) {
			return indexPath
		}
	}

	// 3. Try from base path
	candidate := filepath.Join(fromDir, importPath)
	return r.tryResolve(candidate)
}

// tryResolve attempts exact path, then +.css extension.
func (r *ImportResolver) tryResolve(candidate string) string {
	// Exact match
	if fileExists(candidate) {
		return candidate
	}
	// Add .css extension
	withExt := candidate + ".css"
	if fileExists(withExt) {
		return withExt
	}
	// Try index.css in directory
	indexPath := filepath.Join(candidate, "index.css")
	if fileExists(indexPath) {
		return indexPath
	}
	return ""
}

func isRemoteURL(path string) bool {
	u, err := url.Parse(path)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
