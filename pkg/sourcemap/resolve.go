package sourcemap

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ResolveResult holds the resolved npm dependencies from a bundled JS file.
type ResolveResult struct {
	Dependencies []ResolvedDep `json:"dependencies"`
	TotalModules int           `json:"total_modules"`
	BundlerUsed  BundlerType   `json:"bundler_used"`
}

// ResolvedDep represents a single npm package detected in a bundle.
type ResolvedDep struct {
	PackageName  string   `json:"package_name"`
	Version      string   `json:"version,omitempty"`
	ModulePaths  []string `json:"module_paths"`
	SizeEstimate int64    `json:"size_estimate,omitempty"` // bytes, from sourcesContent
}

// moduleEntry tracks a source file's index and relative path within a package.
type moduleEntry struct {
	index int
	path  string
}

// ResolveDependencies parses a source map and resolves which npm packages
// are bundled by examining the original file paths in the sources array.
// Paths like "node_modules/express/lib/router.js" are mapped to package "express".
// Scoped packages like "@scope/pkg" are handled correctly.
func ResolveDependencies(mapPath string) (*ResolveResult, error) {
	sm, err := readSourceMap(mapPath)
	if err != nil {
		return nil, err
	}

	bundler := DetectBundlerFromMap(sm)

	pkgModules := make(map[string][]moduleEntry)
	totalModules := 0

	for i, src := range sm.Sources {
		cleaned := sanitizePath(src)
		// Normalize separators to forward slashes for matching
		cleaned = filepath.ToSlash(cleaned)

		pkgName, relPath := extractPackageName(cleaned)
		if pkgName == "" {
			continue
		}
		totalModules++
		pkgModules[pkgName] = append(pkgModules[pkgName], moduleEntry{index: i, path: relPath})
	}

	deps := make([]ResolvedDep, 0, len(pkgModules))
	for pkgName, entries := range pkgModules {
		dep := ResolvedDep{
			PackageName: pkgName,
			ModulePaths: make([]string, len(entries)),
		}

		for j, e := range entries {
			dep.ModulePaths[j] = e.path

			// Accumulate size from sourcesContent when available
			if e.index < len(sm.SourcesContent) && sm.SourcesContent[e.index] != "" {
				dep.SizeEstimate += int64(len(sm.SourcesContent[e.index]))
			}
		}

		// Try to detect version from package.json references in the source paths
		dep.Version = detectVersionFromPaths(entries, sm)

		sort.Strings(dep.ModulePaths)
		deps = append(deps, dep)
	}

	// Sort dependencies by name for deterministic output
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].PackageName < deps[j].PackageName
	})

	return &ResolveResult{
		Dependencies: deps,
		TotalModules: totalModules,
		BundlerUsed:  bundler.Bundler,
	}, nil
}

// extractPackageName extracts the npm package name from a source path that
// contains "node_modules". Returns the package name and the relative path
// within that package. Handles scoped packages (@scope/pkg).
//
// Examples:
//
//	"node_modules/express/lib/router.js" -> ("express", "lib/router.js")
//	"node_modules/@babel/core/src/index.js" -> ("@babel/core", "src/index.js")
//	"src/app.js" -> ("", "")
func extractPackageName(path string) (pkgName, relPath string) {
	const nm = "node_modules/"

	idx := strings.LastIndex(path, nm)
	if idx < 0 {
		return "", ""
	}

	after := path[idx+len(nm):]
	if after == "" {
		return "", ""
	}

	// Scoped package: @scope/pkg/...
	if after[0] == '@' {
		parts := strings.SplitN(after, "/", 3)
		if len(parts) < 2 {
			return "", ""
		}
		pkgName = parts[0] + "/" + parts[1]
		if len(parts) == 3 {
			relPath = parts[2]
		}
		return pkgName, relPath
	}

	// Regular package: pkg/...
	parts := strings.SplitN(after, "/", 2)
	pkgName = parts[0]
	if len(parts) == 2 {
		relPath = parts[1]
	}
	return pkgName, relPath
}

// detectVersionFromPaths attempts to infer a package version from
// source content (e.g., a package.json embedded in sourcesContent).
func detectVersionFromPaths(entries []moduleEntry, sm *SourceMap) string {
	for _, e := range entries {
		if !strings.HasSuffix(e.path, "package.json") {
			continue
		}
		if e.index >= len(sm.SourcesContent) {
			continue
		}
		content := sm.SourcesContent[e.index]
		if content == "" {
			continue
		}
		// Quick regex to extract "version": "x.y.z" from JSON content
		re := regexp.MustCompile(`"version"\s*:\s*"([^"]+)"`)
		if m := re.FindStringSubmatch(content); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

// ResolveBundleJS analyzes a bundled JavaScript file (without a source map)
// to identify npm package dependencies by scanning for import/require patterns
// and bundler-specific module comment markers.
func ResolveBundleJS(jsPath string) (*ResolveResult, error) {
	data, err := os.ReadFile(jsPath)
	if err != nil {
		return nil, fmt.Errorf("read bundle: %w", err)
	}

	content := string(data)

	// Detect bundler from the JS content
	bundler := DetectBundler(content)

	pkgSet := make(map[string]struct{})

	// 1. CommonJS require("pkg") patterns
	requireRe := regexp.MustCompile(`\brequire\s*\(\s*["']([^"'./][^"']*)["']\s*\)`)
	for _, m := range requireRe.FindAllStringSubmatch(content, -1) {
		pkg := normalizeImportPath(m[1])
		if pkg != "" {
			pkgSet[pkg] = struct{}{}
		}
	}

	// 2. ESM import ... from "pkg" patterns
	importRe := regexp.MustCompile(`\bfrom\s+["']([^"'./][^"']*)["']`)
	for _, m := range importRe.FindAllStringSubmatch(content, -1) {
		pkg := normalizeImportPath(m[1])
		if pkg != "" {
			pkgSet[pkg] = struct{}{}
		}
	}

	// 3. Dynamic import("pkg") patterns
	dynamicImportRe := regexp.MustCompile(`\bimport\s*\(\s*["']([^"'./][^"']*)["']\s*\)`)
	for _, m := range dynamicImportRe.FindAllStringSubmatch(content, -1) {
		pkg := normalizeImportPath(m[1])
		if pkg != "" {
			pkgSet[pkg] = struct{}{}
		}
	}

	// 4. Webpack module comment markers: /* harmony import */ or /*! module */
	webpackModuleRe := regexp.MustCompile(`/\*!\s*([a-z@][a-z0-9._@/-]*)\s*\*/`)
	for _, m := range webpackModuleRe.FindAllStringSubmatch(content, -1) {
		pkg := normalizeImportPath(m[1])
		if pkg != "" {
			pkgSet[pkg] = struct{}{}
		}
	}

	// 5. Webpack harmony export/import comments referencing modules
	harmonyRe := regexp.MustCompile(`/\*\s*harmony (?:import|export)\s*\*/.*?["']([^"'./][^"']*)["']`)
	for _, m := range harmonyRe.FindAllStringSubmatch(content, -1) {
		pkg := normalizeImportPath(m[1])
		if pkg != "" {
			pkgSet[pkg] = struct{}{}
		}
	}

	// 6. Webpack __webpack_require__ with module IDs mapping to package names
	// Pattern: "node_modules/pkg/..." or similar in webpack module comments
	webpackNMRe := regexp.MustCompile(`["']node_modules/([^"']+)["']`)
	for _, m := range webpackNMRe.FindAllStringSubmatch(content, -1) {
		pkg, _ := extractPackageFromModulePath(m[1])
		if pkg != "" {
			pkgSet[pkg] = struct{}{}
		}
	}

	// Filter out built-in Node.js modules
	for builtin := range nodeBuiltins {
		delete(pkgSet, builtin)
	}

	deps := make([]ResolvedDep, 0, len(pkgSet))
	for pkg := range pkgSet {
		deps = append(deps, ResolvedDep{
			PackageName: pkg,
		})
	}

	sort.Slice(deps, func(i, j int) bool {
		return deps[i].PackageName < deps[j].PackageName
	})

	return &ResolveResult{
		Dependencies: deps,
		TotalModules: len(deps),
		BundlerUsed:  bundler.Bundler,
	}, nil
}

// normalizeImportPath extracts the npm package name from an import specifier.
// "express" -> "express", "express/lib/router" -> "express",
// "@babel/core" -> "@babel/core", "@babel/core/src" -> "@babel/core"
func normalizeImportPath(spec string) string {
	if spec == "" {
		return ""
	}

	// Scoped package
	if spec[0] == '@' {
		parts := strings.SplitN(spec, "/", 3)
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}

	// Regular package: take the first path segment
	parts := strings.SplitN(spec, "/", 2)
	return parts[0]
}

// extractPackageFromModulePath is like extractPackageName but for paths
// that already have node_modules/ stripped.
func extractPackageFromModulePath(path string) (string, string) {
	if path == "" {
		return "", ""
	}

	if path[0] == '@' {
		parts := strings.SplitN(path, "/", 3)
		if len(parts) < 2 {
			return "", ""
		}
		pkg := parts[0] + "/" + parts[1]
		rel := ""
		if len(parts) == 3 {
			rel = parts[2]
		}
		return pkg, rel
	}

	parts := strings.SplitN(path, "/", 2)
	rel := ""
	if len(parts) == 2 {
		rel = parts[1]
	}
	return parts[0], rel
}

// nodeBuiltins lists Node.js built-in module names to filter from results.
var nodeBuiltins = map[string]struct{}{
	"assert":              {},
	"async_hooks":         {},
	"buffer":              {},
	"child_process":       {},
	"cluster":             {},
	"console":             {},
	"constants":           {},
	"crypto":              {},
	"dgram":               {},
	"diagnostics_channel": {},
	"dns":                 {},
	"domain":              {},
	"events":              {},
	"fs":                  {},
	"http":                {},
	"http2":               {},
	"https":               {},
	"inspector":           {},
	"module":              {},
	"net":                 {},
	"os":                  {},
	"path":                {},
	"perf_hooks":          {},
	"process":             {},
	"punycode":            {},
	"querystring":         {},
	"readline":            {},
	"repl":                {},
	"stream":              {},
	"string_decoder":      {},
	"sys":                 {},
	"timers":              {},
	"tls":                 {},
	"trace_events":        {},
	"tty":                 {},
	"url":                 {},
	"util":                {},
	"v8":                  {},
	"vm":                  {},
	"wasi":                {},
	"worker_threads":      {},
	"zlib":                {},
	"node:assert":         {},
	"node:buffer":         {},
	"node:child_process":  {},
	"node:cluster":        {},
	"node:console":        {},
	"node:crypto":         {},
	"node:dgram":          {},
	"node:dns":            {},
	"node:events":         {},
	"node:fs":             {},
	"node:http":           {},
	"node:http2":          {},
	"node:https":          {},
	"node:module":         {},
	"node:net":            {},
	"node:os":             {},
	"node:path":           {},
	"node:perf_hooks":     {},
	"node:process":        {},
	"node:querystring":    {},
	"node:readline":       {},
	"node:stream":         {},
	"node:string_decoder": {},
	"node:timers":         {},
	"node:tls":            {},
	"node:tty":            {},
	"node:url":            {},
	"node:util":           {},
	"node:v8":             {},
	"node:vm":             {},
	"node:wasi":           {},
	"node:worker_threads": {},
	"node:zlib":           {},
}
