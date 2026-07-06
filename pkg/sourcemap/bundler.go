package sourcemap

import (
	"regexp"
	"strings"
)

// BundlerType identifies a JavaScript bundler.
type BundlerType string

const (
	BundlerWebpack BundlerType = "webpack"
	BundlerVite    BundlerType = "vite"
	BundlerEsbuild BundlerType = "esbuild"
	BundlerRollup  BundlerType = "rollup"
	BundlerParcel  BundlerType = "parcel"
	BundlerTSUp    BundlerType = "tsup"
	BundlerSWC     BundlerType = "swc"
	BundlerUnknown BundlerType = "unknown"
)

// BundlerResult holds bundler detection output.
type BundlerResult struct {
	Bundler    BundlerType `json:"bundler"`
	Confidence string      `json:"confidence"`
	Indicators []string    `json:"indicators"`
	Version    string      `json:"version,omitempty"`
}

// bundler detection patterns applied to JS content
type contentPattern struct {
	bundler    BundlerType
	pattern    string
	confidence string
	indicator  string
}

var contentPatterns = []contentPattern{
	// webpack - high confidence
	{BundlerWebpack, `__webpack_require__`, "high", "contains __webpack_require__"},
	{BundlerWebpack, `__webpack_modules__`, "high", "contains __webpack_modules__"},
	{BundlerWebpack, `webpackChunk`, "high", "contains webpackChunk global"},
	{BundlerWebpack, `/***/ `, "medium", "contains webpack comment markers (/***/)"},

	// vite - high confidence
	{BundlerVite, `/@vite/`, "high", "contains /@vite/ import path"},
	{BundlerVite, `__vite_ssr_`, "high", "contains __vite_ssr_ runtime"},
	{BundlerVite, `import.meta.hot`, "medium", "contains Vite HMR (import.meta.hot)"},

	// parcel - high confidence
	{BundlerParcel, `parcelRequire`, "high", "contains parcelRequire runtime"},
	{BundlerParcel, `@parcel/`, "high", "contains @parcel/ package reference"},

	// esbuild
	{BundlerEsbuild, `// @esbuild`, "high", "contains // @esbuild annotation"},

	// rollup
	{BundlerRollup, `/*#__PURE__*/`, "medium", "contains Rollup pure annotations"},

	// swc
	{BundlerSWC, `@swc/helpers`, "high", "contains @swc/helpers import"},
}

var webpackVersionRe = regexp.MustCompile(`webpack/(?:runtime/|lib/|bootstrap )(\d+)`)

// DetectBundler analyzes JavaScript content to identify the bundler.
func DetectBundler(content string) *BundlerResult {
	result := &BundlerResult{
		Bundler:    BundlerUnknown,
		Confidence: "low",
	}

	// Track the best match by confidence priority: high > medium > low
	bestPriority := 0
	confidencePriority := map[string]int{"low": 1, "medium": 2, "high": 3}

	for _, p := range contentPatterns {
		if strings.Contains(content, p.pattern) {
			prio := confidencePriority[p.confidence]

			// First match or better confidence or same bundler with additional indicator
			if prio > bestPriority {
				result.Bundler = p.bundler
				result.Confidence = p.confidence
				result.Indicators = []string{p.indicator}
				bestPriority = prio
			} else if result.Bundler == p.bundler {
				result.Indicators = append(result.Indicators, p.indicator)
			}
		}
	}

	// Try to extract webpack version
	if result.Bundler == BundlerWebpack {
		if m := webpackVersionRe.FindStringSubmatch(content); len(m) > 1 {
			result.Version = m[1]
		}
	}

	return result
}

// DetectBundlerFromMap analyzes a source map to identify the bundler.
func DetectBundlerFromMap(sm *SourceMap) *BundlerResult {
	result := &BundlerResult{
		Bundler:    BundlerUnknown,
		Confidence: "low",
	}

	if sm == nil {
		return result
	}

	// Check source paths for bundler-specific patterns
	var (
		hasWebpackPaths bool
		hasVitePaths    bool
		hasEsbuildPaths bool
		hasSWCPaths     bool
		hasParcelPaths  bool
		hasTSUpPaths    bool
	)

	for _, src := range sm.Sources {
		switch {
		case strings.Contains(src, "webpack/"):
			hasWebpackPaths = true
		case strings.HasPrefix(src, "/@fs/") || strings.Contains(src, "/@vite/"):
			hasVitePaths = true
		case strings.Contains(src, "node_modules/.pnpm"):
			hasEsbuildPaths = true
		case strings.Contains(src, "@swc/"):
			hasSWCPaths = true
		case strings.Contains(src, "@parcel/"):
			hasParcelPaths = true
		}
	}

	// Check file name for tsup
	if strings.Contains(strings.ToLower(sm.File), "tsup") {
		hasTSUpPaths = true
	}

	// Priority-based assignment from source paths
	switch {
	case hasWebpackPaths:
		result.Bundler = BundlerWebpack
		result.Confidence = "high"
		result.Indicators = append(result.Indicators, "source paths contain webpack/ references")
	case hasVitePaths:
		result.Bundler = BundlerVite
		result.Confidence = "high"
		result.Indicators = append(result.Indicators, "source paths contain /@fs/ or /@vite/ prefixes")
	case hasParcelPaths:
		result.Bundler = BundlerParcel
		result.Confidence = "high"
		result.Indicators = append(result.Indicators, "source paths contain @parcel/ references")
	case hasSWCPaths:
		result.Bundler = BundlerSWC
		result.Confidence = "high"
		result.Indicators = append(result.Indicators, "source paths contain @swc/ references")
	case hasTSUpPaths:
		result.Bundler = BundlerTSUp
		result.Confidence = "medium"
		result.Indicators = append(result.Indicators, "source map file name contains tsup")
	case hasEsbuildPaths:
		// esbuild is lower confidence from paths alone since pnpm paths aren't exclusive
		result.Bundler = BundlerEsbuild
		result.Confidence = "medium"
		result.Indicators = append(result.Indicators, "source paths contain node_modules/.pnpm (common with esbuild)")
	}

	// If sources have inline content, also check the content for bundler markers
	if result.Bundler == BundlerUnknown && len(sm.SourcesContent) > 0 {
		// Check first few sourcesContent entries for hints
		limit := min(len(sm.SourcesContent), 5)
		for i := range limit {
			if sm.SourcesContent[i] == "" {
				continue
			}
			contentResult := DetectBundler(sm.SourcesContent[i])
			if contentResult.Bundler != BundlerUnknown {
				result.Bundler = contentResult.Bundler
				result.Confidence = contentResult.Confidence
				result.Indicators = append(result.Indicators, contentResult.Indicators...)
				break
			}
		}
	}

	// Rollup heuristic: if many sources, no other bundler detected, and sourceRoot is empty
	if result.Bundler == BundlerUnknown && len(sm.Sources) > 1 {
		allCleanPaths := true
		for _, src := range sm.Sources {
			if strings.Contains(src, "webpack") || strings.Contains(src, "node_modules") {
				allCleanPaths = false
				break
			}
		}
		if allCleanPaths && sm.SourceRoot == "" {
			result.Bundler = BundlerRollup
			result.Confidence = "low"
			result.Indicators = append(result.Indicators, "clean source paths with no bundler-specific prefixes (possible Rollup)")
		}
	}

	return result
}
