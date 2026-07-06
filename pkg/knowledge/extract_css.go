package knowledge

import (
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/css"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// CSSKnowledge holds CSS-specific knowledge extracted from an application.
type CSSKnowledge struct {
	Framework    string   `json:"framework,omitempty"`
	Preprocessor string   `json:"preprocessor,omitempty"`
	CSSInJS      bool     `json:"css_in_js"`
	TotalFiles   int      `json:"total_files"`
	TotalRules   int      `json:"total_rules"`
	Components   []string `json:"components,omitempty"`
	Variables    []string `json:"variables,omitempty"`
	ImportChains int      `json:"import_chains"`
	ExternalLibs []string `json:"external_libs,omitempty"`
}

// extractCSS builds CSSKnowledge from the dissect result's CSS extraction data.
func extractCSS(dr *dissect.DissectResult) *CSSKnowledge {
	if dr.CSSExtraction == nil {
		return nil
	}

	r := dr.CSSExtraction
	k := &CSSKnowledge{
		TotalFiles:   r.Stats.CSSFiles,
		TotalRules:   countTotalRules(r),
		ImportChains: r.Stats.ImportsResolved,
		CSSInJS:      r.Stats.CSSInJSFound > 0,
	}

	// Collect component names.
	for _, c := range r.Components {
		k.Components = append(k.Components, c.Name)
	}

	// Detect CSS framework from stylesheet content and paths.
	k.Framework = detectCSSFramework(r)

	// Detect preprocessor from file extensions.
	k.Preprocessor = detectPreprocessor(r)

	// Count import graph as external lib references.
	k.ExternalLibs = detectExternalLibs(r)

	return k
}

func countTotalRules(r *css.Result) int {
	total := 0
	for _, s := range r.Stylesheets {
		total += s.RuleCount
	}
	return total
}

func detectCSSFramework(r *css.Result) string {
	for _, s := range r.Stylesheets {
		path := strings.ToLower(s.Path)
		content := strings.ToLower(string(s.Content))

		if strings.Contains(path, "tailwind") || strings.Contains(content, "--tw-") {
			return "Tailwind CSS"
		}
		if strings.Contains(path, "bootstrap") || strings.Contains(content, ".btn-primary") {
			return "Bootstrap"
		}
		if strings.Contains(path, "bulma") || strings.Contains(content, ".is-primary") {
			return "Bulma"
		}
		if strings.Contains(path, "foundation") {
			return "Foundation"
		}
		if strings.Contains(path, "material") || strings.Contains(content, ".mdc-") {
			return "Material Design"
		}
		if strings.Contains(path, "antd") || strings.Contains(content, ".ant-") {
			return "Ant Design"
		}
		if strings.Contains(path, "chakra") {
			return "Chakra UI"
		}
	}
	return ""
}

func detectPreprocessor(r *css.Result) string {
	for _, s := range r.Stylesheets {
		ext := strings.ToLower(filepath.Ext(s.Path))
		switch ext {
		case ".scss", ".sass":
			return "SCSS"
		case ".less":
			return "LESS"
		case ".styl":
			return "Stylus"
		}
	}
	return ""
}

func detectExternalLibs(r *css.Result) []string {
	libs := make(map[string]bool)
	for _, deps := range r.ImportGraph {
		for _, dep := range deps {
			if strings.Contains(dep, "node_modules") {
				// Extract package name from node_modules path.
				parts := strings.SplitAfter(dep, "node_modules/")
				if len(parts) > 1 {
					pkg := parts[1]
					if idx := strings.Index(pkg, "/"); idx > 0 {
						if strings.HasPrefix(pkg, "@") {
							// Scoped package: @scope/name
							rest := pkg[idx+1:]
							if idx2 := strings.Index(rest, "/"); idx2 > 0 {
								pkg = pkg[:idx+1+idx2]
							}
						} else {
							pkg = pkg[:idx]
						}
					}
					libs[pkg] = true
				}
			}
		}
	}

	result := make([]string, 0, len(libs))
	for lib := range libs {
		result = append(result, lib)
	}
	return result
}
