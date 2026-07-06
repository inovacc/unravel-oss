// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"path/filepath"
	"sort"
	"strings"
)

// genericFilenames are names that don't identify a component on their own.
var genericFilenames = map[string]bool{
	"styles":  true,
	"style":   true,
	"index":   true,
	"main":    true,
	"app":     true,
	"global":  true,
	"globals": true,
	"common":  true,
	"base":    true,
	"reset":   true,
	"theme":   true,
}

// knownSuffixes are stripped during filename component detection.
var knownSuffixes = []string{
	".module.css", ".module.scss", ".module.less",
	".styled.js", ".styled.ts", ".styled.tsx",
	".styles.js", ".styles.ts", ".styles.tsx",
	".css", ".scss", ".less", ".sass",
	".js", ".ts", ".tsx", ".jsx",
}

// selectorToComponent maps common selector prefixes to component names.
var selectorToComponent = map[string]string{
	"btn":        "button",
	"button":     "button",
	"modal":      "modal",
	"nav":        "nav",
	"navbar":     "nav",
	"header":     "header",
	"footer":     "footer",
	"card":       "card",
	"form":       "form",
	"input":      "input",
	"table":      "table",
	"list":       "list",
	"menu":       "menu",
	"dropdown":   "dropdown",
	"sidebar":    "sidebar",
	"tab":        "tab",
	"tabs":       "tab",
	"alert":      "alert",
	"badge":      "badge",
	"tooltip":    "tooltip",
	"popover":    "popover",
	"accordion":  "accordion",
	"carousel":   "carousel",
	"breadcrumb": "breadcrumb",
	"pagination": "pagination",
}

// OrganizeByComponent groups stylesheets into components using a 4-layer heuristic:
//  1. Filename match: strip extensions and known suffixes
//  2. Directory context: use parent directory name if filename is generic
//  3. Selector fallback: analyze CSS selectors for dominant prefix
//  4. Catch-all: unmatched files go to "_global"
func OrganizeByComponent(sheets []Stylesheet) []Component {
	compMap := make(map[string]*Component)

	for i := range sheets {
		sheet := &sheets[i]
		name := classifyComponent(sheet)
		sheet.Component = name

		comp, ok := compMap[name]
		if !ok {
			comp = &Component{
				Name: name,
				Dir:  name + "/",
			}
			compMap[name] = comp
		}
		comp.Stylesheets = append(comp.Stylesheets, *sheet)
	}

	// Sort components alphabetically
	var result []Component
	for _, c := range compMap {
		result = append(result, *c)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

// classifyComponent determines which component a stylesheet belongs to.
func classifyComponent(sheet *Stylesheet) string {
	// Layer 1: Filename match
	name := componentFromFilename(sheet.Path)
	if name != "" && !genericFilenames[name] {
		return name
	}

	// Layer 2: Directory context
	name = componentFromDirectory(sheet.Path)
	if name != "" && !genericFilenames[name] {
		return name
	}

	// Layer 3: Selector fallback
	name = componentFromSelectors(sheet.Content)
	if name != "" {
		return name
	}

	// Layer 4: Catch-all
	return "_global"
}

// componentFromFilename strips extensions and known suffixes to derive a component name.
func componentFromFilename(path string) string {
	base := filepath.Base(path)
	// Normalize separators
	base = strings.ReplaceAll(base, "\\", "/")

	// Strip known suffixes (longest first, already ordered that way)
	lower := strings.ToLower(base)
	for _, suffix := range knownSuffixes {
		if strings.HasSuffix(lower, suffix) {
			base = base[:len(base)-len(suffix)]
			break
		}
	}

	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}

	return strings.ToLower(base)
}

// componentFromDirectory uses the parent directory name when the filename is generic.
func componentFromDirectory(path string) string {
	// Normalize to forward slashes
	normalized := strings.ReplaceAll(path, "\\", "/")
	dir := filepath.Dir(normalized)
	if dir == "." || dir == "" || dir == "/" {
		return ""
	}
	// Use the last directory component
	dirName := filepath.Base(dir)
	return strings.ToLower(dirName)
}

// componentFromSelectors analyzes CSS selectors to find a dominant class prefix.
func componentFromSelectors(content []byte) string {
	if len(content) == 0 {
		return ""
	}

	rules, err := ParseStylesheet(content)
	if err != nil || len(rules) == 0 {
		return ""
	}

	// Count class prefixes
	prefixCount := make(map[string]int)
	for _, r := range rules {
		if r.Selector == "" {
			continue
		}
		classes := extractClassPrefixes(r.Selector)
		for _, cls := range classes {
			prefixCount[cls]++
		}
	}

	if len(prefixCount) == 0 {
		return ""
	}

	// Find most frequent prefix
	var bestPrefix string
	bestCount := 0
	for prefix, count := range prefixCount {
		if count > bestCount {
			bestCount = count
			bestPrefix = prefix
		}
	}

	// Need at least 2 occurrences to be meaningful
	if bestCount < 2 {
		return ""
	}

	// Map known prefixes to component names
	if comp, ok := selectorToComponent[bestPrefix]; ok {
		return comp
	}
	return bestPrefix
}

// extractClassPrefixes extracts class name prefixes from a CSS selector.
// ".btn-primary" -> "btn", ".modal-header" -> "modal"
func extractClassPrefixes(selector string) []string {
	var prefixes []string
	parts := strings.FieldsFunc(selector, func(r rune) bool {
		return r == ' ' || r == ',' || r == '>' || r == '+' || r == '~'
	})

	for _, part := range parts {
		// Find class selectors
		_, after, ok := strings.Cut(part, ".")
		if !ok {
			continue
		}
		className := after
		// Remove pseudo-selectors
		if colonIdx := strings.Index(className, ":"); colonIdx >= 0 {
			className = className[:colonIdx]
		}
		// Remove attribute selectors
		if bracketIdx := strings.Index(className, "["); bracketIdx >= 0 {
			className = className[:bracketIdx]
		}
		// Get prefix (before first hyphen)
		if hyphenIdx := strings.Index(className, "-"); hyphenIdx > 0 {
			prefixes = append(prefixes, className[:hyphenIdx])
		} else if className != "" {
			prefixes = append(prefixes, className)
		}
	}
	return prefixes
}
