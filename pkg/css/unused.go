// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// FindUnusedRules partitions CSS rules into used and unused based on HTML cross-reference.
// Conservative approach: ambiguous selectors and @-rules are always considered used.
// If htmlFiles is empty, all rules are returned as used (no false removals).
func FindUnusedRules(rules []Rule, htmlFiles []string) (used []Rule, unused []Rule, err error) {
	// Conservative: no HTML files means all rules are used
	if len(htmlFiles) == 0 {
		return append([]Rule{}, rules...), nil, nil
	}

	classes, ids, elements, err := buildHTMLUsageSet(htmlFiles)
	if err != nil {
		return nil, nil, err
	}

	for _, r := range rules {
		if isRuleUsed(r, classes, ids, elements) {
			used = append(used, r)
		} else {
			unused = append(unused, r)
		}
	}
	return used, unused, nil
}

// RemoveUnusedRules is a convenience wrapper that returns only used rules and the removal count.
func RemoveUnusedRules(rules []Rule, htmlFiles []string) ([]Rule, int, error) {
	used, unused, err := FindUnusedRules(rules, htmlFiles)
	if err != nil {
		return nil, 0, err
	}
	return used, len(unused), nil
}

// isRuleUsed determines if a CSS rule is referenced in the HTML usage set.
func isRuleUsed(r Rule, classes, ids, elements map[string]bool) bool {
	// @-rules are always kept (keyframes, media, font-face, etc.)
	if r.AtRule != "" {
		return true
	}

	// Empty selector = keep (safety)
	if r.Selector == "" {
		return true
	}

	// Parse selector into components
	sClasses, sIDs, sElements := parseSelectorComponents(r.Selector)

	// If selector only has element selectors (no classes or IDs), always keep
	if len(sClasses) == 0 && len(sIDs) == 0 {
		return true
	}

	// Check if ANY class matches (conservative for compound selectors)
	for _, c := range sClasses {
		if classes[c] {
			return true
		}
	}

	// Check if ANY ID matches
	for _, id := range sIDs {
		if ids[id] {
			return true
		}
	}

	// Check if ANY element matches (for mixed selectors like div.container)
	for _, el := range sElements {
		if elements[el] {
			// Only counts if there are no class/ID requirements that all miss
			// But we're conservative, so element match is enough
			// Actually, if there ARE classes and none matched, the rule is likely unused
			// But for conservatism we keep it if element matches
			return true
		}
	}

	return false
}

// parseSelectorComponents extracts classes, IDs, and element names from a CSS selector.
// Handles pseudo-selectors by stripping them to check base selectors.
// Handles compound selectors (.btn.primary) and combinators.
func parseSelectorComponents(selector string) (classes []string, ids []string, elements []string) {
	// Split by comma for grouped selectors
	groups := strings.SplitSeq(selector, ",")

	for group := range groups {
		group = strings.TrimSpace(group)
		// Split by combinators (space, >, +, ~)
		parts := strings.FieldsFunc(group, func(r rune) bool {
			return r == ' ' || r == '>' || r == '+' || r == '~'
		})

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			// Strip pseudo-selectors and pseudo-elements
			// .btn:hover -> .btn, .btn::before -> .btn
			if idx := strings.Index(part, "::"); idx >= 0 {
				part = part[:idx]
			}
			if idx := strings.Index(part, ":"); idx >= 0 {
				part = part[:idx]
			}

			// Strip attribute selectors [...]
			if idx := strings.Index(part, "["); idx >= 0 {
				part = part[:idx]
			}

			if part == "" || part == "*" {
				continue
			}

			// Parse the remaining simple selectors
			// Can have compound: div.btn#main -> element=div, class=btn, id=main
			parseSimpleSelector(part, &classes, &ids, &elements)
		}
	}
	return
}

// parseSimpleSelector parses a single simple selector like "div.btn#main" into components.
func parseSimpleSelector(sel string, classes *[]string, ids *[]string, elements *[]string) {
	// Tokenize by . and # boundaries
	i := 0
	for i < len(sel) {
		switch {
		case sel[i] == '.':
			// Class selector
			j := i + 1
			for j < len(sel) && sel[j] != '.' && sel[j] != '#' {
				j++
			}
			if j > i+1 {
				*classes = append(*classes, sel[i+1:j])
			}
			i = j
		case sel[i] == '#':
			// ID selector
			j := i + 1
			for j < len(sel) && sel[j] != '.' && sel[j] != '#' {
				j++
			}
			if j > i+1 {
				*ids = append(*ids, sel[i+1:j])
			}
			i = j
		default:
			// Element selector
			j := i
			for j < len(sel) && sel[j] != '.' && sel[j] != '#' {
				j++
			}
			if j > i {
				*elements = append(*elements, sel[i:j])
			}
			i = j
		}
	}
}

// buildHTMLUsageSet parses all HTML files and collects sets of classes, IDs, and elements.
func buildHTMLUsageSet(htmlFiles []string) (classes, ids, elements map[string]bool, err error) {
	classes = make(map[string]bool)
	ids = make(map[string]bool)
	elements = make(map[string]bool)

	for _, f := range htmlFiles {
		data, readErr := os.ReadFile(f)
		if readErr != nil {
			return nil, nil, nil, fmt.Errorf("read html %s: %w", f, readErr)
		}

		doc, parseErr := goquery.NewDocumentFromReader(bytes.NewReader(data))
		if parseErr != nil {
			return nil, nil, nil, fmt.Errorf("parse html %s: %w", f, parseErr)
		}

		// Collect all elements, classes, IDs
		doc.Find("*").Each(func(_ int, s *goquery.Selection) {
			tagName := goquery.NodeName(s)
			if tagName != "" {
				elements[tagName] = true
			}

			if classAttr, exists := s.Attr("class"); exists {
				for c := range strings.FieldsSeq(classAttr) {
					classes[c] = true
				}
			}

			if idAttr, exists := s.Attr("id"); exists {
				idAttr = strings.TrimSpace(idAttr)
				if idAttr != "" {
					ids[idAttr] = true
				}
			}
		})
	}
	return
}
