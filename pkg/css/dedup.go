// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

// DeduplicateRules removes exact and semantic duplicate rules.
// Returns deduplicated rules and count of removed rules.
// For exact duplicates, the LAST occurrence wins (CSS cascade).
// Per Pitfall 3: never merge rules with different selectors.
func DeduplicateRules(rules []Rule) ([]Rule, int) {
	if len(rules) == 0 {
		return []Rule{}, 0
	}

	// Build canonical hash for each rule. Process in reverse so last occurrence wins.
	type entry struct {
		rule  Rule
		index int
		hash  string
	}

	seen := make(map[string]int) // hash -> index of kept entry
	entries := make([]entry, 0, len(rules))
	removed := 0

	// Forward pass: for each rule, compute its canonical hash.
	hashes := make([]string, len(rules))
	for i, r := range rules {
		hashes[i] = ruleHash(r)
	}

	// Reverse pass: mark last occurrence of each hash as kept.
	kept := make(map[int]bool)
	for i := len(rules) - 1; i >= 0; i-- {
		h := hashes[i]
		if _, exists := seen[h]; !exists {
			seen[h] = i
			kept[i] = true
		}
	}

	// Also check semantic equivalence for rules with same selector.
	// Group by selector, compare canonical forms.
	type selectorGroup struct {
		indices []int
	}
	groups := make(map[string]*selectorGroup)
	for i, r := range rules {
		if !kept[i] {
			continue
		}
		key := r.Selector
		if key == "" {
			key = r.AtRule
		}
		if groups[key] == nil {
			groups[key] = &selectorGroup{}
		}
		groups[key].indices = append(groups[key].indices, i)
	}

	// Within each selector group, check for semantic equivalence
	for _, g := range groups {
		if len(g.indices) < 2 {
			continue
		}
		// Compare each pair for semantic equivalence
		canonicals := make(map[string]int) // canonical form -> last index
		for _, idx := range g.indices {
			canon := canonicalRuleForm(rules[idx])
			if prevIdx, exists := canonicals[canon]; exists {
				// Remove the earlier one (keep last)
				kept[prevIdx] = false
			}
			canonicals[canon] = idx
		}
	}

	// Build result preserving order
	for i, r := range rules {
		if kept[i] {
			entries = append(entries, entry{rule: r, index: i, hash: hashes[i]})
		} else {
			removed++
		}
	}

	result := make([]Rule, len(entries))
	for i, e := range entries {
		result[i] = e.rule
	}

	return result, removed
}

// ruleHash creates a deterministic hash of a rule by selector + sorted declarations.
func ruleHash(r Rule) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "sel:%s\n", r.Selector)
	_, _ = fmt.Fprintf(h, "at:%s\n", r.AtRule)

	// Sort declarations for deterministic hash
	decls := make([]string, len(r.Declarations))
	for i, d := range r.Declarations {
		imp := ""
		if d.Important {
			imp = "!important"
		}
		decls[i] = fmt.Sprintf("%s:%s%s", d.Property, d.Value, imp)
	}
	sort.Strings(decls)
	for _, d := range decls {
		_, _ = fmt.Fprintf(h, "d:%s\n", d)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// canonicalRuleForm produces a canonical string for semantic comparison.
// Expands shorthands to their canonical form for comparison.
func canonicalRuleForm(r Rule) string {
	var parts []string
	parts = append(parts, "sel:"+r.Selector)
	parts = append(parts, "at:"+r.AtRule)

	decls := make([]string, len(r.Declarations))
	for i, d := range r.Declarations {
		val := expandShorthand(d.Property, d.Value)
		imp := ""
		if d.Important {
			imp = "!important"
		}
		decls[i] = fmt.Sprintf("%s:%s%s", d.Property, val, imp)
	}
	sort.Strings(decls)
	parts = append(parts, decls...)
	return strings.Join(parts, "|")
}

// expandShorthand expands CSS shorthand properties to their canonical form.
// This enables semantic dedup: `margin: 10px 10px 10px 10px` == `margin: 10px`.
func expandShorthand(prop, value string) string {
	prop = strings.ToLower(strings.TrimSpace(prop))
	value = strings.TrimSpace(value)

	// Only expand box-model shorthands
	switch prop {
	case "margin", "padding", "border-width", "border-style", "border-color",
		"border-radius":
		return expandBoxShorthand(value)
	default:
		return value
	}
}

// expandBoxShorthand expands a box-model shorthand to its 4-value canonical form.
// 1 value: all same -> "V V V V"
// 2 values: top/bottom left/right -> "V1 V2 V1 V2"
// 3 values: top left/right bottom -> "V1 V2 V3 V2"
// 4 values: already canonical
func expandBoxShorthand(value string) string {
	parts := strings.Fields(value)
	switch len(parts) {
	case 1:
		return fmt.Sprintf("%s %s %s %s", parts[0], parts[0], parts[0], parts[0])
	case 2:
		return fmt.Sprintf("%s %s %s %s", parts[0], parts[1], parts[0], parts[1])
	case 3:
		return fmt.Sprintf("%s %s %s %s", parts[0], parts[1], parts[2], parts[1])
	case 4:
		return fmt.Sprintf("%s %s %s %s", parts[0], parts[1], parts[2], parts[3])
	default:
		return value
	}
}
