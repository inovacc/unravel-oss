// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/css"
)

// Rule represents a CSS rule (ruleset or at-rule).
type Rule struct {
	Selector     string
	Declarations []Declaration
	AtRule       string
	Children     []Rule
	Raw          string
}

// Declaration represents a CSS property: value pair.
type Declaration struct {
	Property  string
	Value     string
	Important bool
}

// ParseStylesheet parses CSS content into a slice of Rules using tdewolff/parse.
func ParseStylesheet(content []byte) ([]Rule, error) {
	if len(bytes.TrimSpace(content)) == 0 {
		return []Rule{}, nil
	}

	p := css.NewParser(parse.NewInput(bytes.NewReader(content)), false)
	var rules []Rule

	for {
		gt, _, data := p.Next()
		switch gt {
		case css.ErrorGrammar:
			// EOF is normal termination
			if err := p.Err(); err != nil {
				return rules, nil // return partial results on error
			}
			return rules, nil

		case css.BeginAtRuleGrammar:
			atName := string(data)
			rule := Rule{AtRule: atName}
			// Collect the at-rule prelude (e.g., media query)
			prelude := collectValues(p)
			if prelude != "" {
				rule.AtRule = atName + " " + prelude
			}
			// Parse nested content
			rule.Children = parseNestedRules(p)
			rules = append(rules, rule)

		case css.AtRuleGrammar:
			// Non-block at-rule like @import
			atName := string(data)
			prelude := collectValues(p)
			rule := Rule{AtRule: atName}
			if prelude != "" {
				rule.Raw = prelude
			}
			rules = append(rules, rule)

		case css.BeginRulesetGrammar:
			selector := string(data)
			// Collect any additional selector tokens
			extraSel := collectValues(p)
			if extraSel != "" {
				selector += extraSel
			}
			selector = strings.TrimSpace(selector)

			rule := Rule{Selector: selector}
			rule.Declarations = parseDeclarations(p)
			rules = append(rules, rule)

		case css.QualifiedRuleGrammar:
			// Standalone qualified rule
			selector := strings.TrimSpace(string(data))
			rules = append(rules, Rule{Selector: selector})

		case css.DeclarationGrammar:
			// Top-level declaration (rare, but handle gracefully)
			continue

		case css.CustomPropertyGrammar:
			continue

		default:
			continue
		}
	}
}

// parseNestedRules parses rules inside an at-rule block.
func parseNestedRules(p *css.Parser) []Rule {
	var children []Rule
	for {
		gt, _, data := p.Next()
		switch gt {
		case css.ErrorGrammar:
			return children

		case css.EndAtRuleGrammar, css.EndRulesetGrammar:
			return children

		case css.BeginRulesetGrammar:
			selector := string(data)
			extra := collectValues(p)
			if extra != "" {
				selector += extra
			}
			selector = strings.TrimSpace(selector)
			rule := Rule{Selector: selector}
			rule.Declarations = parseDeclarations(p)
			children = append(children, rule)

		case css.BeginAtRuleGrammar:
			atName := string(data)
			prelude := collectValues(p)
			rule := Rule{AtRule: atName}
			if prelude != "" {
				rule.AtRule = atName + " " + prelude
			}
			rule.Children = parseNestedRules(p)
			children = append(children, rule)

		case css.DeclarationGrammar:
			// Declaration at at-rule level (e.g., inside @keyframes step)
			prop := strings.TrimSpace(string(data))
			val, important := collectDeclarationValue(p)
			if prop != "" {
				// If children is empty or last child has a selector, add to declarations
				if len(children) > 0 {
					last := &children[len(children)-1]
					last.Declarations = append(last.Declarations, Declaration{
						Property:  prop,
						Value:     val,
						Important: important,
					})
				}
			}

		case css.CustomPropertyGrammar:
			prop := strings.TrimSpace(string(data))
			val, important := collectDeclarationValue(p)
			if len(children) > 0 {
				last := &children[len(children)-1]
				last.Declarations = append(last.Declarations, Declaration{
					Property:  prop,
					Value:     val,
					Important: important,
				})
			}

		default:
			continue
		}
	}
}

// parseDeclarations reads declarations until EndRulesetGrammar.
func parseDeclarations(p *css.Parser) []Declaration {
	var decls []Declaration
	for {
		gt, _, data := p.Next()
		switch gt {
		case css.ErrorGrammar, css.EndRulesetGrammar, css.EndAtRuleGrammar:
			return decls

		case css.DeclarationGrammar:
			prop := strings.TrimSpace(string(data))
			val, important := collectDeclarationValue(p)
			decls = append(decls, Declaration{
				Property:  prop,
				Value:     val,
				Important: important,
			})

		case css.CustomPropertyGrammar:
			prop := strings.TrimSpace(string(data))
			val, important := collectDeclarationValue(p)
			decls = append(decls, Declaration{
				Property:  prop,
				Value:     val,
				Important: important,
			})

		default:
			continue
		}
	}
}

// collectValues gathers value tokens from the parser.
func collectValues(p *css.Parser) string {
	var parts []string
	for _, val := range p.Values() {
		parts = append(parts, string(val.Data))
	}
	return strings.TrimSpace(strings.Join(parts, ""))
}

// collectDeclarationValue gathers values and detects !important.
func collectDeclarationValue(p *css.Parser) (string, bool) {
	var parts []string
	important := false
	for _, val := range p.Values() {
		tok := string(val.Data)
		if strings.EqualFold(tok, "!important") || strings.EqualFold(tok, "important") {
			important = true
			continue
		}
		if tok == "!" {
			// Next token might be "important"
			continue
		}
		parts = append(parts, tok)
	}
	value := strings.TrimSpace(strings.Join(parts, " "))
	// Collapse internal whitespace
	value = collapseSpaces(value)
	return value, important
}

// collapseSpaces reduces multiple spaces to single space.
func collapseSpaces(s string) string {
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				b.WriteRune(' ')
			}
			prevSpace = true
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

// ParseInlineStyle parses inline CSS (e.g., from style attributes) into declarations.
func ParseInlineStyle(style string) ([]Declaration, error) {
	if strings.TrimSpace(style) == "" {
		return []Declaration{}, nil
	}

	p := css.NewParser(parse.NewInput(strings.NewReader(style)), true)
	var decls []Declaration

	for {
		gt, _, data := p.Next()
		switch gt {
		case css.ErrorGrammar:
			return decls, nil

		case css.DeclarationGrammar:
			prop := strings.TrimSpace(string(data))
			val, important := collectDeclarationValue(p)
			decls = append(decls, Declaration{
				Property:  prop,
				Value:     val,
				Important: important,
			})

		case css.CustomPropertyGrammar:
			prop := strings.TrimSpace(string(data))
			val, important := collectDeclarationValue(p)
			decls = append(decls, Declaration{
				Property:  prop,
				Value:     val,
				Important: important,
			})

		default:
			continue
		}
	}
}

// NormalizeCSS lowercases property names, trims values, and sorts declarations
// alphabetically within each rule. Preserves rule order (CSS cascade).
func NormalizeCSS(rules []Rule) []Rule {
	result := make([]Rule, len(rules))
	for i, r := range rules {
		result[i] = normalizeRule(r)
	}
	return result
}

func normalizeRule(r Rule) Rule {
	out := Rule{
		Selector: r.Selector,
		AtRule:   r.AtRule,
		Raw:      r.Raw,
	}

	// Normalize declarations
	decls := make([]Declaration, len(r.Declarations))
	for j, d := range r.Declarations {
		decls[j] = Declaration{
			Property:  strings.ToLower(strings.TrimSpace(d.Property)),
			Value:     strings.TrimSpace(d.Value),
			Important: d.Important,
		}
	}

	// Sort declarations alphabetically by property name
	sort.Slice(decls, func(a, b int) bool {
		return decls[a].Property < decls[b].Property
	})
	out.Declarations = decls

	// Normalize children recursively
	if len(r.Children) > 0 {
		out.Children = make([]Rule, len(r.Children))
		for j, child := range r.Children {
			out.Children[j] = normalizeRule(child)
		}
	}

	return out
}

// varPattern matches CSS var() function calls.
var varPattern = regexp.MustCompile(`var\(\s*(--[a-zA-Z0-9_-]+)\s*(?:,\s*([^)]+))?\)`)

// ResolveVariables replaces var() references with resolved values from :root.
// maxDepth limits recursion to detect circular references.
func ResolveVariables(rules []Rule, maxDepth int) []Rule {
	if maxDepth <= 0 {
		maxDepth = 10
	}

	// First pass: collect custom property declarations from :root and *
	vars := make(map[string]string)
	for _, r := range rules {
		if r.Selector == ":root" || r.Selector == "*" {
			for _, d := range r.Declarations {
				if strings.HasPrefix(d.Property, "--") {
					vars[d.Property] = d.Value
				}
			}
		}
	}

	// Second pass: resolve var() references
	result := make([]Rule, len(rules))
	for i, r := range rules {
		result[i] = resolveRuleVars(r, vars, maxDepth)
	}
	return result
}

func resolveRuleVars(r Rule, vars map[string]string, maxDepth int) Rule {
	out := Rule{
		Selector: r.Selector,
		AtRule:   r.AtRule,
		Raw:      r.Raw,
	}

	decls := make([]Declaration, len(r.Declarations))
	for j, d := range r.Declarations {
		decls[j] = Declaration{
			Property:  d.Property,
			Value:     resolveValue(d.Value, vars, maxDepth, nil),
			Important: d.Important,
		}
	}
	out.Declarations = decls

	if len(r.Children) > 0 {
		out.Children = make([]Rule, len(r.Children))
		for j, child := range r.Children {
			out.Children[j] = resolveRuleVars(child, vars, maxDepth)
		}
	}

	return out
}

// resolveValue resolves var() references in a value string.
// stack tracks the resolution path for cycle detection.
func resolveValue(value string, vars map[string]string, maxDepth int, stack []string) string {
	if maxDepth <= 0 || !strings.Contains(value, "var(") {
		return value
	}

	return varPattern.ReplaceAllStringFunc(value, func(match string) string {
		sub := varPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		varName := sub[1]
		fallback := ""
		if len(sub) >= 3 {
			fallback = strings.TrimSpace(sub[2])
		}

		// Cycle detection
		if slices.Contains(stack, varName) {
			// Circular reference detected -- leave raw var() in place
			return match
		}

		resolved, ok := vars[varName]
		if !ok {
			if fallback != "" {
				return fallback
			}
			return match
		}

		// Recursively resolve if the resolved value also contains var()
		newStack := append(stack, varName)
		return resolveValue(resolved, vars, maxDepth-1, newStack)
	})
}

// String returns a CSS string representation of the declaration.
func (d Declaration) String() string {
	s := fmt.Sprintf("%s: %s", d.Property, d.Value)
	if d.Important {
		s += " !important"
	}
	return s
}
