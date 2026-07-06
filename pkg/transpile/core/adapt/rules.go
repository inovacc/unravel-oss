package adapt

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/cpp/prompt"
)

// Rule represents a library-specific conversion rule.
type Rule struct {
	Name     string   `json:"name"`
	Includes []string `json:"includes"` // matching #include patterns
	Content  string   `json:"content"`  // rule text
}

// RuleSet holds a collection of rules indexed by include path.
type RuleSet struct {
	rules map[string]*Rule
}

// NewRuleSet creates a new empty rule set.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		rules: make(map[string]*Rule),
	}
}

// AddRule adds a rule to the set.
func (rs *RuleSet) AddRule(r *Rule) {
	for _, inc := range r.Includes {
		rs.rules[inc] = r
	}
}

// MatchIncludes returns unique rule names that match any of the given includes.
func (rs *RuleSet) MatchIncludes(includes []string) []string {
	seen := make(map[string]struct{})

	var names []string

	for _, inc := range includes {
		// Try direct match
		if r, ok := rs.rules[inc]; ok {
			if _, ok := seen[r.Name]; !ok {
				seen[r.Name] = struct{}{}
				names = append(names, r.Name)
			}

			continue
		}

		// Try matching via the prompt package's include mapping
		ruleName := prompt.MapIncludeToRule(inc)
		if ruleName != "" {
			if _, ok := seen[ruleName]; !ok {
				seen[ruleName] = struct{}{}
				names = append(names, ruleName)
			}

			continue
		}

		// Try matching the first path component
		if idx := strings.Index(inc, "/"); idx > 0 {
			prefix := inc[:idx]
			if r, ok := rs.rules[prefix]; ok {
				if _, ok := seen[r.Name]; !ok {
					seen[r.Name] = struct{}{}
					names = append(names, r.Name)
				}
			}
		}
	}

	return names
}
