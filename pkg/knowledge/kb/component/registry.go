/*
Copyright (c) 2026 Security Research
*/

package component

import (
	"slices"
	"sync"
)

var (
	rulesMu sync.RWMutex
	rules   []Rule
)

// Register adds a rule to the package-level registry. Intended to be called
// from rule package init() functions via blank-import wiring (see component/runtime).
// Panics on empty Name or non-bucket Component (positive rules only) so that
// configuration bugs surface at process start.
func Register(rule Rule) {
	if rule.Name == "" {
		panic("component.Register: rule.Name must be non-empty")
	}
	if !rule.Suppress {
		if !isBucket(rule.Component) {
			panic("component.Register: rule.Component not in Buckets: " + rule.Component)
		}
		if rule.Confidence != 0.65 && rule.Confidence != 0.80 && rule.Confidence != 0.95 {
			panic("component.Register: rule.Confidence must be 0.65, 0.80, or 0.95")
		}
	}
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules = append(rules, rule)
}

// All returns a copy of the registered rules. Safe for concurrent use.
func All() []Rule {
	rulesMu.RLock()
	defer rulesMu.RUnlock()
	out := make([]Rule, len(rules))
	copy(out, rules)
	return out
}

// resetForTest wipes the registry. Test-only helper.
func resetForTest() {
	rulesMu.Lock()
	defer rulesMu.Unlock()
	rules = nil
}

func isBucket(c string) bool {
	return slices.Contains(Buckets, c)
}
