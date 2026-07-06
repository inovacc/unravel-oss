/*
Copyright (c) 2026 Security Research

rules.go — DefaultRules() returns a copy of the embedded rubric.

Security reviewers MUST audit changes to the embedded kb-regressions.yaml.
The Go layer is intentionally a thin parser to keep the source of truth a
single auditable YAML file.
*/
package regressions

import (
	"fmt"
	"sync"
)

var (
	defaultsOnce sync.Once
	defaults     []Rule
	defaultsErr  error
)

func parseDefaults() {
	rub, err := decodeRubric(defaultRubricYAML)
	if err != nil {
		defaultsErr = fmt.Errorf("parse embedded kb-regressions.yaml: %w", err)
		return
	}
	if err := validateRubric(rub); err != nil {
		defaultsErr = fmt.Errorf("validate embedded kb-regressions.yaml: %w", err)
		return
	}
	out := make([]Rule, len(rub.Rules))
	for i, r := range rub.Rules {
		r.Source = SourceHardcoded
		out[i] = r
	}
	defaults = out
}

// DefaultRules returns a copy of the embedded rubric rules. Panics if the
// embedded YAML is invalid (build-time bug, not runtime input).
func DefaultRules() []Rule {
	defaultsOnce.Do(parseDefaults)
	if defaultsErr != nil {
		panic(defaultsErr)
	}
	out := make([]Rule, len(defaults))
	copy(out, defaults)
	return out
}
