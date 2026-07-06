/*
Copyright (c) 2026 Security Research
*/
package scorecard

// scorers is the global registry populated via init() side-effects in each
// scorer_<id>.go file (mirrors pkg/inject/registry.go:12).
var scorers []Scorer

// Register appends s to the global registry. Called from each scorer file's
// init() function.
func Register(s Scorer) { scorers = append(scorers, s) }

// All returns a snapshot of registered scorers (unordered — Rubric.New sorts
// against CanonicalDims).
func All() []Scorer { return append([]Scorer(nil), scorers...) }

// resetScorersForTest clears the registry. Test-only helper.
func resetScorersForTest() { scorers = nil }
