// Copyright (c) 2026. All rights reserved.
// Use of this source code is governed by a BSD 3-Clause
// license that can be found in the LICENSE file.

package css

import (
	"testing"
)

func TestDeduplicateRules_ExactDuplicates(t *testing.T) {
	rules := []Rule{
		{Selector: ".btn", Declarations: []Declaration{
			{Property: "color", Value: "red"},
			{Property: "padding", Value: "8px"},
		}},
		{Selector: ".btn", Declarations: []Declaration{
			{Property: "color", Value: "red"},
			{Property: "padding", Value: "8px"},
		}},
	}
	result, removed := DeduplicateRules(rules)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 rule after dedup, got %d", len(result))
	}
}

func TestDeduplicateRules_SameSelectorDifferentDeclarations(t *testing.T) {
	rules := []Rule{
		{Selector: ".btn", Declarations: []Declaration{
			{Property: "color", Value: "red"},
		}},
		{Selector: ".btn", Declarations: []Declaration{
			{Property: "color", Value: "blue"},
		}},
	}
	result, removed := DeduplicateRules(rules)
	if removed != 0 {
		t.Errorf("expected 0 removed (different declarations), got %d", removed)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result))
	}
}

func TestDeduplicateRules_SameDeclarationsDifferentSelectors(t *testing.T) {
	// Per Pitfall 3: never merge cross-selector
	rules := []Rule{
		{Selector: ".btn", Declarations: []Declaration{
			{Property: "color", Value: "red"},
		}},
		{Selector: ".modal", Declarations: []Declaration{
			{Property: "color", Value: "red"},
		}},
	}
	result, removed := DeduplicateRules(rules)
	if removed != 0 {
		t.Errorf("expected 0 removed (different selectors), got %d", removed)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 rules, got %d", len(result))
	}
}

func TestDeduplicateRules_SemanticEquivalence(t *testing.T) {
	rules := []Rule{
		{Selector: ".card", Declarations: []Declaration{
			{Property: "margin", Value: "10px 10px 10px 10px"},
		}},
		{Selector: ".card", Declarations: []Declaration{
			{Property: "margin", Value: "10px"},
		}},
	}
	result, removed := DeduplicateRules(rules)
	if removed != 1 {
		t.Errorf("expected 1 removed (semantic equiv), got %d", removed)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 rule, got %d", len(result))
	}
}

func TestDeduplicateRules_PreservesOrder(t *testing.T) {
	// Last occurrence wins for exact dupes
	rules := []Rule{
		{Selector: ".a", Declarations: []Declaration{{Property: "color", Value: "red"}}},
		{Selector: ".b", Declarations: []Declaration{{Property: "color", Value: "blue"}}},
		{Selector: ".a", Declarations: []Declaration{{Property: "color", Value: "red"}}},
	}
	result, _ := DeduplicateRules(rules)
	if len(result) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(result))
	}
	// .b should come first (since the first .a was removed, last .a kept)
	if result[0].Selector != ".b" {
		t.Errorf("expected first rule to be .b, got %q", result[0].Selector)
	}
	if result[1].Selector != ".a" {
		t.Errorf("expected second rule to be .a, got %q", result[1].Selector)
	}
}
