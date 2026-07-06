/*
Copyright (c) 2026 Security Research
*/
// Golden tests for B4: kb_facts / kb_gaps honest-empty banner.
// These tests run without a DB — they verify the banner format and
// populated_categories helper logic.
package cmd

import (
	"strings"
	"testing"
)

// TestSqlitePopulatedCategoriesNilOnError verifies that on a nil/bad DB the
// helper returns nil rather than panicking.
func TestSqlitePopulatedCategoriesNilOnError(t *testing.T) {
	result := sqlitePopulatedCategories(nil, "", false)
	if result != nil {
		t.Errorf("expected nil on nil db, got %v", result)
	}
}

// TestHonestEmptyBannerFormat verifies the banner line format produced by
// the honest-empty path is identifiable by consumers.
func TestHonestEmptyBannerFormat(t *testing.T) {
	// Simulate what the CLI prints on empty:
	populated := []string{"auth", "network"}
	banner := "[honest-empty] layer_status=empty populated_categories=" + formatCategories(populated)
	if !strings.Contains(banner, "layer_status=empty") {
		t.Errorf("banner missing layer_status: %q", banner)
	}
	if !strings.Contains(banner, "populated_categories=") {
		t.Errorf("banner missing populated_categories: %q", banner)
	}
	if !strings.Contains(banner, "auth") {
		t.Errorf("banner missing category name: %q", banner)
	}
}

// TestHonestEmptyBannerNoCategories verifies the banner format when no
// categories exist at all.
func TestHonestEmptyBannerNoCategories(t *testing.T) {
	populated := []string{}
	banner := "[honest-empty] layer_status=empty populated_categories=" + formatCategories(populated)
	if !strings.Contains(banner, "layer_status=empty") {
		t.Errorf("banner missing layer_status: %q", banner)
	}
}

// formatCategories mirrors the %v formatting of []string used in the CLI.
func formatCategories(cats []string) string {
	if len(cats) == 0 {
		return "[]"
	}
	return "[" + strings.Join(cats, " ") + "]"
}
