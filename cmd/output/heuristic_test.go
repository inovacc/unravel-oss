/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/heuristic"
)

// ── colorLevel ────────────────────────────────────────────────────────────────

func TestColorLevel(t *testing.T) {
	t.Parallel()

	levels := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			t.Parallel()
			got := colorLevel(level)
			// Must contain the level string
			if !strings.Contains(got, level) {
				t.Errorf("colorLevel(%q) = %q; must contain the level string", level, got)
			}
			// All non-empty levels should have ANSI escape
			if !strings.Contains(got, "\033[") {
				t.Errorf("colorLevel(%q) = %q; expected ANSI escape sequence", level, got)
			}
		})
	}
}

// ── padSeverity ───────────────────────────────────────────────────────────────

func TestPadSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		wantLen int
	}{
		{"HIGH", 8},
		{"LOW", 8},
		{"CRITICAL", 8}, // already 8 chars
		{"X", 8},
		{"VERYLONGNAME", 12}, // longer than 8 kept as-is
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := padSeverity(tc.input)
			if len(got) < tc.wantLen {
				t.Errorf("padSeverity(%q) len=%d; want >= %d, got %q", tc.input, len(got), tc.wantLen, got)
			}
			if !strings.HasPrefix(got, tc.input) {
				t.Errorf("padSeverity(%q) = %q; must start with input", tc.input, got)
			}
		})
	}
}

// ── categoryLabel ────────────────────────────────────────────────────────────

func TestCategoryLabel(t *testing.T) {
	t.Parallel()

	knownMappings := map[heuristic.Category]string{
		heuristic.CategoryNetwork:     "Network/Exfil",
		heuristic.CategoryObfuscation: "Obfuscation",
		heuristic.CategoryExecution:   "Execution",
		heuristic.CategoryDataAccess:  "Data Access",
		heuristic.CategoryPersistence: "Persistence",
		heuristic.CategoryEvasion:     "Evasion",
		heuristic.CategoryCrypto:      "Crypto",
		heuristic.CategorySupplyChain: "Supply Chain",
	}

	for cat, want := range knownMappings {
		t.Run(string(cat), func(t *testing.T) {
			t.Parallel()
			got := categoryLabel(cat)
			if got != want {
				t.Errorf("categoryLabel(%q) = %q; want %q", cat, got, want)
			}
		})
	}

	// Unknown category falls back to raw string
	t.Run("unknown category", func(t *testing.T) {
		t.Parallel()
		unknown := heuristic.Category("foobar")
		got := categoryLabel(unknown)
		if got != "foobar" {
			t.Errorf("categoryLabel(unknown) = %q; want %q", got, "foobar")
		}
	})
}

// ── digitCount ───────────────────────────────────────────────────────────────

func TestDigitCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		n    int
		want int
	}{
		{0, 1},
		{1, 1},
		{9, 1},
		{10, 2},
		{99, 2},
		{100, 3},
		{999, 3},
		{1000, 4},
	}

	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			got := digitCount(tc.n)
			if got != tc.want {
				t.Errorf("digitCount(%d) = %d; want %d", tc.n, got, tc.want)
			}
		})
	}
}

// ── sortedCategories ─────────────────────────────────────────────────────────

func TestSortedCategories(t *testing.T) {
	t.Parallel()

	r := &heuristic.Result{
		Categories: map[heuristic.Category]*heuristic.CategorySummary{
			heuristic.CategoryCrypto:  {Count: 1},
			heuristic.CategoryNetwork: {Count: 2},
			// intentionally absent: Execution, etc.
		},
	}

	cats := sortedCategories(r)

	// Network should appear before Crypto (per order slice)
	if len(cats) != 2 {
		t.Fatalf("sortedCategories len = %d; want 2", len(cats))
	}
	if cats[0] != heuristic.CategoryNetwork {
		t.Errorf("cats[0] = %q; want Network", cats[0])
	}
	if cats[1] != heuristic.CategoryCrypto {
		t.Errorf("cats[1] = %q; want Crypto", cats[1])
	}
}

func TestSortedCategories_Empty(t *testing.T) {
	t.Parallel()

	r := &heuristic.Result{Categories: map[heuristic.Category]*heuristic.CategorySummary{}}
	cats := sortedCategories(r)
	if len(cats) != 0 {
		t.Errorf("sortedCategories(empty) = %v; want empty", cats)
	}
}
