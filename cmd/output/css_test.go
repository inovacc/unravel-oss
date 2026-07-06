/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/css"
)

// ── PrintCSSResult ────────────────────────────────────────────────────────────

func TestPrintCSSResult_Nil(t *testing.T) {
	out := captureStdout(t, func() {
		PrintCSSResult(nil, false)
	})
	if !strings.Contains(out, "No CSS") {
		t.Errorf("expected 'No CSS' for nil result, got: %q", out)
	}
}

func TestPrintCSSResult_Variants(t *testing.T) {
	tests := []struct {
		name    string
		result  *css.Result
		verbose bool
		checks  []string
	}{
		{
			name: "basic stats non-verbose",
			result: &css.Result{
				Stats: css.ExtractionStats{
					CSSFiles:          5,
					HTMLFiles:         3,
					CSSInJSFound:      2,
					ImportsResolved:   4,
					RulesRemovedDedup: 10,
					UnusedRemoved:     7,
					ComponentCount:    2,
				},
				OutputDir: "/out/css",
			},
			verbose: false,
			checks: []string{
				"CSS Extraction",
				"5", // css files
				"3", // html files
				"/out/css",
			},
		},
		{
			name: "with components",
			result: &css.Result{
				Stats: css.ExtractionStats{CSSFiles: 2, ComponentCount: 1},
				Components: []css.Component{
					{
						Name: "Button",
						Stylesheets: []css.Stylesheet{
							{Path: "button.css"},
							{Path: "button-dark.css"},
						},
					},
				},
			},
			verbose: false,
			checks:  []string{"Button", "2 stylesheets"},
		},
		{
			name: "verbose with stylesheets",
			result: &css.Result{
				Stats: css.ExtractionStats{CSSFiles: 1},
				Stylesheets: []css.Stylesheet{
					{
						Path:         "app.css",
						Source:       "file",
						RuleCount:    42,
						OriginalSize: 1024,
						CleanedSize:  900,
					},
				},
			},
			verbose: true,
			checks:  []string{"app.css", "42 rules", "1.0 KB"},
		},
		{
			name: "with errors",
			result: &css.Result{
				Stats:  css.ExtractionStats{CSSFiles: 0},
				Errors: []string{"failed to parse vars.css", "import loop detected"},
			},
			verbose: false,
			checks:  []string{"Warnings: 2", "failed to parse vars.css", "import loop"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := captureStdout(t, func() {
				PrintCSSResult(tc.result, tc.verbose)
			})
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}

// ── PrintCSSBatchResult ───────────────────────────────────────────────────────

func TestPrintCSSBatchResult_EmptySlice(t *testing.T) {
	out := captureStdout(t, func() {
		PrintCSSBatchResult(nil)
	})
	if !strings.Contains(out, "0 paths") {
		t.Errorf("expected '0 paths' for nil slice, got: %q", out)
	}
}

func TestPrintCSSBatchResult_WithNilEntry(t *testing.T) {
	results := []*css.Result{
		{Stats: css.ExtractionStats{CSSFiles: 3}},
		nil,
		{Stats: css.ExtractionStats{CSSFiles: 1}, Errors: []string{"e1"}},
	}

	out := captureStdout(t, func() {
		PrintCSSBatchResult(results)
	})

	checks := []string{
		"3 paths processed",
		"(nil result)",
		"1 warnings",
		"Total: 4 CSS files",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("expected %q in batch output, got:\n%s", c, out)
		}
	}
}
