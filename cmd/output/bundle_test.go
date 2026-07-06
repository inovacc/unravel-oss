/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/jsdeob/bundle"
)

func TestPrintBundleReport_NilReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	PrintBundleReport(nil, &buf)
	out := buf.String()
	if !strings.Contains(out, "nil report") {
		t.Errorf("expected 'nil report' for nil input, got: %q", out)
	}
}

func TestPrintBundleReport_BasicReport(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		report *bundle.RunReport
		checks []string
	}{
		{
			name: "webpack bundle no beautify",
			report: &bundle.RunReport{
				BundleKind:   "webpack",
				ModulesCount: 42,
				NamedCount:   30,
				UnnamedCount: 12,
				UsedMCP:      false,
				ManifestPath: "/out/manifest.json",
				IndexPath:    "/out/index.js",
				OutputDir:    "/out",
			},
			checks: []string{
				"BUNDLE RECONSTRUCT",
				"webpack",
				"42",
				"named=30",
				"unnamed=12",
				"/out/manifest.json",
				"/out/index.js",
			},
		},
		{
			name: "rollup with beautify and MCP",
			report: &bundle.RunReport{
				BundleKind:    "rollup",
				ModulesCount:  10,
				NamedCount:    8,
				UnnamedCount:  2,
				UsedMCP:       true,
				BeautifyCount: 5,
				ManifestPath:  "/tmp/m.json",
				IndexPath:     "/tmp/i.js",
				OutputDir:     "/tmp",
			},
			checks: []string{
				"rollup",
				"Beautified:   5 modules",
				"true",
			},
		},
		{
			name: "long output dir truncated",
			report: &bundle.RunReport{
				BundleKind:   "esm",
				OutputDir:    strings.Repeat("x", 200),
				ManifestPath: "m.json",
				IndexPath:    "i.js",
			},
			checks: []string{"esm", "..."},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			PrintBundleReport(tc.report, &buf)
			out := buf.String()
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}
