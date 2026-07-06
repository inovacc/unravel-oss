/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/jsdeob"
	"github.com/inovacc/unravel-oss/pkg/jsdeob/framework"
)

func TestPrintBeautifyAIReport_NilReport(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	PrintBeautifyAIReport(nil, &buf)
	out := buf.String()
	if !strings.Contains(out, "nil report") {
		t.Errorf("expected 'nil report' for nil input, got: %q", out)
	}
}

func TestPrintBeautifyAIReport_Variants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		report *jsdeob.BeautifyAIReport
		checks []string
	}{
		{
			name: "not beautified with reason",
			report: &jsdeob.BeautifyAIReport{
				Beautified: false,
				Reason:     "export_count_mismatch",
				ChunkCount: 2,
				RawSize:    1000,
				OutSize:    900,
			},
			checks: []string{
				"JS BEAUTIFY",
				"false",
				"export_count_mismatch",
				"1000 bytes",
				"900 bytes",
			},
		},
		{
			name: "beautified with frameworks",
			report: &jsdeob.BeautifyAIReport{
				Beautified: true,
				ChunkCount: 4,
				RawSize:    5000,
				OutSize:    4800,
				FrameworkDetected: []framework.FrameworkInfo{
					{Name: "React", Version: "18.0", Confidence: 0.95},
					{Name: "Lodash", Version: "4.17", Confidence: 0.80},
				},
			},
			checks: []string{
				"true",
				"Frameworks (2)",
				"React",
				"18.0",
				"0.95",
				"Lodash",
			},
		},
		{
			name: "no frameworks no reason",
			report: &jsdeob.BeautifyAIReport{
				Beautified: true,
				ChunkCount: 1,
				RawSize:    200,
				OutSize:    200,
			},
			checks: []string{"JS BEAUTIFY", "true", "1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			PrintBeautifyAIReport(tc.report, &buf)
			out := buf.String()
			for _, c := range tc.checks {
				if !strings.Contains(out, c) {
					t.Errorf("expected %q in output, got:\n%s", c, out)
				}
			}
		})
	}
}
