/*
Copyright (c) 2026 Security Research
*/

package telemetry

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Telemetry(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "TelemetryTracker", Path: "src/telemetry/track.go",
				SymbolsJSON: `["sentry","analytics"]`,
			},
			want: "telemetry",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "MetricBeacon", Path: "src/util/x.go",
				SymbolsJSON: `["sentry","beacon"]`,
			},
			want: "telemetry",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Util", Path: "src/analytics/x.go",
				SymbolsJSON: `["beacon"]`,
			},
			want: "telemetry",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := component.Apply(tc.mod)
			if result.Component != tc.want {
				t.Fatalf("Component = %q, want %q (evidence=%q)", result.Component, tc.want, result.Evidence)
			}
			if result.Classifier != "rule" {
				t.Fatalf("Classifier = %q, want rule", result.Classifier)
			}
		})
	}
}
