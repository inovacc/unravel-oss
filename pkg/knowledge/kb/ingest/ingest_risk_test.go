/*
Copyright (c) 2026 Security Research
*/

package ingest

import "testing"

func intp(v int) *int { return &v }

func TestCanonicalizeRisk(t *testing.T) {
	tests := []struct {
		name      string
		input     map[string]any
		wantScore *int
		wantLevel string
	}{
		{
			name: "uwp explicit level",
			input: map[string]any{
				"uwp_analyze": map[string]any{
					"score": map[string]any{
						"value": 72,
						"level": "high",
					},
				},
			},
			wantScore: intp(72),
			wantLevel: "high",
		},
		{
			name: "electron security risk_score+level",
			input: map[string]any{
				"security": map[string]any{
					"risk_score": 45,
					"risk_level": "medium",
				},
			},
			wantScore: intp(45),
			wantLevel: "medium",
		},
		{
			name: "android security_score derives level",
			input: map[string]any{
				"android_manifest": map[string]any{
					"security_score": 80,
				},
			},
			wantScore: intp(80),
			wantLevel: "critical",
		},
		{
			name: "android low score",
			input: map[string]any{
				"android_manifest": map[string]any{
					"security_score": 10,
				},
			},
			wantScore: intp(10),
			wantLevel: "low",
		},
		{
			name: "tauri no risk fields → unknown (not low)",
			input: map[string]any{
				"tauri": map[string]any{
					"version": "2.8.2",
				},
			},
			wantScore: nil,
			wantLevel: "unknown",
		},
		{
			name:      "empty knowledge.json → unknown",
			input:     map[string]any{},
			wantScore: nil,
			wantLevel: "unknown",
		},
		{
			name:      "nil map → unknown",
			input:     nil,
			wantScore: nil,
			wantLevel: "unknown",
		},
		{
			name: "json-unmarshalled float64 score",
			input: map[string]any{
				"uwp_analyze": map[string]any{
					"score": map[string]any{
						"value": float64(60),
						"level": "high",
					},
				},
			},
			wantScore: intp(60),
			wantLevel: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScore, gotLevel := CanonicalizeRisk(tt.input)
			if (gotScore == nil) != (tt.wantScore == nil) {
				t.Fatalf("score nil mismatch: got=%v want=%v", gotScore, tt.wantScore)
			}
			if gotScore != nil && *gotScore != *tt.wantScore {
				t.Errorf("score: got=%d want=%d", *gotScore, *tt.wantScore)
			}
			if gotLevel != tt.wantLevel {
				t.Errorf("level: got=%q want=%q", gotLevel, tt.wantLevel)
			}
		})
	}
}

func TestLevelFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "low"},
		{24, "low"},
		{25, "medium"},
		{49, "medium"},
		{50, "high"},
		{74, "high"},
		{75, "critical"},
		{100, "critical"},
		{150, "critical"},
	}
	for _, c := range cases {
		if got := levelFromScore(c.score); got != c.want {
			t.Errorf("levelFromScore(%d)=%q want=%q", c.score, got, c.want)
		}
	}
}
