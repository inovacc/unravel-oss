/* Copyright (c) 2026 Security Research */
package risk

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestCalculate(t *testing.T) {
	weights := map[string]int{
		"CRITICAL": 40,
		"HIGH":     20,
		"MEDIUM":   10,
		"LOW":      2,
	}

	tests := []struct {
		name         string
		security     []string
		stealth      []string
		ipc          []string
		wantLevel    string
		wantMinScore int
		wantMaxScore int
	}{
		{
			name:      "empty risks returns LOW",
			wantLevel: "LOW",
		},
		{
			name:         "score >= 100 returns CRITICAL",
			security:     []string{"CRITICAL", "CRITICAL", "HIGH"},
			wantLevel:    "CRITICAL",
			wantMinScore: 100,
		},
		{
			name:         "score >= 50 returns HIGH",
			security:     []string{"CRITICAL"},
			stealth:      []string{"HIGH"},
			wantLevel:    "HIGH",
			wantMinScore: 50,
			wantMaxScore: 99,
		},
		{
			name:         "score >= 20 returns MEDIUM",
			security:     []string{"HIGH"},
			wantLevel:    "MEDIUM",
			wantMinScore: 20,
			wantMaxScore: 49,
		},
		{
			name:         "score < 20 returns LOW",
			security:     []string{"LOW"},
			wantLevel:    "LOW",
			wantMaxScore: 19,
		},
		{
			name:         "combined risks from all categories",
			security:     []string{"CRITICAL"},
			stealth:      []string{"CRITICAL"},
			ipc:          []string{"CRITICAL"},
			wantLevel:    "CRITICAL",
			wantMinScore: 120,
		},
		{
			name:      "unknown weight key ignored",
			security:  []string{"UNKNOWN"},
			wantLevel: "LOW",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Calculate(weights, tt.security, tt.stealth, tt.ipc)

			if got.Level != tt.wantLevel {
				t.Errorf("Level = %q, want %q", got.Level, tt.wantLevel)
			}

			if tt.wantMinScore > 0 && got.Value < tt.wantMinScore {
				t.Errorf("Value = %d, want >= %d", got.Value, tt.wantMinScore)
			}

			if tt.wantMaxScore > 0 && got.Value > tt.wantMaxScore {
				t.Errorf("Value = %d, want <= %d", got.Value, tt.wantMaxScore)
			}
		})
	}
}

func TestCalculateFromManifest(t *testing.T) {
	m := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20},
		},
	}

	got := CalculateFromManifest(m, []string{"HIGH"}, nil, nil)
	if got.Value != 20 {
		t.Errorf("Value = %d, want 20", got.Value)
	}
	if got.Level != "MEDIUM" {
		t.Errorf("Level = %q, want MEDIUM", got.Level)
	}
}
