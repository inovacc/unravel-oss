/* Copyright (c) 2026 Security Research */
package stealth

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		pattern      manifest.StealthPattern
		wantNil      bool
		wantEvidence string
	}{
		{
			name:    "regex match returns finding with context",
			content: "some code before setContentProtection(true) and after",
			pattern: manifest.StealthPattern{
				Name:        "Content Protection",
				Description: "Hidden from screen capture",
				Patterns:    []string{`setContentProtection\s*\(\s*true`},
				Risk:        "HIGH",
			},
			wantEvidence: "setContentProtection(true)",
		},
		{
			name:    "plain string match when regex is invalid",
			content: "contains [bracket pattern here",
			pattern: manifest.StealthPattern{
				Name:        "Bracket Test",
				Description: "test",
				Patterns:    []string{"[bracket"},
				Risk:        "MEDIUM",
			},
			wantEvidence: "[bracket",
		},
		{
			name:    "no match returns nil",
			content: "nothing interesting here",
			pattern: manifest.StealthPattern{
				Name:     "Content Protection",
				Patterns: []string{`setContentProtection\s*\(\s*true`},
				Risk:     "HIGH",
			},
			wantNil: true,
		},
		{
			name:    "invalid regex and no string match returns nil",
			content: "nothing here",
			pattern: manifest.StealthPattern{
				Name:     "Test",
				Patterns: []string{"[nomatch"},
				Risk:     "LOW",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.content, tt.pattern)

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}

			if got == nil {
				t.Fatal("expected finding, got nil")
			}

			if got.Name != tt.pattern.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.pattern.Name)
			}

			if got.Risk != tt.pattern.Risk {
				t.Errorf("Risk = %q, want %q", got.Risk, tt.pattern.Risk)
			}

			if !strings.Contains(got.Evidence, tt.wantEvidence) {
				t.Errorf("Evidence = %q, want to contain %q", got.Evidence, tt.wantEvidence)
			}
		})
	}
}
