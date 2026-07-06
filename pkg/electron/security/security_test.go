/* Copyright (c) 2026 Security Research */
package security

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestCheck(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		setting  manifest.SecuritySetting
		wantNil  bool
		wantRisk string
	}{
		{
			name:    "insecure value returns finding with risk",
			content: "nodeIntegration: true",
			setting: manifest.SecuritySetting{
				Name:           "nodeIntegration",
				SearchPatterns: []string{`nodeIntegration:\s*(true|false)`},
				InsecureValue:  "true",
				RiskIfInsecure: "CRITICAL",
				Description:    "Allows Node.js in renderer",
			},
			wantRisk: "CRITICAL",
		},
		{
			name:    "secure value returns finding with LOW risk",
			content: "nodeIntegration: false",
			setting: manifest.SecuritySetting{
				Name:           "nodeIntegration",
				SearchPatterns: []string{`nodeIntegration:\s*(true|false)`},
				InsecureValue:  "true",
				RiskIfInsecure: "CRITICAL",
				Description:    "Allows Node.js in renderer",
			},
			wantRisk: "LOW",
		},
		{
			name:    "no match returns nil",
			content: "something unrelated",
			setting: manifest.SecuritySetting{
				Name:           "nodeIntegration",
				SearchPatterns: []string{`nodeIntegration:\s*(true|false)`},
			},
			wantNil: true,
		},
		{
			name:    "invalid regex is skipped gracefully",
			content: "nodeIntegration: true",
			setting: manifest.SecuritySetting{
				Name:           "nodeIntegration",
				SearchPatterns: []string{`[invalid`, `nodeIntegration:\s*(true|false)`},
				InsecureValue:  "true",
				RiskIfInsecure: "CRITICAL",
			},
			wantRisk: "CRITICAL",
		},
		{
			name:    "all patterns invalid returns nil",
			content: "nodeIntegration: true",
			setting: manifest.SecuritySetting{
				Name:           "nodeIntegration",
				SearchPatterns: []string{`[invalid`},
			},
			wantNil: true,
		},
		{
			name:    "pattern without capture group returns nil",
			content: "nodeIntegration: true",
			setting: manifest.SecuritySetting{
				Name:           "nodeIntegration",
				SearchPatterns: []string{`nodeIntegration`},
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Check(tt.content, tt.setting)

			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}

			if got == nil {
				t.Fatal("expected finding, got nil")
			}

			if got.Risk != tt.wantRisk {
				t.Errorf("Risk = %q, want %q", got.Risk, tt.wantRisk)
			}

			if got.Name != tt.setting.Name {
				t.Errorf("Name = %q, want %q", got.Name, tt.setting.Name)
			}
		})
	}
}
