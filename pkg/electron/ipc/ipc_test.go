/* Copyright (c) 2026 Security Research */
package ipc

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestFind(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		pattern   manifest.IPCPattern
		dangerous []manifest.DangerousKeyword
		wantLen   int
		wantFirst *Finding
	}{
		{
			name:    "finds IPC channels with capture groups",
			content: `ipcMain.handle("get-data", handler); ipcMain.handle("set-config", handler2);`,
			pattern: manifest.IPCPattern{
				Pattern:      `ipcMain\.handle\s*\(\s*"([^"]+)"`,
				Direction:    "main",
				CaptureGroup: 1,
			},
			wantLen:   2,
			wantFirst: &Finding{Channel: "get-data", Direction: "main", Risk: "LOW"},
		},
		{
			name:    "deduplicates channels",
			content: `ipcMain.handle("get-data", h1); ipcMain.handle("get-data", h2);`,
			pattern: manifest.IPCPattern{
				Pattern:      `ipcMain\.handle\s*\(\s*"([^"]+)"`,
				Direction:    "main",
				CaptureGroup: 1,
			},
			wantLen: 1,
		},
		{
			name:    "marks dangerous keywords",
			content: `ipcMain.handle("exec-command", handler);`,
			pattern: manifest.IPCPattern{
				Pattern:      `ipcMain\.handle\s*\(\s*"([^"]+)"`,
				Direction:    "main",
				CaptureGroup: 1,
			},
			dangerous: []manifest.DangerousKeyword{
				{Keyword: "exec", Risk: "CRITICAL"},
				{Keyword: "shell", Risk: "CRITICAL"},
			},
			wantLen:   1,
			wantFirst: &Finding{Channel: "exec-command", Direction: "main", Risk: "CRITICAL"},
		},
		{
			name:    "no matches returns empty",
			content: "no ipc here",
			pattern: manifest.IPCPattern{
				Pattern:      `ipcMain\.handle\s*\(\s*"([^"]+)"`,
				Direction:    "main",
				CaptureGroup: 1,
			},
			wantLen: 0,
		},
		{
			name:    "invalid regex returns empty",
			content: "anything",
			pattern: manifest.IPCPattern{
				Pattern:      `[invalid`,
				CaptureGroup: 1,
			},
			wantLen: 0,
		},
		{
			name:    "capture group out of bounds skipped",
			content: `ipcMain.handle("test")`,
			pattern: manifest.IPCPattern{
				Pattern:      `ipcMain\.handle\s*\(\s*"([^"]+)"`,
				Direction:    "main",
				CaptureGroup: 5,
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Find(tt.content, tt.pattern, tt.dangerous)

			if len(got) != tt.wantLen {
				t.Fatalf("len = %d, want %d; findings: %+v", len(got), tt.wantLen, got)
			}

			if tt.wantFirst != nil && len(got) > 0 {
				if got[0].Channel != tt.wantFirst.Channel {
					t.Errorf("Channel = %q, want %q", got[0].Channel, tt.wantFirst.Channel)
				}
				if got[0].Direction != tt.wantFirst.Direction {
					t.Errorf("Direction = %q, want %q", got[0].Direction, tt.wantFirst.Direction)
				}
				if got[0].Risk != tt.wantFirst.Risk {
					t.Errorf("Risk = %q, want %q", got[0].Risk, tt.wantFirst.Risk)
				}
			}
		})
	}
}
