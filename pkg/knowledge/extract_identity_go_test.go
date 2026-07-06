/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/garble"
)

func TestExtractIdentityGoBinary(t *testing.T) {
	tests := []struct {
		name        string
		info        *garble.BinaryInfo
		path        string
		wantPlat    string
		wantPackage string
	}{
		{
			name:        "module path present",
			info:        &garble.BinaryInfo{HasBuildInfo: true, GoVersion: "go1.27", OS: "linux", ModulePath: "github.com/acme/tool"},
			path:        "/x/tool",
			wantPlat:    "linux-elf",
			wantPackage: "github.com/acme/tool",
		},
		{
			name:        "stripped module -> binary name fallback (windows)",
			info:        &garble.BinaryInfo{HasBuildInfo: true, GoVersion: "go1.27", OS: "windows"},
			path:        `C:\x\agy.exe`,
			wantPlat:    "windows-pe",
			wantPackage: "agy",
		},
		{
			name:        "command-line-arguments is not a real module",
			info:        &garble.BinaryInfo{GoVersion: "go1.27", OS: "darwin", ModulePath: "command-line-arguments"},
			path:        "/x/agy",
			wantPlat:    "macos",
			wantPackage: "agy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &dissect.DissectResult{Path: tt.path, GarbleInfo: tt.info}
			plat, pkg, disp, _ := extractIdentity(r)
			if plat != tt.wantPlat {
				t.Errorf("platform = %q, want %q", plat, tt.wantPlat)
			}
			if pkg != tt.wantPackage {
				t.Errorf("packageID = %q, want %q", pkg, tt.wantPackage)
			}
			if disp != tt.wantPackage {
				t.Errorf("displayName = %q, want %q", disp, tt.wantPackage)
			}
		})
	}
}

func TestExtractIdentityNonGoStillEmpty(t *testing.T) {
	// A bare result with no recognizable identity source must still yield empty.
	r := &dissect.DissectResult{Path: "/x/mystery.bin"}
	if plat, pkg, _, _ := extractIdentity(r); plat != "" || pkg != "" {
		t.Errorf("expected empty identity, got platform=%q package=%q", plat, pkg)
	}
}
