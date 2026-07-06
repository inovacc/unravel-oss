/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

func TestSeamID_Deterministic(t *testing.T) {
	a := seamID("linux", "/lib/x.so", "DT_NEEDED")
	b := seamID("linux", "/lib/x.so", "DT_NEEDED")
	if a != b {
		t.Errorf("seamID not deterministic: %s != %s", a, b)
	}
	if len(a) != 8 {
		t.Errorf("seamID len = %d; want 8", len(a))
	}
}

func TestSeamID_DifferentInputsDiffer(t *testing.T) {
	a := seamID("linux", "/lib/x.so", "DT_NEEDED")
	b := seamID("linux", "/lib/y.so", "DT_NEEDED")
	if a == b {
		t.Error("seamID collision on different inputs")
	}
}

func TestDerivePlatform(t *testing.T) {
	yes := true
	tests := []struct {
		name string
		seam inject.Seam
		want string
	}{
		{"electron->windows", inject.Seam{Framework: inject.FrameworkElectron}, "windows"},
		{"tauri->windows", inject.Seam{Framework: inject.FrameworkTauri}, "windows"},
		{"webview2->windows", inject.Seam{Framework: inject.FrameworkWebView2}, "windows"},
		{"macos->macos", inject.Seam{Framework: inject.FrameworkMacOS}, "macos"},
		{"ptrace-set->linux", inject.Seam{PtraceEligibleBinary: &yes}, "linux"},
		{"ptrace-flags->linux", inject.Seam{PtraceFlags: []string{"non_pie"}}, "linux"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := derivePlatform(tt.seam)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q; want %q", got, tt.want)
			}
		})
	}
}
