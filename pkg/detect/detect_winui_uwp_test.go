/*
Copyright (c) 2026 Security Research
*/

package detect

import "testing"

func TestTypeWinUIAppRegistered(t *testing.T) {
	if string(TypeWinUIApp) != "WinUI App" {
		t.Errorf("TypeWinUIApp = %q, want %q", TypeWinUIApp, "WinUI App")
	}
}

func TestTypeUWPAppRegistered(t *testing.T) {
	if string(TypeUWPApp) != "UWP App" {
		t.Errorf("TypeUWPApp = %q, want %q", TypeUWPApp, "UWP App")
	}
}
