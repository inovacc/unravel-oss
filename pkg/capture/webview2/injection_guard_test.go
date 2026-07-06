//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"testing"
)

// ---------------------------------------------------------------------------
// W5 — validateProcessName
// ---------------------------------------------------------------------------

func TestValidateProcessName_RejectsMalicious(t *testing.T) {
	bad := []string{
		"",
		"proc ess",              // space
		`proc"ess`,              // double-quote closes /FI filter context
		"proc'ess",              // single-quote
		"proc&ess",              // shell metachar (belt-and-braces)
		"IMAGENAME eq injected", // second /FI injection attempt
		"proc\x00ess",           // null byte
		"proc\ness",             // newline
	}
	for _, name := range bad {
		t.Run("reject_"+name, func(t *testing.T) {
			if err := validateProcessName(name); err == nil {
				t.Errorf("validateProcessName(%q): expected error, got nil", name)
			}
		})
	}
}

func TestValidateProcessName_AcceptsValid(t *testing.T) {
	good := []string{
		"notepad.exe",
		"WhatsApp.exe",
		"my-app_v2.exe",
		"Teams",
	}
	for _, name := range good {
		t.Run(name, func(t *testing.T) {
			if err := validateProcessName(name); err != nil {
				t.Errorf("validateProcessName(%q): unexpected error: %v", name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// W5 — validatePkgName
// ---------------------------------------------------------------------------

func TestValidatePkgName_RejectsMalicious(t *testing.T) {
	bad := []string{
		"",
		"Foo' | Invoke-Expression (Get-Content C:\\secret.txt) #",
		"Pkg$(calc.exe)",
		"Pkg`$(calc.exe)`",
		"pkg name",    // space
		"pkg\x00name", // null byte
		"pkg\nname",   // newline
	}
	for _, name := range bad {
		t.Run("reject", func(t *testing.T) {
			if err := validatePkgName(name); err == nil {
				t.Errorf("validatePkgName(%q): expected error, got nil", name)
			}
		})
	}
}

func TestValidatePkgName_AcceptsValid(t *testing.T) {
	good := []string{
		"Microsoft.WhatsAppDesktop_8wekyb3d8bbwe",
		"Microsoft.Teams_8wekyb3d8bbwe",
		"Contoso.App-v2.0_xyz123",
	}
	for _, name := range good {
		t.Run(name, func(t *testing.T) {
			if err := validatePkgName(name); err != nil {
				t.Errorf("validatePkgName(%q): unexpected error: %v", name, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// W5 — psSingleQuoteEscape hardening
// ---------------------------------------------------------------------------

func TestPsSingleQuoteEscape_HardensBacktick(t *testing.T) {
	// A backtick in the input must be escaped so PS -Command cannot interpret
	// `$(...) subexpressions even inside a nominally single-quoted context.
	input := "Foo`$(calc.exe)`Bar"
	got := psSingleQuoteEscape(input)
	want := "Foo``$(calc.exe)``Bar"
	if got != want {
		t.Errorf("psSingleQuoteEscape(%q) = %q; want %q", input, got, want)
	}
}

func TestPsSingleQuoteEscape_DoublesSingleQuote(t *testing.T) {
	input := "O'Reilly's"
	got := psSingleQuoteEscape(input)
	want := "O''Reilly''s"
	if got != want {
		t.Errorf("psSingleQuoteEscape(%q) = %q; want %q", input, got, want)
	}
}

func TestPsSingleQuoteEscape_StripsNullByte(t *testing.T) {
	input := "pkg\x00name"
	got := psSingleQuoteEscape(input)
	want := "pkgname"
	if got != want {
		t.Errorf("psSingleQuoteEscape(%q) = %q; want %q", input, got, want)
	}
}

func TestPsSingleQuoteEscape_CombinedInjectionAttempt(t *testing.T) {
	// Simulate a malicious MSIX manifest package family name.
	input := "Foo' | Invoke-Expression (Get-Content C:\\secret.txt) #"
	got := psSingleQuoteEscape(input)
	// Single quotes must be doubled; no backtick in this input.
	wantContains := "''"
	if len(got) == 0 {
		t.Fatal("empty result")
	}
	// The doubled single-quote must appear where the original ' was.
	if got[3] != '\'' || got[4] != '\'' {
		t.Errorf("expected '' at positions 3-4; got %q", got)
	}
	_ = wantContains
}
