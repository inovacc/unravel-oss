/*
Copyright (c) 2026 Security Research
*/
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScan_GoodTreeHasNoViolations(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "good"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	v, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(v) != 0 {
		t.Fatalf("want 0 violations, got %d: %+v", len(v), v)
	}
}

func TestScan_BadTreeReportsViolation(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "bad"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	v, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(v) != 1 {
		t.Fatalf("want 1 violation, got %d: %+v", len(v), v)
	}
	got := v[0]
	if got.file != "pkg/offender/bad.go" {
		t.Errorf("file=%q want pkg/offender/bad.go", got.file)
	}
	if got.imp != "github.com/anthropics/anthropic-sdk-go/option" {
		t.Errorf("imp=%q want anthropic-sdk-go/option", got.imp)
	}
	if got.line <= 0 {
		t.Errorf("line=%d want > 0", got.line)
	}
}

// TestScan_TranspileDenyFires asserts the explicit pkg/transpile deny entry
// (TRANSPILE-PHASE2-GAPS) catches a forbidden SDK import under pkg/transpile
// and surfaces a DISTINCT, self-explaining message rather than the generic
// forbidden-import line. Proves the named deny is real, not incidental.
func TestScan_TranspileDenyFires(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "transpile_deny"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	v, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(v) != 1 {
		t.Fatalf("want 1 violation, got %d: %+v", len(v), v)
	}
	got := v[0]
	if got.file != "pkg/transpile/converter/offender.go" {
		t.Errorf("file=%q want pkg/transpile/converter/offender.go", got.file)
	}
	if !strings.Contains(got.imp, "github.com/anthropics/anthropic-sdk-go") {
		t.Errorf("imp=%q want it to name the SDK import", got.imp)
	}
	if !strings.Contains(got.imp, "pkg/transpile must not import the Anthropic SDK (D-09)") {
		t.Errorf("imp=%q want the distinct pkg/transpile deny message", got.imp)
	}
}

// TestMatchExplicitDeny pins the named deny-subtree matcher: pkg/transpile is
// denied, the two SDK-allowed dirs are not.
func TestMatchExplicitDeny(t *testing.T) {
	cases := map[string]bool{
		"pkg/transpile/converter/x.go": true,
		"pkg/transpile/x.go":           true,
		"pkg/transpiler/x.go":          false, // must match the slash-terminated prefix only
		"internal/ai/foo.go":           false,
		"pkg/offender/bad.go":          false,
	}
	for path, want := range cases {
		if _, got := matchExplicitDeny(path); got != want {
			t.Errorf("matchExplicitDeny(%q)=%v want %v", path, got, want)
		}
	}
}

func TestIsAllowed(t *testing.T) {
	cases := map[string]bool{
		"internal/ai/foo.go":        true,
		"internal/mcp/sampling.go":  true,
		"internal/server/server.go": false,
		"pkg/forensic/x.go":         false,
		"cmd/mcp.go":                false,
	}
	for path, want := range cases {
		if got := isAllowed(path, allowedDirs); got != want {
			t.Errorf("isAllowed(%q)=%v want %v", path, got, want)
		}
	}
}

func TestIsForbidden(t *testing.T) {
	cases := map[string]bool{
		"github.com/anthropics/anthropic-sdk-go":           true,
		"github.com/anthropics/anthropic-sdk-go/option":    true,
		"github.com/anthropics/anthropic-sdk-go/v2/things": true,
		"github.com/spf13/cobra":                           false,
		"context":                                          false,
	}
	for imp, want := range cases {
		if got := isForbidden(imp); got != want {
			t.Errorf("isForbidden(%q)=%v want %v", imp, got, want)
		}
	}
}
