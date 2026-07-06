/*
Copyright (c) 2026 Security Research

Phase 45 / LLMC-03 negative test for the D-09 CI guard.

Locks the wire-level contract: when a Go file outside any allowlisted
directory imports the forbidden Anthropic SDK at the top level, the
scanner MUST emit a violation with (a) repo-relative slash-style path,
(b) a non-zero source line, (c) the exact import string, and the
process MUST be the kind that exits with code 1.

We exercise the in-process scan() directly here; the exit-1 invariant
is also asserted in CI by `task d09:check` running on the same tree
plus a temporary symlink to this fixture (see 45-VERIFICATION.md).
*/
package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestScan_ViolationFixture_ProducesPreciseStderrLine asserts the scanner
// pinpoints the exact file/line/import for a forbidden import in a
// non-allowlisted package. Mirrors what an operator sees on stderr when
// `task d09:check` exits 1.
func TestScan_ViolationFixture_ProducesPreciseStderrLine(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("testdata", "violation"))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	violations, err := scan(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("want exactly 1 violation, got %d: %+v", len(violations), violations)
	}

	v := violations[0]
	if v.file != "pkg/offender/violation.go" {
		t.Errorf("file=%q want pkg/offender/violation.go", v.file)
	}
	if v.imp != "github.com/anthropics/anthropic-sdk-go" {
		t.Errorf("imp=%q want exact root SDK path", v.imp)
	}
	if v.line <= 0 {
		t.Errorf("line=%d want > 0 (precise stderr requires real source line)", v.line)
	}
	// Path must be slash-style, never backslashed — CI runs on linux but
	// devs on windows; reports must be stable across both.
	if strings.Contains(v.file, "\\") {
		t.Errorf("file path %q contains backslash; want forward-slash", v.file)
	}
}

// TestScan_ViolationFixture_NotMaskedByAllowlistPrefix guards against a
// future refactor accidentally adding "internal/" or "pkg/" to allowedDirs
// (which would turn this fixture green and silently retire D-09).
func TestScan_ViolationFixture_NotMaskedByAllowlistPrefix(t *testing.T) {
	if isAllowed("pkg/offender/violation.go", allowedDirs) {
		t.Fatal("pkg/offender/violation.go must NOT be allowlisted; D-09 regression risk")
	}
}
