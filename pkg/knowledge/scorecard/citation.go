/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — P58 citation type + helper.
//
// Citation pinpoints the evidence artifact a single Evidence row was derived
// from. Added in P58. Missing-kind Evidence carries no Citation by design
// (lenient rule — see citations.go::ComputeCitationsOK).
//
// JSON shape (decision 2):
//   - File: path RELATIVE to KBOutputDir, forward-slash normalized for cross-OS
//     stability. Always populated when Citation is non-nil.
//   - Line: 1-based line number; 0 (omitempty zero-value) means "whole file".
//   - Hash: optional sha256 hex prefix; never computed fresh at scoring time
//     (decision 7). Reuse cache hash where available; empty otherwise.
package scorecard

import (
	"path/filepath"
	"strings"
)

// Citation pinpoints the source artifact for a single Evidence row.
// File is path relative to the target's KBOutputDir, forward-slash normalized.
// Line=0 means "whole file" (e.g. binaries, JSON manifests).
// Hash is optional in P58; never compute fresh sha256 here (decision 7).
type Citation struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
	Hash string `json:"hash,omitempty"`
}

// newCitation constructs a *Citation whose File is path relative to
// kbOutputDir, forward-slash normalized for cross-OS byte stability.
//
// Behavior:
//   - If absPath is empty, returns nil (caller should not attach a citation).
//   - If kbOutputDir is empty or absPath is not under it, falls back to using
//     filepath.Base(absPath) as the relative path.
//   - All backslashes are converted to forward slashes (Windows safety).
//
// Hash is left empty here (decision 7) — callers populate it only from a
// pre-existing cache hash; never compute fresh sha256 at scoring time.
func newCitation(kbOutputDir, absPath string, line int) *Citation {
	if absPath == "" {
		return nil
	}
	rel := absPath
	if kbOutputDir != "" {
		if r, err := filepath.Rel(kbOutputDir, absPath); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		} else {
			rel = filepath.Base(absPath)
		}
	}
	rel = filepath.ToSlash(rel)
	if line < 0 {
		line = 0
	}
	return &Citation{File: rel, Line: line}
}
