/*
Copyright (c) 2026 Security Research
*/
package inject

// scanners is the global registry populated via init() side effects in
// per-framework subpackages (mirrors pkg/knowledge/registry/dep_extractors.go).
var scanners []Scanner

// RegisterScanner appends s to the global registry. Called from per-framework
// package init() functions.
func RegisterScanner(s Scanner) { scanners = append(scanners, s) }

// Scanners returns a copy-by-slice of all registered scanners.
func Scanners() []Scanner { return scanners }

// resetScannersForTest clears the registry. Test-only helper used by
// inject_test.go to isolate registration state across cases.
func resetScannersForTest() { scanners = nil }
