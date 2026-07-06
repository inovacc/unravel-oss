// Copyright (c) 2026 Unravel Authors. All rights reserved.

// Package audit provides internal milestone-artifact verification gates.
//
// Tests in this package assert that planning artifacts referenced by completed
// milestone audits (e.g. AUDIT-v2.3.md §5d) carry real evidence rather than
// stubs. The current scope is limited to the v2.3 artifact inventory (REQ
// ART-CLEAN-01, Phase 28). Future milestones may extend the inventory.
//
// The package exposes no public API. All checks live in *_test.go files and
// run under `-short` so they are part of the default test suite.
package audit
