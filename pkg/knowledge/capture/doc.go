/*
Copyright (c) 2026 Security Research
*/

// Package capture orchestrates the optional live-overlay pass for
// `unravel knowledge`. Per Phase 23 D-05..07, v2.4 ships a fixed CDP
// capture batch (no scenario scripting). The orchestrator launches the
// target via pkg/capture/launch, connects via pkg/capture/cdp, executes
// the fixed batch, and returns a Result.
//
// Process lifecycle is owned by pkg/sandbox helpers (D-13: defer-kill
// on every return path). Failures are non-fatal at the call site
// (D-14): the caller falls back to static-only output and writes a
// WARN line to stderr.
package capture
