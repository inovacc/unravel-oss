/*
Copyright (c) 2026 Security Research
*/

// Package license tests license validation endpoints for common bypass vulnerabilities.
//
// It probes API endpoints with empty keys, malformed formats, replay attacks,
// and timing analysis to identify weaknesses in license enforcement.
//
// Entry points:
//   - RunTests: run all license bypass tests against a target URL
//   - AnalyzeMachineIDs: enumerate machine ID sources used for hardware binding
package license
