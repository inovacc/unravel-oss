/*
Copyright (c) 2026 Security Research
*/

// Package decompile provides the FRM-04 ilspycmd shell-out, assembly walker,
// and bounded-parallel orchestrator for .NET assembly decompilation.
//
// Prerequisite: ilspycmd must be on PATH. Install via:
//
//	dotnet tool install -g ilspycmd
//
// Discovery is via exec.LookPath; a missing binary fails loudly with the
// install command in the error message (D-01 / D-03). No vendoring, no
// silent fallback, no degrade-and-continue.
//
// D-07 supplemental wiring note: Plan 05-03 registers a supplemental
// analyzer on detect.TypePE that uses IsManagedPE as a cheap pre-check.
// Non-managed PE binaries are a no-op. No new FileType is added.
//
// COST WARNING: When this package is invoked from the dissect supplemental
// on TypePE, every managed PE encountered triggers a full ilspycmd + (later)
// AI pipeline run. Operators batch-dissecting 100+ apps should expect
// proportional ilspycmd subprocess and (when --beautify) AI token spend.
// Per D-07 user resolution: full decompile by default; no flag-only mode.
package decompile
