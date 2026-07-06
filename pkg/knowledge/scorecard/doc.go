/*
Copyright (c) 2026 Security Research
*/

// Package scorecard ports the WhatsApp clean-room W-## scorecard rubric into
// pure Go. It exposes 12 per-dimension Scorers (canonical IDs in dims.go) that
// each consume a *dissect.DissectResult plus *analysis.ResultSet and produce
// an integer 0-100 DimScore with evidence pointers.
//
// Scope (P56): W-00..W-11 baseline curves only. W-12/W-13/W-14 deepening
// adders, the iteration loop, citation extraction, SCORECARD.md emission, and
// validation re-runs are owned by P57-P60.
//
// Pattern: each scorer self-registers via init() (mirrors pkg/inject/registry.go:12
// and pkg/dissect/analyze_*.go). The Rubric orchestrator iterates registered
// scorers in the canonical order from dims.go, regardless of init link order.
//
// Invariants:
//   - RUBR-01: Rubric.Score returns 12 DimScore entries with int 0-100 scores.
//   - RUBR-02: per-scorer init() registration; no central switch.
//   - RUBR-03: WhatsApp parity within +/-5% of the W-11 baseline snapshot.
//   - RUBR-04: integer scores only; no floating-point types anywhere in
//     package source (CI grep gate).
//   - D-09:    no anthropic-sdk-go imports anywhere in this package.
//   - D-10:    Scorecard is a return value, never a field of DissectResult.
//
// Runtime-gap dims (ipc, wire, auth, state_machines, behavior) score honestly
// from static evidence (may be 0) and always emit Evidence{Kind:"missing",
// Source:"runtime", Detail:"no runtime capture (P57)"} when runtime data is
// absent. P57's deepening loop reads that marker to know which dim to invest
// in.
package scorecard
