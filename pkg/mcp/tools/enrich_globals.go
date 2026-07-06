/*
Copyright (c) 2026 Security Research
*/

// Package mcptools / enrich_globals.go owns the cross-tool concurrency
// primitives + model allowlist for KB enrichment. Shared between the
// retry tool and any future enrich orchestrator. The legacy
// sampling-only enrich tool (broken under Claude Code's MCP client)
// was removed 2026-05-23; these primitives stayed because the retry
// path still uses them.
package mcptools

// enrichGlobalSem serializes server-wide enrich invocations to prevent
// runaway concurrent LLM fanout. Capacity 1 = strict serialization;
// acquire is ctx-cancellable at the call site.
var enrichGlobalSem = make(chan struct{}, 1)

// hardMaxConcurrent caps the per-call internal worker fanout regardless
// of what the caller asks for. 16 = 2× the Phase A winning recipe
// (conc=8), leaving headroom for tuning without runaway parallelism.
const hardMaxConcurrent = 16

// validModels lists accepted model alias values for KB enrichment.
// Locked to Haiku 4.5 and Sonnet 4.6 — Opus is intentionally NOT
// supported for enrichment (cost/throughput unjustified vs measured
// Haiku quality per docs/KB-CONSUMPTION-CALIBRATION.md Phase A).
var validModels = []string{"haiku", "sonnet"}
