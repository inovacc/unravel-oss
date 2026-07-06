/*
Copyright (c) 2026 Security Research

MCP delegation seam for the LLM classifier path (Phase 45 / LLMC-01).

This file declares ClassifyMCPClient — the consumer-facing interface that
internal/mcp ships an adapter for — and a NilClassifyMCPClient helper used
by the lazy resolver when no MCP session is wired (D-13: graceful-degrade
preserves existing rule/heuristic semantics).

Plan 45-01 lands the surface only. The wiring of ClassifyClient into
classify.Run, prompt construction, response parsing, and migration of
module_components.prompt_version are all deferred to plan 45-02.
*/
package classify

import "context"

// ClassifyMCPClient is the narrow seam classify.Run will eventually call to
// ask the host LLM (via MCP sampling/createMessage) to classify a module
// when rule + heuristic verdicts are insufficient.
//
// Implementations MUST:
//   - Treat ctx cancellation as authoritative (no internal retries that
//     outlive the parent context).
//   - Return ([]byte, nil) on a well-formed response and (nil, err) on any
//     failure; callers degrade gracefully on error per D-06.
type ClassifyMCPClient interface {
	// ClassifyModule submits prompt to the MCP host and returns the raw
	// response bytes. The bytes are expected to be UTF-8 JSON; parsing is
	// the caller's responsibility (deferred to 45-02).
	ClassifyModule(ctx context.Context, prompt string) ([]byte, error)
}

// nilClassifyMCPClient is the zero-impact fallback used when no MCP session
// is wired (e.g. running outside `unravel mcp serve`, or the host did not
// advertise sampling capability).
type nilClassifyMCPClient struct{}

// ClassifyModule satisfies ClassifyMCPClient by returning (nil, nil) so
// callers detect "no LLM available" via empty body, identical to the
// pattern used by forensic.NilMCPClient / enrich.NilMCPClient.
func (nilClassifyMCPClient) ClassifyModule(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

// NilClassifyMCPClient returns a no-op ClassifyMCPClient. The lazy resolver
// in internal/mcp.ClassifyClient falls back to this when the daemon hasn't
// wired a session, preserving D-13 graceful-degrade semantics.
func NilClassifyMCPClient() ClassifyMCPClient { return nilClassifyMCPClient{} }
