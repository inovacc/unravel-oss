/*
Copyright (c) 2026 Security Research

Adapters that satisfy pkg/forensic.MCPClient and pkg/frida/enrich.MCPClient
without leaking the internal/mcp surface. Lazy resolvers fall back to the
consumer's existing NilMCPClient when the daemon hasn't wired a session
(D-13: graceful-degrade preserved).

The primitive Sample/SetSession/HasSession functions live in pkg/mcp (reusable
library). This file contains only the domain-specific adapters and resolvers
that cannot move to pkg/mcp without creating import cycles.
*/
package mcp

import (
	"context"
	"encoding/json"
	"log/slog"

	pkgmcp "github.com/inovacc/unravel-oss/pkg/mcp"

	"github.com/inovacc/unravel-oss/pkg/forensic"
	"github.com/inovacc/unravel-oss/pkg/frida/enrich"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/llm"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/adapt"
)

// forensicAdapter satisfies forensic.MCPClient via pkgmcp.Sample().
type forensicAdapter struct{}

// Summarize implements forensic.MCPClient.
func (forensicAdapter) Summarize(ctx context.Context, prompt string) ([]byte, error) {
	return pkgmcp.Sample(ctx, prompt)
}

// ForensicClient is the lazy resolver for pkg/mcptools/forensic.go (D-13).
// Returns the production adapter when SetSession was called with non-nil;
// otherwise returns forensic.NilMCPClient() so callers degrade gracefully.
func ForensicClient() forensic.MCPClient {
	if !pkgmcp.HasSession() {
		return forensic.NilMCPClient()
	}
	return forensicAdapter{}
}

// fridaAdapter satisfies enrich.MCPClient via pkgmcp.Sample() + json.Unmarshal.
type fridaAdapter struct{}

// EnrichScript implements enrich.MCPClient.
func (fridaAdapter) EnrichScript(ctx context.Context, prompt string) (enrich.EnrichResponse, error) {
	body, err := pkgmcp.Sample(ctx, prompt)
	if err != nil {
		return enrich.EnrichResponse{}, err
	}
	var out enrich.EnrichResponse
	if err := json.Unmarshal(body, &out); err != nil {
		// D-06: pkgmcp.Sample() already logged transport-level failures. Here
		// we log the parse failure, which is unique to the frida adapter.
		slog.Default().Warn("sampling/createMessage: malformed EnrichResponse JSON", "error", err)
		return enrich.EnrichResponse{}, err
	}
	return out, nil
}

// FridaClient is the lazy resolver for pkg/mcptools/frida_phase9.go (D-13).
// Returns the production adapter when SetSession was called with non-nil;
// otherwise returns enrich.NilMCPClient() so callers degrade gracefully.
func FridaClient() enrich.MCPClient {
	if !pkgmcp.HasSession() {
		return enrich.NilMCPClient()
	}
	return fridaAdapter{}
}

// classifyAdapter satisfies classify.ClassifyMCPClient via pkgmcp.Sample().
//
// D-45-CLASSIFY-NO-DIRECT-CLIENT: classify.Run never imports
// internal/mcp directly; it consumes ClassifyMCPClient and the resolver
// below decides whether to plug in this production adapter or the no-op
// fallback. See pkg/knowledge/kb/component/classify/classify_mcp.go for
// the consumer-side interface.
type classifyAdapter struct{}

// ClassifyModule implements classify.ClassifyMCPClient.
func (classifyAdapter) ClassifyModule(ctx context.Context, prompt string) ([]byte, error) {
	return pkgmcp.Sample(ctx, prompt)
}

// ClassifyClient is the lazy resolver for the LLM classifier path (D-13,
// D-45-CLASSIFY-NO-DIRECT-CLIENT). Returns the production adapter when
// SetSession was called with non-nil; otherwise returns the
// classify.NilClassifyMCPClient() so callers degrade gracefully back to
// rule/heuristic-only verdicts. Wiring into classify.Run lands in 45-02.
func ClassifyClient() classify.ClassifyMCPClient {
	if !pkgmcp.HasSession() {
		return classify.NilClassifyMCPClient()
	}
	return classifyAdapter{}
}

// enrichAdapter satisfies llm.SamplingClient via pkgmcp.Sample().
//
// KBC-SUBSCRIPTION-DRAIN-DIAG Option A: routes kbllm.Call through the
// existing MCP stdio connection (Claude Code's warm session) instead of
// spawning a fresh claude subprocess per module summary. The model parameter
// accepted by kbllm.Call is ignored on this path — Claude Code selects the
// model from its own session context, matching the pattern used by all three
// sibling adapters (forensic, frida, classify).
type enrichAdapter struct{}

// Summarize implements llm.SamplingClient.
func (enrichAdapter) Summarize(ctx context.Context, prompt string) ([]byte, error) {
	return pkgmcp.Sample(ctx, prompt)
}

// EnrichClient is the lazy resolver for the kbllm sampling path (D-13).
// Returns the production adapter when SetSession was called with non-nil;
// otherwise returns llm.NilSamplingClient() so kbllm.Call falls back to the
// subprocess path, preserving CLI/script invocation behaviour unchanged.
func EnrichClient() llm.SamplingClient {
	if !pkgmcp.HasSession() {
		return llm.NilSamplingClient()
	}
	return enrichAdapter{}
}

// transpileAdapter satisfies adapt.LLMClient via pkgmcp.Sample().
type transpileAdapter struct{}

// Convert implements adapt.LLMClient.
func (transpileAdapter) Convert(ctx context.Context, system, user string) (string, error) {
	prompt := "SYSTEM: " + system + "\n\nUSER: " + user
	body, err := pkgmcp.Sample(ctx, prompt)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// TranspileClient is the lazy resolver for the transpiler sampling path (D-13).
// Returns the production adapter when SetSession was called with non-nil;
// otherwise returns adapt.NilLLMClient() so adaptation falls back to
// deterministic-only or errors on required LLM fallbacks.
func TranspileClient() adapt.LLMClient {
	if !pkgmcp.HasSession() {
		return adapt.NilLLMClient()
	}
	return transpileAdapter{}
}
