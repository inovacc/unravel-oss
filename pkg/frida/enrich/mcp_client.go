/*
Copyright (c) 2026 Security Research
*/
package enrich

import (
	"context"
	"errors"
)

// EnrichResponse is the structured JSON shape the AI is asked to return
// (Phase 9 D-17). One entry per Interceptor.attach hook plus a top-level
// header summary.
type EnrichResponse struct {
	HeaderSummary string           `json:"header_summary"`
	Hooks         []HookEnrichment `json:"hooks"`
}

// HookEnrichment is the per-hook enrichment payload. The `Expected` block
// is consumed verbatim into criteria.json; the prose fields drive JSDoc.
type HookEnrichment struct {
	ID           string   `json:"id"`
	Summary      string   `json:"summary"`
	WhyItMatters string   `json:"why_it_matters"`
	WatchFor     string   `json:"watch_for"`
	Expected     Expected `json:"expected"`
}

// Expected is the criteria-shaped sub-object: each field maps 1:1 to the
// Criterion list emitted into <script>.criteria.json (D-07, D-09).
type Expected struct {
	Args             []ExpectedArg     `json:"args,omitempty"`
	Return           *ExpectedValue    `json:"return,omitempty"`
	CallCount        *FrequencyBound   `json:"call_count,omitempty"`
	ValueConstraints []ValueConstraint `json:"value_constraints,omitempty"`
}

// ExpectedArg is one positional argument constraint.
type ExpectedArg struct {
	Index   int      `json:"index"`
	Op      string   `json:"op"`
	Value   any      `json:"value,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// ExpectedValue is a single value constraint (return shape).
type ExpectedValue struct {
	Op      string   `json:"op"`
	Value   any      `json:"value,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// FrequencyBound is the call-count constraint shape.
type FrequencyBound struct {
	Min *float64 `json:"min,omitempty"`
	Max *float64 `json:"max,omitempty"`
}

// ValueConstraint is a free-form rule attached to args/return path expressions.
type ValueConstraint struct {
	Target  string   `json:"target"`
	Op      string   `json:"op"`
	Value   any      `json:"value,omitempty"`
	Pattern string   `json:"pattern,omitempty"`
	Min     *float64 `json:"min,omitempty"`
	Max     *float64 `json:"max,omitempty"`
}

// MCPClient is the package-local interface; mirrors migrate.MCPClient.
// The cmd/ wiring supplies a real implementation; tests pass a stub.
type MCPClient interface {
	EnrichScript(ctx context.Context, prompt string) (EnrichResponse, error)
}

// nilClient is the zero-value MCPClient. Always errors. Allows callers to
// construct an Orchestrator without a wired client and surface a sensible
// error instead of a nil-pointer panic.
type nilClient struct{}

// EnrichScript implements MCPClient.
func (nilClient) EnrichScript(_ context.Context, _ string) (EnrichResponse, error) {
	return EnrichResponse{}, errors.New("enrich: no MCP client wired (use --ai with a configured backend)")
}

// NilMCPClient returns the zero-value MCPClient (always errors). Mirrors
// pkg/forensic.NilMCPClient so internal/mcp adapters have a uniform shape.
func NilMCPClient() MCPClient { return nilClient{} }
