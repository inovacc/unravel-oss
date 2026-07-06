/*
Copyright (c) 2026 Security Research
*/

// Package mcptools / kb_pending_enrich.go registers the
// unravel_kb_enrich_pending + unravel_kb_enrich_write_enrichment MCP tools used by
// the unravel-enrich Claude Code skill (Understand-Anything-style fanout).
//
// Together these two tools form the I/O seam: the skill calls
// pending_enrich to fetch candidate rows, dispatches Task-spawned subagents
// to summarise each module, then calls write_enrichment per result. The
// Go binary never makes the LLM call — the parent Claude Code session does,
// reusing its warm prompt cache and the user's existing subscription.
package mcptools

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/insights"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// envFlag is a tiny helper for boolean env-var gates used by this tool.
func envFlag(name string) bool {
	v := os.Getenv(name)
	return v == "1" || v == "true" || v == "yes"
}

// KBPendingEnrichInput is the typed input for unravel_kb_enrich_pending.
type KBPendingEnrichInput struct {
	App       string `json:"app,omitempty" jsonschema:"app filter (teams, whatsapp, slack, ...); empty = all apps"`
	DB        string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	Limit     int    `json:"limit,omitempty" jsonschema:"max rows to return (default 10, hard cap 1000)"`
	NamedOnly *bool  `json:"named_only,omitempty" jsonschema:"restrict to semantic-named OR synthetic_name-backfilled modules (exclude bare hashes and teams_module_NNN placeholders). Defaults to TRUE — naive runs skip placeholders so they don't burn ~17k tokens/module (KB-OVERSEG P4). Pass false to deliberately include placeholders."`
	Force     bool   `json:"force,omitempty" jsonschema:"when true, bypass the UNRAVEL_VENDORED_SHAS skip list so vendored libraries are returned (default false)"`
	BodyCap   int    `json:"body_cap,omitempty" jsonschema:"max bytes of body_excerpt per row (default 2048; Phase A bounded-input recipe). Pass 0 for the legacy full-body shape (warning: blows tool-result token budgets at limit>=3)."`
}

// KBWriteEnrichmentInput is the typed input for unravel_kb_enrich_write_enrichment.
// parsed_json MUST be a JSON string with the shape {summary, long_summary,
// role, inputs, outputs, side_effects, deps, tags} — the contract enforced
// by the unravel-enricher subagent's response schema.
//
// KBC-ENRICH-MODEL-ESCALATION Phase 2: escalated_to + needs_human_verification
// optional fields let the subagent's retry orchestrator persist the model
// that finally succeeded (or flag the module for human review when both
// sonnet and opus exhausted retries). Both are additive — legacy callers
// that omit them keep the prior single-model semantics.
type KBWriteEnrichmentInput struct {
	ModuleID               int    `json:"module_id" jsonschema:"the id of the modules row being enriched"`
	App                    string `json:"app" jsonschema:"app the module belongs to (teams, whatsapp, ...)"`
	SHA256                 string `json:"sha256,omitempty" jsonschema:"body sha256 (echoed back from unravel_kb_enrich_pending)"`
	RawResponse            string `json:"raw_response,omitempty" jsonschema:"the subagent's full response text, persisted for audit"`
	ParsedJSON             string `json:"parsed_json" jsonschema:"the enrichment fields as a JSON string"`
	ModelUsed              string `json:"model_used,omitempty" jsonschema:"free-form model label; default 'claude-code-subagent' for the plugin path"`
	DB                     string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	EscalatedTo            string `json:"escalated_to,omitempty" jsonschema:"set to 'opus' when the surviving summary came from the opus retry path (KBC-ENRICH-MODEL-ESCALATION). Persisted to modules.escalated_to for audit."`
	NeedsHumanVerification bool   `json:"needs_human_verification,omitempty" jsonschema:"set true to flag this module for human review when both sonnet (3x) and opus retries failed. Module is then excluded from future enrichment runs until cleared via unravel_kb_enrich_human_review's mark_resolved action."`
}

func registerKBPendingEnrichTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_pending",
		Description: "Fetch JS modules that have no summary yet, ready for the unravel-enrich " +
			"Claude Code skill to enrich via Task-spawned subagents. Returns up to `limit` " +
			"rows shaped {id, app, name, sha256, body_excerpt, symbols_json}. The LLM call " +
			"happens in the Claude Code session — this tool is the read half of the " +
			"Understand-Anything-style plugin I/O seam.",
	}, handleKBPendingEnrich)

	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_write_enrichment",
		Description: "Persist a single enrichment result produced by an unravel-enricher " +
			"subagent. The skill receives the subagent's JSON, validates the shape, and " +
			"calls this tool once per module. Updates modules.summary / modules.tags and " +
			"upserts module_enrichment. Pair with unravel_kb_enrich_pending.",
	}, handleKBWriteEnrichment)
}

func handleKBPendingEnrich(ctx context.Context, _ *mcp.CallToolRequest, in KBPendingEnrichInput) (*mcp.CallToolResult, any, error) {
	defer insights.MCPCallStart("unravel_kb_enrich_pending", "")(nil)
	if in.Limit < 1 {
		in.Limit = 10
	}
	if in.Limit > 1000 {
		in.Limit = 1000
	}
	// body_cap default = 2048 bytes (Phase A bounded-input recipe).
	// A negative value collapses to default; 0 means "send full body" but
	// callers are warned via jsonschema that limit>=3 will overflow the
	// MCP tool-result token budget on most hosts.
	bodyCap := in.BodyCap
	if bodyCap < 0 {
		bodyCap = 2048
	}
	if in.BodyCap == 0 && !envFlag("UNRAVEL_ENRICH_FULL_BODY") {
		bodyCap = 2048
	}

	// named_only defaults to TRUE (KB-OVERSEG P4): an omitted field must skip
	// placeholders so naive plugin runs don't enrich teams_module_NNN / bare
	// hashes first. *bool lets us distinguish omitted (nil → true) from an
	// explicit false (deliberately include placeholders).
	namedOnly := true
	if in.NamedOnly != nil {
		namedOnly = *in.NamedOnly
	}

	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}

	resp, err := cli.Pending(ctx, supervisor.EnrichPendingParams{
		App:       in.App,
		Limit:     in.Limit,
		NamedOnly: namedOnly,
		Force:     in.Force,
	})
	if err != nil {
		return errorResult(fmt.Errorf("pending modules: %w", err)), nil, nil
	}
	rows := resp.Modules
	if rows == nil {
		rows = nil
	}

	// Truncate body excerpts to bodyCap. This drops per-row payload from
	// ~16KB to ~2KB and keeps a limit=10 response under 30KB — well below
	// the MCP tool-result spill threshold. The symbols_json + first 2KB
	// of body is the Phase A winning recipe input shape.
	if bodyCap > 0 {
		for i := range rows {
			if len(rows[i].BodyExcerpt) > bodyCap {
				rows[i].BodyExcerpt = rows[i].BodyExcerpt[:bodyCap] + "\n…[truncated]"
			}
		}
	}
	// Wrap in a top-level object so MCP-spec-strict hosts (zod validators in
	// Claude Code, Cursor, etc.) that require `structuredContent` to be a
	// record-typed JSON object accept the response. Bare arrays fail
	// validation under those hosts.
	out := map[string]any{
		"modules": rows,
		"count":   len(rows),
		"app":     in.App,
	}
	return jsonResult(out), out, nil
}

func handleKBWriteEnrichment(ctx context.Context, _ *mcp.CallToolRequest, in KBWriteEnrichmentInput) (*mcp.CallToolResult, any, error) {
	defer insights.MCPCallStart("unravel_kb_enrich_write_enrichment", "")(nil)
	if in.ModuleID == 0 {
		return errorResult(fmt.Errorf("module_id is required")), nil, nil
	}
	if in.App == "" {
		return errorResult(fmt.Errorf("app is required")), nil, nil
	}
	if in.ParsedJSON == "" {
		return errorResult(fmt.Errorf("parsed_json is required")), nil, nil
	}
	model := in.ModelUsed
	if model == "" {
		model = "claude-code-subagent"
	}
	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}

	res, err := cli.Write(ctx, supervisor.EnrichWriteParams{
		ModuleID:               in.ModuleID,
		App:                    in.App,
		SHA256:                 in.SHA256,
		RawResponse:            in.RawResponse,
		ParsedJSON:             in.ParsedJSON,
		ModelUsed:              model,
		EscalatedTo:            in.EscalatedTo,
		NeedsHumanVerification: in.NeedsHumanVerification,
	})
	if err != nil {
		return errorResult(fmt.Errorf("write enrichment: %w", err)), nil, nil
	}

	out := map[string]any{
		"module_id":                res.ModuleID,
		"app":                      res.App,
		"persisted":                res.Persisted,
		"model_used":               res.ModelUsed,
		"escalated_to":             res.EscalatedTo,
		"needs_human_verification": res.NeedsHumanVerification,
	}
	return jsonResult(out), out, nil
}
