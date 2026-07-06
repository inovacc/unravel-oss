/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_enrich_human_review — list + clear the modules
// flagged for human verification after the sonnet+opus escalation
// pipeline exhausted retries (KBC-ENRICH-MODEL-ESCALATION, schema
// migration 000015). Pairs with the EnrichCore opus-retry path
// (orchestration commit lands separately).
//
// Thin delegate: all SQL lives in pkg/knowledge/kbenrich/human_review.go
// so the supervisor dispatcher (enrich.human_review) and this MCP tool
// share one implementation.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EnrichHumanReviewInput is the typed input for
// unravel_kb_enrich_human_review.
//
// action:
//   - "list"          : default. Return modules where
//     needs_human_verification = true with their
//     most recent failure error (from
//     enrich_attempts).
//   - "mark_resolved" : clear needs_human_verification for the named
//     module_id, optionally setting
//     escalated_to='opus' to record the resolution
//     came from a human-driven re-attempt.
type EnrichHumanReviewInput struct {
	DB       string `json:"db,omitempty"        jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	Action   string `json:"action,omitempty"    jsonschema:"list (default) or mark_resolved"`
	App      string `json:"app,omitempty"       jsonschema:"filter modules by app (list action only)"`
	Limit    int    `json:"limit,omitempty"     jsonschema:"max modules to return (default 50, hard cap 500)"`
	ModuleID int64  `json:"module_id,omitempty" jsonschema:"module to clear (required for mark_resolved)"`
}

// EnrichHumanReviewModule is one row of the list output. Wire-shape alias
// over kbenrich.HumanReviewModule so legacy MCP-tool callers keep their
// import surface.
type EnrichHumanReviewModule = kbenrich.HumanReviewModule

func registerKnowledgeEnrichHumanReviewTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_human_review",
		Description: "List or clear modules flagged for human verification " +
			"by KBC-ENRICH-MODEL-ESCALATION (modules.needs_human_verification " +
			"set when both sonnet and opus failed). Default action=list returns " +
			"modules with their most recent failure error. action=mark_resolved " +
			"clears the flag for the given module_id (typically called by an " +
			"operator after fixing the underlying parse / prompt issue).",
	}, handleKnowledgeEnrichHumanReview)
}

func handleKnowledgeEnrichHumanReview(ctx context.Context, _ *mcp.CallToolRequest, in EnrichHumanReviewInput) (*mcp.CallToolResult, any, error) {
	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}
	payload, err := cli.HumanReview(ctx, supervisor.EnrichHumanReviewParams{
		Action:   in.Action,
		App:      in.App,
		Limit:    in.Limit,
		ModuleID: in.ModuleID,
	})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(payload), payload, nil
}
