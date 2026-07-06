/*
Copyright (c) 2026 Security Research
*/
// unravel_kb_enrich_retry — re-run failed / timed-out / interrupted
// modules from a prior enrich run. The retry executes under a NEW enrich_runs
// row whose parent_run_id points back at the source run.
//
// Thin delegate: all logic lives in pkg/knowledge/kbenrich/retry.go so the
// supervisor dispatcher (enrich.retry) and this MCP tool share one
// implementation. The CallFn seam stays a parameter so the dispatcher can
// inject kbllm.Call and tests can inject a stub.
package mcptools

import (
	"context"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/supervisor"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EnrichRetryInput is the typed input for unravel_kb_enrich_retry.
type EnrichRetryInput struct {
	DB         string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored — supervisor owns DSN (v2.17 thin-client)"`
	RunID      string `json:"run_id" jsonschema:"required: source run to retry"`
	ErrorClass string `json:"error_class,omitempty" jsonschema:"optional filter: re-run only attempts with this error_class"`
	Concurrent int    `json:"concurrent,omitempty" jsonschema:"parallel claude invocations (default 8)"`
	Model      string `json:"model,omitempty" jsonschema:"claude model: 'sonnet' (default) or 'haiku'"`
}

//nolint:unused // registered via knowledge.go
func registerKnowledgeEnrichRetryTool(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "unravel_kb_enrich_retry",
		Description: "Re-run failed / timed-out / interrupted modules from a prior enrich run. " +
			"Looks up enrich_attempts where run_id=<parent> AND status IN ('failure','timeout','interrupted'), " +
			"optionally filtered by error_class, then invokes EnrichCore restricted to those module_ids. " +
			"The new run row has parent_run_id pointing at the source run for audit chain. " +
			"Pair with unravel_kb_enrich_status to inspect which runs need retrying.",
	}, handleKnowledgeEnrichRetry)
}

func handleKnowledgeEnrichRetry(ctx context.Context, _ *mcp.CallToolRequest, in EnrichRetryInput) (*mcp.CallToolResult, any, error) {
	if in.RunID == "" {
		return errorResult(fmt.Errorf("run_id is required")), nil, nil
	}
	// Share the enrich global semaphore with the legacy sampling-based enrich path so
	// retry runs don't pile on top of an in-flight primary enrich.
	select {
	case enrichGlobalSem <- struct{}{}:
		defer func() { <-enrichGlobalSem }()
	case <-ctx.Done():
		return errorResult(fmt.Errorf("enrich-retry cancelled before acquire: %w", ctx.Err())), nil, nil
	}
	cli, err := getEnrichClient(ctx)
	if err != nil {
		if errors.Is(err, ErrSupervisorUnavailable) {
			return supervisorUnavailableResult(err), nil, nil
		}
		return errorResult(fmt.Errorf("enrich client: %w", err)), nil, nil
	}
	payload, err := cli.Retry(ctx, supervisor.EnrichRetryParams{
		RunID:      in.RunID,
		ErrorClass: in.ErrorClass,
		Concurrent: in.Concurrent,
		Model:      in.Model,
	})
	if err != nil {
		return errorResult(fmt.Errorf("enrich: %w", err)), nil, nil
	}
	return jsonResult(payload), payload, nil
}

// handleKnowledgeEnrichRetryWithCallFn — the integration-test seam that
// bypasses the supervisor IPC and calls kbenrich.Retry directly with an
// injectable CallFn — moved to knowledge_enrich_retry_test.go in v2.17
// thin-client B7-P4 so the production file is supervisor-only (B7 invariant).
