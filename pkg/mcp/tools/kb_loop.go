/*
Copyright (c) 2026 Security Research
*/
// pkg/mcptools/kb_loop.go is the Claude-as-pipe gap-resolution loop.
//
// Two MCP tools cooperate to drain the open-gaps queue in app_facts:
//
//	unravel_kb_pull_gap   — claim one open gap row, hydrate evidence,
//	                        render the prompt template, return JSON
//	unravel_kb_push_answer — write the model's answer back into app_facts
//	                         and append a fact_history row
//
// Both tools are registered alongside the existing kb_* tools by
// pkg/mcptools/server.go via registerKBLoopTools.
package mcptools

import (
	"context"
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/prompts"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// ─── input/output types ─────────────────────────────────────────────

type kbPullGapInput struct {
	DB  string `json:"db,omitempty" jsonschema:"DEPRECATED: ignored. Supervisor-routed since v2.17."`
	App string `json:"app" jsonschema:"app slug to pull a gap for (e.g. whatsapp)"`
	Op  string `json:"op,omitempty" jsonschema:"prompt op id (default: fact_resolve)"`
}

// kbEvidence is one supporting module surfaced to the model.
type kbEvidence struct {
	ModuleID    int64  `json:"module_id"`
	Name        string `json:"name"`
	BodyExcerpt string `json:"body_excerpt,omitempty"`
	SymbolsJSON string `json:"symbols_json,omitempty"`
}

type kbPullGapOutput struct {
	GapID        int64        `json:"gap_id"`
	App          string       `json:"app,omitempty"`
	Category     string       `json:"category,omitempty"`
	Key          string       `json:"key,omitempty"`
	Prompt       string       `json:"prompt,omitempty"`
	OutputFormat string       `json:"output_format,omitempty"`
	Schema       string       `json:"schema,omitempty"`
	Evidence     []kbEvidence `json:"evidence,omitempty"`
	Message      string       `json:"message,omitempty"`
}

type kbPushAnswerInput struct {
	DB          string  `json:"db,omitempty" jsonschema:"DEPRECATED: ignored. Supervisor-routed since v2.17."`
	GapID       int64   `json:"gap_id" jsonschema:"the gap_id returned by kb_pull_gap"`
	Value       string  `json:"value" jsonschema:"resolved fact value"`
	EvidenceIDs []int64 `json:"evidence_ids,omitempty" jsonschema:"module ids supporting the value"`
	Confidence  float64 `json:"confidence,omitempty" jsonschema:"0..1 confidence score"`
	SourceStep  string  `json:"source_step,omitempty" jsonschema:"label for fact_history (default: claude_mcp)"`
}

type kbPushAnswerOutput struct {
	OK       bool   `json:"ok"`
	GapID    int64  `json:"gap_id"`
	App      string `json:"app,omitempty"`
	Category string `json:"category,omitempty"`
	Key      string `json:"key,omitempty"`
}

// ─── registration ────────────────────────────────────────────────────

func registerKBLoopTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_gaps_pull",
		Description: "Claim one open gap from app_facts for the given app, hydrate the top 8 evidence modules via FTS, render the prompt template, and return everything Claude needs to resolve the gap.",
	}, handleKBPullGap)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_kb_gaps_push_answer",
		Description: "Write a resolved gap value back into app_facts and append the prior shape to fact_history. Pair with unravel_kb_pull_gap to drive the gap-resolution loop.",
	}, handleKBPushAnswer)
}

// ─── handlers ────────────────────────────────────────────────────────

func handleKBPullGap(ctx context.Context, _ *mcp.CallToolRequest, in kbPullGapInput) (*mcp.CallToolResult, any, error) {
	if strings.TrimSpace(in.App) == "" {
		return errorResult(fmt.Errorf("app is required")), nil, nil
	}
	op := in.Op
	if op == "" {
		op = prompts.OpFactResolve
	}

	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}

	storeOut, err := cli.PullGap(ctx, supervisor.KBPullGapParams{App: in.App, Op: op})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(convertGapPayload(storeOut)), nil, nil
}

func handleKBPushAnswer(ctx context.Context, _ *mcp.CallToolRequest, in kbPushAnswerInput) (*mcp.CallToolResult, any, error) {
	if in.GapID == 0 {
		return errorResult(fmt.Errorf("gap_id is required")), nil, nil
	}
	if in.SourceStep == "" {
		in.SourceStep = "claude_mcp"
	}

	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}

	storeOut, err := cli.PushAnswer(ctx, supervisor.KBPushAnswerParams{
		GapID:       in.GapID,
		Value:       in.Value,
		EvidenceIDs: in.EvidenceIDs,
		Confidence:  in.Confidence,
		SourceStep:  in.SourceStep,
	})
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(&kbPushAnswerOutput{
		OK:       storeOut.OK,
		GapID:    storeOut.GapID,
		App:      storeOut.App,
		Category: storeOut.Category,
		Key:      storeOut.Key,
	}), nil, nil
}

// CLI passthrough shims (PullOpenGapForCLI / PushAnswerForCLI) lived here
// until v2.17 thin-client B7-P1; the only caller was
// cmd/knowledge_mcp_loop.go and the shims pulled kbdb into pkg/mcp/tools.
// The CLI now calls kbdb.Open + kbstore.* directly from
// cmd/knowledge_mcp_loop.go (allowed for cmd/-side code).
//
// convertGapPayload survives — it's the MCP-wire-shape adapter still used
// by handleKBPullGap to map the supervisor's KBPullGapResult to the
// legacy kbPullGapOutput JSON the MCP tool exposes externally. Parameterised
// on supervisor.KBPullGapResult so this file no longer needs the kbstore
// import.
func convertGapPayload(in *supervisor.KBPullGapResult) *kbPullGapOutput {
	if in == nil {
		return nil
	}
	ev := make([]kbEvidence, 0, len(in.Evidence))
	for _, e := range in.Evidence {
		ev = append(ev, kbEvidence{
			ModuleID:    e.ModuleID,
			Name:        e.Name,
			BodyExcerpt: e.BodyExcerpt,
			SymbolsJSON: e.SymbolsJSON,
		})
	}
	return &kbPullGapOutput{
		GapID:        in.GapID,
		App:          in.App,
		Category:     in.Category,
		Key:          in.Key,
		Prompt:       in.Prompt,
		OutputFormat: in.OutputFormat,
		Schema:       in.Schema,
		Evidence:     ev,
		Message:      in.Message,
	}
}
