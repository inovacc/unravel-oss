/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/findings"
)

// ─── record ──────────────────────────────────────────────────────────────────

type findingRecordInput struct {
	App        string  `json:"app"         jsonschema:"KB app slug (e.g. whatsapp)"`
	ModuleID   *int64  `json:"module_id"   jsonschema:"module id (omit for app-level findings)"`
	Scope      string  `json:"scope"       jsonschema:"module | app | cross-module (default: module)"`
	TargetKind string  `json:"target_kind" jsonschema:"summary|role|side_effect|dep|input|output|security|vendored|app_fact|other"`
	TargetRef  string  `json:"target_ref"  jsonschema:"specific claim reference (optional)"`
	Claim      string  `json:"claim"       jsonschema:"KB assertion under scrutiny"`
	Stance     string  `json:"stance"      jsonschema:"affirm|contradict|augment|uncertain"`
	Finding    string  `json:"finding"     jsonschema:"verdict and reasoning text"`
	Evidence   string  `json:"evidence"    jsonschema:"citations (optional)"`
	Confidence float64 `json:"confidence"  jsonschema:"0..1 confidence score"`
	Severity   string  `json:"severity"    jsonschema:"info|low|medium|high (optional)"`
	Iterations int     `json:"iterations"  jsonschema:"number of passes to converge (default 1)"`
	Converged  bool    `json:"converged"   jsonschema:"true if verdict is stable; false if hit max-iter cap"`
	ModelUsed  string  `json:"model_used"  jsonschema:"model identifier (optional)"`
	RunID      string  `json:"run_id"      jsonschema:"UUID grouping one audit run (optional)"`
	CreatedAt  int64   `json:"created_at"  jsonschema:"epoch-ms; 0 = use current time"`
}

func handleFindingRecord(ctx context.Context, _ *mcp.CallToolRequest, in findingRecordInput) (*mcp.CallToolResult, any, error) {
	db, err := kbdb.Open(ctx, "")
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()

	createdAt := in.CreatedAt
	if createdAt == 0 {
		createdAt = time.Now().UnixMilli()
	}

	f := findings.Finding{
		App:        in.App,
		ModuleID:   in.ModuleID,
		Scope:      in.Scope,
		TargetKind: in.TargetKind,
		TargetRef:  in.TargetRef,
		Claim:      in.Claim,
		Stance:     findings.Stance(in.Stance),
		Finding:    in.Finding,
		Evidence:   in.Evidence,
		Confidence: in.Confidence,
		Severity:   in.Severity,
		Iterations: in.Iterations,
		Converged:  in.Converged,
		ModelUsed:  in.ModelUsed,
		RunID:      in.RunID,
		CreatedAt:  createdAt,
	}

	id, err := findings.Record(db, f)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(map[string]any{"id": id}), nil, nil
}

// ─── record iteration ────────────────────────────────────────────────────────

type findingIterationInput struct {
	FindingID     int64   `json:"finding_id"     jsonschema:"finding row id"`
	Iter          int     `json:"iter"           jsonschema:"pass number (1..N)"`
	InterimStance string  `json:"interim_stance" jsonschema:"verdict at this pass (optional)"`
	InterimConf   float64 `json:"interim_conf"   jsonschema:"confidence at this pass"`
	Challenger    string  `json:"challenger"     jsonschema:"which lens/adversary ran this pass (optional)"`
	Changed       bool    `json:"changed"        jsonschema:"true if verdict flipped vs prior pass"`
	Note          string  `json:"note"           jsonschema:"what the challenge found (optional)"`
	CreatedAt     int64   `json:"created_at"     jsonschema:"epoch-ms; 0 = use current time"`
}

func handleFindingIteration(ctx context.Context, _ *mcp.CallToolRequest, in findingIterationInput) (*mcp.CallToolResult, any, error) {
	db, err := kbdb.Open(ctx, "")
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()

	createdAt := in.CreatedAt
	if createdAt == 0 {
		createdAt = time.Now().UnixMilli()
	}

	it := findings.Iteration{
		FindingID:     in.FindingID,
		Iter:          in.Iter,
		InterimStance: in.InterimStance,
		InterimConf:   in.InterimConf,
		Challenger:    in.Challenger,
		Changed:       in.Changed,
		Note:          in.Note,
		CreatedAt:     createdAt,
	}

	if err := findings.RecordIteration(db, it); err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(map[string]any{"ok": true}), nil, nil
}

// ─── list ─────────────────────────────────────────────────────────────────────

type findingsListInput struct {
	App      string `json:"app"       jsonschema:"filter by KB app slug (empty = all)"`
	ModuleID int64  `json:"module_id" jsonschema:"filter by module id (0 = all)"`
	Stance   string `json:"stance"    jsonschema:"filter by stance: affirm|contradict|augment|uncertain (empty = all)"`
	Status   string `json:"status"    jsonschema:"filter by status: open|accepted|rejected|applied|superseded (empty = all)"`
	Limit    int    `json:"limit"     jsonschema:"max rows (0 = default cap of 500)"`
}

func handleFindingsList(ctx context.Context, _ *mcp.CallToolRequest, in findingsListInput) (*mcp.CallToolResult, any, error) {
	db, err := kbdb.Open(ctx, "")
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()

	filter := findings.Filter{
		App:      in.App,
		ModuleID: in.ModuleID,
		Stance:   in.Stance,
		Status:   in.Status,
		Limit:    in.Limit,
	}

	rows, err := findings.List(db, filter)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(rows), nil, nil
}

// ─── resolve ──────────────────────────────────────────────────────────────────

type findingResolveInput struct {
	ID         int64  `json:"id"          jsonschema:"finding row id"`
	Status     string `json:"status"      jsonschema:"accepted|rejected|applied|superseded"`
	ResolvedBy string `json:"resolved_by" jsonschema:"identifier of the resolver (agent id, username, etc.)"`
	ResolvedAt int64  `json:"resolved_at" jsonschema:"epoch-ms; 0 = use current time"`
}

func handleFindingResolve(ctx context.Context, _ *mcp.CallToolRequest, in findingResolveInput) (*mcp.CallToolResult, any, error) {
	db, err := kbdb.Open(ctx, "")
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()

	resolvedAt := in.ResolvedAt
	if resolvedAt == 0 {
		resolvedAt = time.Now().UnixMilli()
	}

	if err := findings.Resolve(db, in.ID, in.Status, in.ResolvedBy, resolvedAt); err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(map[string]any{"ok": true}), nil, nil
}

// ─── summary ──────────────────────────────────────────────────────────────────

type findingsSummaryInput struct {
	App string `json:"app" jsonschema:"KB app slug; empty = aggregate across all apps"`
}

func handleFindingsSummary(ctx context.Context, _ *mcp.CallToolRequest, in findingsSummaryInput) (*mcp.CallToolResult, any, error) {
	db, err := kbdb.Open(ctx, "")
	if err != nil {
		return errorResult(err), nil, nil
	}
	defer func() { _ = db.Close() }()

	sum, err := findings.Summary(db, in.App)
	if err != nil {
		return errorResult(err), nil, nil
	}
	return jsonResult(sum), nil, nil
}

// ─── registration ─────────────────────────────────────────────────────────────

func registerFindingsTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_kb_findings_record", Description: "Record a new KB AI adjudication finding (affirm/contradict/augment/uncertain) and return its id"}, handleFindingRecord)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_kb_findings_iteration", Description: "Append one per-pass iteration trail row to an existing finding (idempotent on finding_id+iter)"}, handleFindingIteration)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_kb_findings_list", Description: "List KB AI findings with optional filters by app, module, stance, and status"}, handleFindingsList)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_kb_findings_resolve", Description: "Resolve a finding: transition its status to accepted|rejected|applied|superseded"}, handleFindingResolve)
	mcp.AddTool(s, &mcp.Tool{Name: "unravel_kb_findings_summary", Description: "Aggregated finding counts by stance and status for an app (or all apps)"}, handleFindingsSummary)
}
