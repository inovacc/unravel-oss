/*
Copyright (c) 2026 Security Research
*/
// Package supervisor / enrich_dispatch.go: thin-client surface for the
// enrich.* verb group. Eight verbs (pending, write, status, retry, record,
// record_cost, cost_report, human_review) backed by pkg/knowledge/kbenrich
// free-functions extracted
// during Phase A8 of the v2.17 thin-client refactor. The MCP tool
// processes dial in over IPC and never open their own DB — the supervisor
// owns the pool.
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ipc"

	kbllm "github.com/inovacc/unravel-oss/pkg/knowledge/kb/llm"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// ---------- request / response shapes ----------

// EnrichPendingParams is the request body for enrich.pending.
type EnrichPendingParams struct {
	App       string `json:"app,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	NamedOnly bool   `json:"named_only,omitempty"`
	Force     bool   `json:"force,omitempty"`
}

// EnrichPendingResult is the response body for enrich.pending.
type EnrichPendingResult struct {
	Modules []kbenrich.PendingModule `json:"modules"`
	Count   int                      `json:"count"`
	App     string                   `json:"app,omitempty"`
}

// EnrichWriteParams is the request body for enrich.write.
//
// EscalatedTo + NeedsHumanVerification mirror the KBC-ENRICH-MODEL-ESCALATION
// Phase 2 contract that the MCP tool kb_write_enrichment already exposes —
// surfacing them at the supervisor seam lets the thin-client MCP handler
// stay direct-DB-free (v2.17 thin-client B4).
type EnrichWriteParams struct {
	ModuleID               int    `json:"module_id"`
	App                    string `json:"app"`
	SHA256                 string `json:"sha256,omitempty"`
	RawResponse            string `json:"raw_response,omitempty"`
	ParsedJSON             string `json:"parsed_json"`
	ModelUsed              string `json:"model_used,omitempty"`
	EscalatedTo            string `json:"escalated_to,omitempty"`
	NeedsHumanVerification bool   `json:"needs_human_verification,omitempty"`
}

// EnrichWriteResult is the response body for enrich.write.
type EnrichWriteResult struct {
	ModuleID               int    `json:"module_id"`
	App                    string `json:"app"`
	Persisted              bool   `json:"persisted"`
	ModelUsed              string `json:"model_used"`
	EscalatedTo            string `json:"escalated_to,omitempty"`
	NeedsHumanVerification bool   `json:"needs_human_verification,omitempty"`
}

// EnrichStatusParams is the request body for enrich.status.
type EnrichStatusParams struct {
	App   string `json:"app,omitempty"`
	RunID string `json:"run_id,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// EnrichStatusResult is the response body for enrich.status. Wire-shape
// alias over kbenrich.StatusPayload.
type EnrichStatusResult = kbenrich.StatusPayload

// EnrichRetryParams is the request body for enrich.retry.
type EnrichRetryParams struct {
	RunID      string `json:"run_id"`
	ErrorClass string `json:"error_class,omitempty"`
	Concurrent int    `json:"concurrent,omitempty"`
	Model      string `json:"model,omitempty"`
}

// EnrichRetryResult is the response body for enrich.retry. Wire-shape
// alias over kbenrich.RetryPayload.
type EnrichRetryResult = kbenrich.RetryPayload

// EnrichRecordParams is the request body for enrich.record. Two modes:
//   - Action="start" — open a new enrich_runs row, return run_id
//   - Action="attempt" — record one enrich_attempts row
type EnrichRecordParams struct {
	Action      string `json:"action"`
	App         string `json:"app,omitempty"`
	TotalTarget int    `json:"total_target,omitempty"`
	Model       string `json:"model,omitempty"`
	RunID       string `json:"run_id,omitempty"`
	ModuleID    int64  `json:"module_id,omitempty"`
	AttemptNo   int    `json:"attempt_no,omitempty"`
	Status      string `json:"status,omitempty"`
	ErrorClass  string `json:"error_class,omitempty"`
	ErrorMsg    string `json:"error_message,omitempty"`
}

// EnrichRecordCostParams is the request body for enrich.record_cost. The
// orchestrator reports a batch's observed subagent_tokens; the supervisor
// splits it 90/10 in/out (P1), prices it, and writes it through attempts +
// run + rollup. Best-effort: a missing model prices at 0, never an error.
type EnrichRecordCostParams struct {
	RunID       string  `json:"run_id"`
	App         string  `json:"app,omitempty"`
	Model       string  `json:"model,omitempty"`
	TotalTokens int64   `json:"total_tokens"`
	ModuleIDs   []int64 `json:"module_ids"`
}

// EnrichCostReportParams is the request body for enrich.cost_report. Both
// fields optional: empty App+RunID returns global + all per-app rollups.
type EnrichCostReportParams struct {
	App   string `json:"app,omitempty"`
	RunID string `json:"run_id,omitempty"`
}

// EnrichCostReportResult is the response body. Wire-shape alias over the
// kbenrich payload.
type EnrichCostReportResult = kbenrich.CostReportPayload

// EnrichHumanReviewParams is the request body for enrich.human_review.
type EnrichHumanReviewParams struct {
	Action   string `json:"action,omitempty"`
	App      string `json:"app,omitempty"`
	Limit    int    `json:"limit,omitempty"`
	ModuleID int64  `json:"module_id,omitempty"`
}

// EnrichHumanReviewResult is the response body for enrich.human_review.
type EnrichHumanReviewResult = kbenrich.HumanReviewPayload

// ---------- registration ----------

// errEnrichNoDB is returned when an enrich.* verb is invoked but the
// supervisor has no DB pool (Config.DSN was empty).
func errEnrichNoDB() *ipc.ErrorBody {
	return &ipc.ErrorBody{
		Code:    ipc.CodeUnavailable,
		Message: "enrich: supervisor has no DB pool (Config.DSN empty)",
	}
}

// registerEnrichVerbs wires the enrich.* verb group. Called from New().
func (sv *Supervisor) registerEnrichVerbs() {
	sv.RegisterVerb("enrich.pending", sv.enrichPending)
	sv.RegisterVerb("enrich.write", sv.enrichWrite)
	sv.RegisterVerb("enrich.status", sv.enrichStatus)
	sv.RegisterVerb("enrich.retry", sv.enrichRetry)
	sv.RegisterVerb("enrich.record", sv.enrichRecord)
	sv.RegisterVerb("enrich.record_cost", sv.enrichRecordCost)
	sv.RegisterVerb("enrich.cost_report", sv.enrichCostReport)
	sv.RegisterVerb("enrich.human_review", sv.enrichHumanReview)
}

// ---------- handlers ----------

func (sv *Supervisor) enrichPending(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichPendingParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.pending: " + err.Error()}
		}
	}
	rows, err := kbenrich.PendingModules(ctx, sv.db, p.App, p.Limit, p.NamedOnly, p.Force)
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.pending: %w", err).Error()}
	}
	if rows == nil {
		rows = []kbenrich.PendingModule{}
	}
	return &EnrichPendingResult{Modules: rows, Count: len(rows), App: p.App}, nil
}

func (sv *Supervisor) enrichWrite(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichWriteParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.write: " + err.Error()}
	}
	if p.ModuleID == 0 {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.write: module_id required"}
	}
	if p.ParsedJSON == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.write: parsed_json required"}
	}
	model := p.ModelUsed
	if model == "" {
		model = "claude-code-subagent"
	}
	if err := kbenrich.WriteEnrichmentJSONWithEscalation(
		ctx, sv.db, p.ModuleID, p.App, p.SHA256, p.RawResponse, model, []byte(p.ParsedJSON),
		p.EscalatedTo, p.NeedsHumanVerification,
	); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.write: %w", err).Error()}
	}
	return &EnrichWriteResult{
		ModuleID:               p.ModuleID,
		App:                    p.App,
		Persisted:              true,
		ModelUsed:              model,
		EscalatedTo:            p.EscalatedTo,
		NeedsHumanVerification: p.NeedsHumanVerification,
	}, nil
}

func (sv *Supervisor) enrichStatus(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichStatusParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.status: " + err.Error()}
		}
	}
	out, err := kbenrich.Status(ctx, sv.db, kbenrich.StatusOptions{
		App:   p.App,
		RunID: p.RunID,
		Limit: p.Limit,
	})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.status: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) enrichRetry(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichRetryParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.retry: " + err.Error()}
	}
	if p.RunID == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.retry: run_id required"}
	}
	out, err := kbenrich.Retry(ctx, sv.db, kbenrich.RetryOptions{
		RunID:      p.RunID,
		ErrorClass: p.ErrorClass,
		Concurrent: p.Concurrent,
		Model:      p.Model,
	}, kbllm.Call)
	if err != nil {
		if errors.Is(err, kbenrich.ErrRetryRunNotFound) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: err.Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.retry: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) enrichRecord(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichRecordParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.record: " + err.Error()}
	}
	switch p.Action {
	case "start":
		out, err := kbenrich.StartRun(ctx, sv.db, kbenrich.StartRunOptions{
			App:         p.App,
			TotalTarget: p.TotalTarget,
			Model:       p.Model,
		})
		if err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.record: %w", err).Error()}
		}
		return out, nil
	case "attempt":
		out, err := kbenrich.RecordAttempt(ctx, sv.db, kbenrich.RecordAttemptOptions{
			RunID:      p.RunID,
			ModuleID:   p.ModuleID,
			AttemptNo:  p.AttemptNo,
			Status:     p.Status,
			ErrorClass: p.ErrorClass,
			ErrorMsg:   p.ErrorMsg,
			ModelUsed:  p.Model,
		})
		if err != nil {
			if errors.Is(err, kbenrich.ErrRecordRunNotFound) {
				return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: err.Error()}
			}
			return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.record: %w", err).Error()}
		}
		return out, nil
	default:
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Sprintf("enrich.record: action must be 'start' or 'attempt' (got %q)", p.Action)}
	}
}

func (sv *Supervisor) enrichRecordCost(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichRecordCostParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.record_cost: " + err.Error()}
	}
	if p.RunID == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.record_cost: run_id required"}
	}
	if len(p.ModuleIDs) == 0 {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.record_cost: module_ids required"}
	}
	out, err := kbenrich.RecordCost(ctx, sv.db, kbenrich.RecordCostOptions{
		RunID:       p.RunID,
		App:         p.App,
		Model:       p.Model,
		TotalTokens: p.TotalTokens,
		ModuleIDs:   p.ModuleIDs,
	})
	if err != nil {
		if errors.Is(err, kbenrich.ErrRecordRunNotFound) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: err.Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.record_cost: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) enrichCostReport(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichCostReportParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.cost_report: " + err.Error()}
		}
	}
	out, err := kbenrich.CostReport(ctx, sv.db, kbenrich.CostReportOptions{
		App:   p.App,
		RunID: p.RunID,
	})
	if err != nil {
		if errors.Is(err, kbenrich.ErrRecordRunNotFound) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: err.Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("enrich.cost_report: %w", err).Error()}
	}
	return out, nil
}

func (sv *Supervisor) enrichHumanReview(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errEnrichNoDB()
	}
	var p EnrichHumanReviewParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "enrich.human_review: " + err.Error()}
		}
	}
	out, err := kbenrich.HumanReview(ctx, sv.db, kbenrich.HumanReviewOptions{
		Action:   p.Action,
		App:      p.App,
		Limit:    p.Limit,
		ModuleID: p.ModuleID,
	})
	if err != nil {
		if errors.Is(err, kbenrich.ErrHumanReviewModuleNotFound) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: err.Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: fmt.Errorf("enrich.human_review: %w", err).Error()}
	}
	return out, nil
}
