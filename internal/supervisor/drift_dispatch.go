/*
Copyright (c) 2026 Security Research
*/
package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
)

// ---------- request / response shapes ----------

// DriftCheckParams is the request body for drift.check.
type DriftCheckParams struct {
	App               string  `json:"app"`
	RunID             string  `json:"run_id,omitempty"` // enrich_runs.run_id (uuid)
	ThresholdRelative float64 `json:"threshold_relative,omitempty"`
	MinRunSize        int     `json:"min_run_size,omitempty"`
}

// DriftCheckResult aliases drift.DriftVerdict — supervisor exposes the
// verdict directly on the wire.
type DriftCheckResult = drift.DriftVerdict

// DriftBaselineParams is the request body for drift.baseline (action
// dispatch: set | clear | show).
type DriftBaselineParams struct {
	Action string `json:"action"`
	App    string `json:"app"`
	RunID  string `json:"run_id,omitempty"` // enrich_runs.run_id (uuid)
	Force  bool   `json:"force,omitempty"`
}

// DriftBaselineResult is the unified response for drift.baseline. Fields
// are populated based on action: set → BaselineRunID; clear → Cleared;
// show → BaselineRunID or Note (when no baseline set).
type DriftBaselineResult struct {
	Action        string `json:"action"`
	App           string `json:"app"`
	BaselineRunID string `json:"baseline_run_id,omitempty"` // enrich_runs.run_id (uuid)
	Cleared       bool   `json:"cleared,omitempty"`
	Note          string `json:"note,omitempty"`
}

// DriftHistoryParams is the request body for drift.history.
type DriftHistoryParams struct {
	App   string `json:"app"`
	Limit int    `json:"limit,omitempty"`
}

// DriftHistoryResult aliases drift.HistoryResult.
type DriftHistoryResult = drift.HistoryResult

// ---------- registration ----------

// errDriftNoDB is returned when a drift.* verb is invoked but the
// supervisor has no DB pool (Config.DSN was empty).
func errDriftNoDB() *ipc.ErrorBody {
	return &ipc.ErrorBody{
		Code:    ipc.CodeUnavailable,
		Message: "drift: supervisor has no DB pool (Config.DSN empty)",
	}
}

// registerDriftVerbs wires the drift.* verb group. Called from New().
func (sv *Supervisor) registerDriftVerbs() {
	sv.RegisterVerb("drift.check", sv.driftCheck)
	sv.RegisterVerb("drift.baseline", sv.driftBaseline)
	sv.RegisterVerb("drift.history", sv.driftHistory)
}

// ---------- handlers ----------

func (sv *Supervisor) driftCheck(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errDriftNoDB()
	}
	var p DriftCheckParams
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "drift.check: " + err.Error()}
		}
	}
	if p.App == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "drift.check: app is required"}
	}

	runID := p.RunID
	if runID == "" {
		if err := sv.db.QueryRowContext(ctx,
			`SELECT run_id::text FROM enrich_runs WHERE app = $1 ORDER BY started_at DESC LIMIT 1`,
			p.App).Scan(&runID); err != nil {
			return nil, &ipc.ErrorBody{
				Code:    ipc.CodeNotFound,
				Message: fmt.Errorf("drift.check: no enrich runs for app %q: %w", p.App, err).Error(),
			}
		}
	}

	o := drift.DefaultOpts()
	if p.ThresholdRelative > 0 {
		o.ThresholdRelative = p.ThresholdRelative
	}
	if p.MinRunSize > 0 {
		o.MinRunSize = p.MinRunSize
	}

	v, err := drift.Check(ctx, sv.db, runID, o)
	if err != nil {
		if errors.Is(err, drift.ErrRunNotFound) {
			return nil, &ipc.ErrorBody{Code: ipc.CodeNotFound, Message: err.Error()}
		}
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("drift.check: %w", err).Error()}
	}
	return v, nil
}

func (sv *Supervisor) driftBaseline(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	if sv.db == nil {
		return nil, errDriftNoDB()
	}
	var p DriftBaselineParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "drift.baseline: " + err.Error()}
	}
	if p.App == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "drift.baseline: app is required"}
	}
	action := p.Action
	if action == "" {
		action = "show"
	}

	switch action {
	case "set":
		if p.RunID == "" {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "drift.baseline: action=set requires run_id"}
		}
		if err := drift.SetBaseline(ctx, sv.db, p.App, p.RunID, p.Force, drift.DefaultOpts().MinRunSize); err != nil {
			if errors.Is(err, drift.ErrRunTooSmall) {
				return nil, &ipc.ErrorBody{Code: ipc.CodeConflict, Message: err.Error()}
			}
			return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("drift.baseline: %w", err).Error()}
		}
		return &DriftBaselineResult{Action: "set", App: p.App, BaselineRunID: p.RunID}, nil

	case "clear":
		if err := drift.ClearBaseline(ctx, sv.db, p.App); err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("drift.baseline: %w", err).Error()}
		}
		return &DriftBaselineResult{Action: "clear", App: p.App, Cleared: true}, nil

	case "show":
		id, err := drift.ShowBaseline(ctx, sv.db, p.App)
		if errors.Is(err, drift.ErrNoBaseline) {
			return &DriftBaselineResult{Action: "show", App: p.App, Note: "no baseline set for app"}, nil
		}
		if err != nil {
			return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("drift.baseline: %w", err).Error()}
		}
		return &DriftBaselineResult{Action: "show", App: p.App, BaselineRunID: id}, nil

	default:
		return nil, &ipc.ErrorBody{
			Code:    ipc.CodeInvalidArg,
			Message: fmt.Sprintf("drift.baseline: action must be 'set', 'clear', or 'show' (got %q)", p.Action),
		}
	}
}

func (sv *Supervisor) driftHistory(ctx context.Context, params json.RawMessage) (any, *ipc.ErrorBody) {
	var p DriftHistoryParams
	if e := sv.decodeParams("drift.history", params, &p, errDriftNoDB); e != nil {
		return nil, e
	}
	if p.App == "" {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInvalidArg, Message: "drift.history: app is required"}
	}
	out, err := drift.History(ctx, sv.db, drift.HistoryOptions{App: p.App, Limit: p.Limit})
	if err != nil {
		return nil, &ipc.ErrorBody{Code: ipc.CodeInternal, Message: fmt.Errorf("drift.history: %w", err).Error()}
	}
	return out, nil
}
