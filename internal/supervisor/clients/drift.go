/*
Copyright (c) 2026 Security Research
*/
package clients

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
)

// ErrDriftUnavailable is returned when the supervisor was started
// without a DSN (CodeUnavailable) so the drift.* verbs can't reach the DB.
var ErrDriftUnavailable = errors.New("drift: supervisor has no DB pool")

// translateDriftErr layers drift-specific sentinel mapping on top of
// translateErr. CodeUnavailable maps to ErrDriftUnavailable (joined with
// the underlying ipc.ErrorBody so callers can drill into wire details).
func translateDriftErr(err error, notFound error) error {
	if err == nil {
		return nil
	}
	var eb *ipc.ErrorBody
	if errors.As(err, &eb) && eb.Code == ipc.CodeUnavailable {
		return errors.Join(ErrDriftUnavailable, eb)
	}
	return translateErr(err, notFound)
}

// DriftClient wraps the drift.* verbs. Construct one per ipc.Bus.
type DriftClient struct {
	bus ipc.Bus
}

// NewDriftClient returns a wrapper over bus for the drift.* verb group.
func NewDriftClient(bus ipc.Bus) *DriftClient {
	return &DriftClient{bus: bus}
}

// Check calls drift.check.
func (c *DriftClient) Check(ctx context.Context, p supervisor.DriftCheckParams) (*supervisor.DriftCheckResult, error) {
	raw, err := c.bus.Call(ctx, "drift.check", p)
	if err != nil {
		return nil, translateDriftErr(err, ErrDriftRunNotFound)
	}
	var out supervisor.DriftCheckResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Baseline calls drift.baseline. Action is one of "set", "clear", "show"
// (empty defaults to "show" on the supervisor side). For action=set,
// runID is required and force toggles the min-run-size override.
func (c *DriftClient) Baseline(ctx context.Context, action, app string, runID string, force bool) (*supervisor.DriftBaselineResult, error) {
	p := supervisor.DriftBaselineParams{
		Action: action,
		App:    app,
		RunID:  runID,
		Force:  force,
	}
	raw, err := c.bus.Call(ctx, "drift.baseline", p)
	if err != nil {
		return nil, translateDriftErr(err, ErrDriftNoBaseline)
	}
	var out supervisor.DriftBaselineResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// History calls drift.history. Limit defaults to 20 on the supervisor
// side when 0; hard cap is 500.
func (c *DriftClient) History(ctx context.Context, app string, limit int) (*supervisor.DriftHistoryResult, error) {
	p := supervisor.DriftHistoryParams{App: app, Limit: limit}
	raw, err := c.bus.Call(ctx, "drift.history", p)
	if err != nil {
		return nil, translateDriftErr(err, nil)
	}
	var out supervisor.DriftHistoryResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
