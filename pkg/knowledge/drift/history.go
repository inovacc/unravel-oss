/*
Copyright (c) 2026 Security Research
*/
package drift

import (
	"context"
	"database/sql"
	"fmt"
)

// defaultHistoryLimit is the default row cap for History when callers
// pass limit <= 0.
const defaultHistoryLimit = 20

// maxHistoryLimit is the hard cap History enforces regardless of input.
const maxHistoryLimit = 500

// Alert is one persisted drift_alerts row. JSON tags are snake_case so
// the type doubles as the MCP/IPC wire shape.
type Alert struct {
	ID                int64   `json:"id"`
	App               string  `json:"app"`
	RunID             string  `json:"run_id"`
	BaselineRunID     string  `json:"baseline_run_id"`
	Metric            string  `json:"metric"`
	BaselineValue     float64 `json:"baseline_value"`
	RecentValue       float64 `json:"recent_value"`
	RelativeDelta     float64 `json:"relative_delta"`
	ThresholdRelative float64 `json:"threshold_relative"`
	CreatedAt         string  `json:"created_at"`
}

// HistoryOptions controls History pagination. Limit defaults to 20 and is
// hard-capped at 500. App is required.
type HistoryOptions struct {
	App   string
	Limit int
}

// HistoryResult is the typed result of History: a list of alerts plus
// echo of the query for caller convenience.
type HistoryResult struct {
	App    string  `json:"app"`
	Limit  int     `json:"limit"`
	Count  int     `json:"count"`
	Alerts []Alert `json:"alerts"`
}

// History returns the most recent drift_alerts rows for app, newest
// first. Limit defaults to 20, hard-capped at 500. App is required.
//
// Empty result is returned as &HistoryResult{Alerts: []Alert{}}, never
// nil — so JSON marshalling produces "alerts":[] rather than "alerts":null.
func History(ctx context.Context, db *sql.DB, opts HistoryOptions) (*HistoryResult, error) {
	if db == nil {
		return nil, fmt.Errorf("history: db is nil")
	}
	if opts.App == "" {
		return nil, fmt.Errorf("history: app is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = defaultHistoryLimit
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}

	rows, err := db.QueryContext(ctx,
		`SELECT id, app, run_id, baseline_run_id, metric, baseline_value,
		        recent_value, relative_delta, threshold_relative,
		        created_at::text
		   FROM drift_alerts
		  WHERE app = $1
		  ORDER BY created_at DESC
		  LIMIT $2`, opts.App, limit)
	if err != nil {
		return nil, fmt.Errorf("query drift_alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]Alert, 0)
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.App, &a.RunID, &a.BaselineRunID, &a.Metric,
			&a.BaselineValue, &a.RecentValue, &a.RelativeDelta,
			&a.ThresholdRelative, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan drift_alerts row: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate drift_alerts: %w", err)
	}
	return &HistoryResult{
		App:    opts.App,
		Limit:  limit,
		Count:  len(out),
		Alerts: out,
	}, nil
}
