/*
Copyright (c) 2026 Security Research
*/

// Package kbenrich / human_review.go: free-function HumanReview()
// extracted from pkg/mcp/tools/knowledge_enrich_human_review.go. Lists
// (or clears) modules flagged for human verification by the
// KBC-ENRICH-MODEL-ESCALATION pipeline.
package kbenrich

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// HumanReviewAction selects which sub-operation HumanReview performs.
const (
	HumanReviewActionList         = "list"
	HumanReviewActionMarkResolved = "mark_resolved"
	humanReviewDefaultLimit       = 50
	humanReviewHardCapLimit       = 500
)

// ErrHumanReviewModuleNotFound is returned when mark_resolved targets a
// module_id that doesn't exist or isn't currently flagged. Wrappers map
// it to CodeNotFound / ErrEnrichModuleNotFound at the supervisor +
// client boundary.
var ErrHumanReviewModuleNotFound = errors.New("kbenrich: human_review module not found or not flagged")

// HumanReviewOptions controls HumanReview().
type HumanReviewOptions struct {
	Action   string
	App      string
	Limit    int
	ModuleID int64
}

// HumanReviewModule is one row of the list output. Field names match
// the legacy JSON wire shape.
type HumanReviewModule struct {
	ID            int64  `json:"id"`
	App           string `json:"app"`
	Name          string `json:"name"`
	LastError     string `json:"last_error,omitempty"`
	LastErrorAt   string `json:"last_error_at,omitempty"`
	LastAttemptNo int    `json:"last_attempt_no,omitempty"`
}

// HumanReviewPayload is the wire body returned by HumanReview(). The Action
// field is always set to echo the operation that ran. Modules / Count are
// populated for list; ModuleID / RowsAffected / Cleared for mark_resolved.
type HumanReviewPayload struct {
	Action       string              `json:"action"`
	Count        int                 `json:"count,omitempty"`
	Modules      []HumanReviewModule `json:"modules,omitempty"`
	ModuleID     int64               `json:"module_id,omitempty"`
	RowsAffected int64               `json:"rows_affected,omitempty"`
	Cleared      bool                `json:"cleared,omitempty"`
}

// HumanReview dispatches on opts.Action. Valid actions are
// HumanReviewActionList (default when Action is empty) and
// HumanReviewActionMarkResolved.
func HumanReview(ctx context.Context, db *sql.DB, opts HumanReviewOptions) (*HumanReviewPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("HumanReview: nil db")
	}
	action := opts.Action
	if action == "" {
		action = HumanReviewActionList
	}
	switch action {
	case HumanReviewActionList:
		return humanReviewList(ctx, db, opts)
	case HumanReviewActionMarkResolved:
		return humanReviewMarkResolved(ctx, db, opts)
	default:
		return nil, fmt.Errorf("HumanReview: unknown action %q (allowed: list, mark_resolved)", action)
	}
}

func humanReviewList(ctx context.Context, db *sql.DB, opts HumanReviewOptions) (*HumanReviewPayload, error) {
	limit := opts.Limit
	if limit < 1 {
		limit = humanReviewDefaultLimit
	}
	if limit > humanReviewHardCapLimit {
		limit = humanReviewHardCapLimit
	}
	args := []any{}
	where := "m.needs_human_verification = true"
	if opts.App != "" {
		args = append(args, opts.App)
		where += fmt.Sprintf(" AND m.app = $%d", len(args))
	}
	args = append(args, limit)
	q := fmt.Sprintf(`
		SELECT m.id, m.app, m.name,
		       COALESCE((
		         SELECT ea.error_message_redacted
		           FROM enrich_attempts ea
		          WHERE ea.module_id = m.id AND ea.status = 'failure'
		          ORDER BY ea.started_at DESC
		          LIMIT 1
		       ), '') AS last_error,
		       COALESCE((
		         SELECT to_char(ea.started_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')
		           FROM enrich_attempts ea
		          WHERE ea.module_id = m.id AND ea.status = 'failure'
		          ORDER BY ea.started_at DESC
		          LIMIT 1
		       ), '') AS last_error_at,
		       COALESCE((
		         SELECT ea.attempt_no
		           FROM enrich_attempts ea
		          WHERE ea.module_id = m.id AND ea.status = 'failure'
		          ORDER BY ea.started_at DESC
		          LIMIT 1
		       ), 0) AS last_attempt_no
		  FROM modules m
		 WHERE %s
		 ORDER BY m.id
		 LIMIT $%d`, where, len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query human_review modules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	mods := []HumanReviewModule{}
	for rows.Next() {
		var m HumanReviewModule
		if err := rows.Scan(&m.ID, &m.App, &m.Name, &m.LastError, &m.LastErrorAt, &m.LastAttemptNo); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		mods = append(mods, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return &HumanReviewPayload{Action: HumanReviewActionList, Count: len(mods), Modules: mods}, nil
}

func humanReviewMarkResolved(ctx context.Context, db *sql.DB, opts HumanReviewOptions) (*HumanReviewPayload, error) {
	if opts.ModuleID == 0 {
		return nil, fmt.Errorf("HumanReview: module_id is required for mark_resolved")
	}
	res, err := db.ExecContext(ctx, `
		UPDATE modules
		   SET needs_human_verification = false
		 WHERE id = $1 AND needs_human_verification = true`, opts.ModuleID)
	if err != nil {
		return nil, fmt.Errorf("update modules: %w", err)
	}
	n, _ := res.RowsAffected()
	return &HumanReviewPayload{
		Action:       HumanReviewActionMarkResolved,
		ModuleID:     opts.ModuleID,
		RowsAffected: n,
		Cleared:      n > 0,
	}, nil
}
