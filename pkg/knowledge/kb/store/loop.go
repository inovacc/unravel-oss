/*
Copyright (c) 2026 Security Research
*/
// Gap-resolution loop — claim one open app_facts row, render its prompt,
// then later write the resolved value back.
//
// Extracted out of pkg/mcp/tools/kb_loop.go (pullOpenGap / pushAnswer) so
// the supervisor dispatcher (internal/supervisor/kb_dispatch.go), the MCP
// tool, and the CLI share one source of truth for the DB-touching half
// of the kb_pull_gap / kb_push_answer cooperative loop. See
// docs/superpowers/plans/2026-05-27-v2.17-thinclient-refactor.md
// (Phase A5 + A6).
//
// The wire shapes (GapPayload, PushAnswerPayload, GapEvidence) are
// field-for-field compatible with the JSON the MCP tools emitted prior
// to the extraction.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/prompts"
)

// PullGapOptions controls PullGap's behaviour. App is required. Op
// selects the prompt template (defaults to prompts.OpFactResolve when
// empty). EvidenceLimit caps the supporting modules hydrated alongside
// the gap (defaults to 8).
type PullGapOptions struct {
	App           string `json:"app"`
	Op            string `json:"op,omitempty"`
	EvidenceLimit int    `json:"evidence_limit,omitempty"`
}

// GapEvidence is one supporting module surfaced to the model. Mirrors
// kbEvidence in pkg/mcp/tools/kb_loop.go prior to the extraction.
type GapEvidence struct {
	ModuleID    int64  `json:"module_id"`
	Name        string `json:"name"`
	BodyExcerpt string `json:"body_excerpt,omitempty"`
	SymbolsJSON string `json:"symbols_json,omitempty"`
}

// GapPayload is the response body for PullGap. When no gap is pending,
// GapID is 0 and Message is set so callers can short-circuit cleanly —
// no error is returned in that case.
type GapPayload struct {
	GapID        int64         `json:"gap_id"`
	App          string        `json:"app,omitempty"`
	Category     string        `json:"category,omitempty"`
	Key          string        `json:"key,omitempty"`
	Prompt       string        `json:"prompt,omitempty"`
	OutputFormat string        `json:"output_format,omitempty"`
	Schema       string        `json:"schema,omitempty"`
	Evidence     []GapEvidence `json:"evidence,omitempty"`
	Message      string        `json:"message,omitempty"`
}

// PushAnswerOptions controls PushAnswer's behaviour. GapID and Value are
// required. EvidenceIDs is JSON-encoded into the app_facts row.
// SourceStep defaults to "claude_mcp" when empty.
type PushAnswerOptions struct {
	GapID       int64   `json:"gap_id"`
	Value       string  `json:"value"`
	EvidenceIDs []int64 `json:"evidence_ids,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	SourceStep  string  `json:"source_step,omitempty"`
}

// PushAnswerPayload is the response body for PushAnswer.
type PushAnswerPayload struct {
	OK       bool   `json:"ok"`
	GapID    int64  `json:"gap_id"`
	App      string `json:"app,omitempty"`
	Category string `json:"category,omitempty"`
	Key      string `json:"key,omitempty"`
}

// PullGap claims one open app_facts row for opts.App (value IS NULL),
// hydrates up to opts.EvidenceLimit supporting modules via the row's
// candidates_q FTS hint, renders the prompt template named opts.Op, and
// returns everything Claude needs to resolve the gap.
//
// When no open gaps exist, the returned GapPayload has GapID=0 and
// Message="no open gaps" — not an error.
func PullGap(ctx context.Context, db *sql.DB, opts PullGapOptions) (*GapPayload, error) {
	if db == nil {
		return nil, errors.New("kb_pull_gap: nil db")
	}
	if strings.TrimSpace(opts.App) == "" {
		return nil, errors.New("kb_pull_gap: app required")
	}
	op := opts.Op
	if op == "" {
		op = prompts.OpFactResolve
	}
	limit := opts.EvidenceLimit
	if limit <= 0 {
		limit = 8
	}

	var (
		id          int64
		category    string
		key         string
		gapPrompt   sql.NullString
		candidatesQ sql.NullString
	)
	err := db.QueryRowContext(ctx, `
		SELECT id, category, key,
		       COALESCE(gap_prompt, '') AS gap_prompt,
		       COALESCE(candidates_q, '') AS candidates_q
		  FROM app_facts
		 WHERE value IS NULL AND app = $1
		 ORDER BY category, key
		 LIMIT 1`, opts.App).Scan(&id, &category, &key, &gapPrompt, &candidatesQ)
	if errors.Is(err, sql.ErrNoRows) {
		return &GapPayload{GapID: 0, Message: "no open gaps"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("kb_pull_gap: select gap: %w", err)
	}

	evidence, err := fetchGapEvidence(ctx, db, opts.App, candidatesQ.String, limit)
	if err != nil {
		return nil, err
	}

	tmpl, err := prompts.Get(op)
	if err != nil {
		return nil, fmt.Errorf("kb_pull_gap: %w", err)
	}
	evJSON, _ := json.Marshal(evidence)
	rendered := tmpl.Render(map[string]string{
		"gap_prompt":    gapPrompt.String,
		"evidence_json": string(evJSON),
	})

	return &GapPayload{
		GapID:        id,
		App:          opts.App,
		Category:     category,
		Key:          key,
		Prompt:       rendered,
		OutputFormat: tmpl.OutputFormat,
		Schema:       tmpl.Schema,
		Evidence:     evidence,
	}, nil
}

// fetchGapEvidence resolves the FTS query stored on
// app_facts.candidates_q to a list of supporting modules. When
// candidatesQ is empty the fallback returns the most-recently-seen
// modules for the app — better than returning nothing.
func fetchGapEvidence(ctx context.Context, db *sql.DB, app, candidatesQ string, limit int) ([]GapEvidence, error) {
	var rows *sql.Rows
	var err error
	if strings.TrimSpace(candidatesQ) != "" {
		rows, err = db.QueryContext(ctx, `
			SELECT m.id, COALESCE(m.name, ''),
			       COALESCE(m.body_excerpt, ''),
			       COALESCE(m.symbols_json, '')
			  FROM modules m
			 WHERE m.search_text ILIKE '%' || $1 || '%' AND m.app = $2
			 ORDER BY length(m.search_text) ASC
			 LIMIT $3`, candidatesQ, app, limit)
	} else {
		rows, err = db.QueryContext(ctx, `
			SELECT id, COALESCE(name, ''),
			       COALESCE(body_excerpt, ''),
			       COALESCE(symbols_json, '')
			  FROM modules
			 WHERE app = $1
			 ORDER BY COALESCE(last_seen_at, 0) DESC, id DESC
			 LIMIT $2`, app, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("kb_pull_gap: evidence query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []GapEvidence
	for rows.Next() {
		var e GapEvidence
		if err := rows.Scan(&e.ModuleID, &e.Name, &e.BodyExcerpt, &e.SymbolsJSON); err != nil {
			return nil, fmt.Errorf("kb_pull_gap: scan evidence: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("kb_pull_gap: iterate evidence: %w", err)
	}
	return out, nil
}

// PushAnswer writes opts.Value back into app_facts(id=opts.GapID) and
// appends a fact_history row in a single transaction. Returns an error
// when GapID is zero, the row does not exist, or any SQL step fails.
func PushAnswer(ctx context.Context, db *sql.DB, opts PushAnswerOptions) (*PushAnswerPayload, error) {
	if db == nil {
		return nil, errors.New("kb_push_answer: nil db")
	}
	if opts.GapID == 0 {
		return nil, errors.New("kb_push_answer: gap_id required")
	}
	sourceStep := opts.SourceStep
	if sourceStep == "" {
		sourceStep = "claude_mcp"
	}

	now := time.Now().UnixMilli()
	evJSON := "[]"
	if len(opts.EvidenceIDs) > 0 {
		raw, err := json.Marshal(opts.EvidenceIDs)
		if err != nil {
			return nil, fmt.Errorf("kb_push_answer: marshal evidence_ids: %w", err)
		}
		evJSON = string(raw)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("kb_push_answer: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		UPDATE app_facts
		   SET value = $1, evidence_ids = $2, confidence = $3,
		       source_step = $4, filled_at = $5, updated_at = $6
		 WHERE id = $7`,
		opts.Value, evJSON, opts.Confidence, sourceStep, now, now, opts.GapID)
	if err != nil {
		return nil, fmt.Errorf("kb_push_answer: update app_facts: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("kb_push_answer: no app_facts row with id=%d", opts.GapID)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO fact_history
		    (fact_id, value, evidence_ids, source_step, confidence, observed_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 ON CONFLICT(fact_id, observed_at) DO NOTHING`,
		opts.GapID, opts.Value, evJSON, sourceStep, opts.Confidence, now); err != nil {
		return nil, fmt.Errorf("kb_push_answer: insert fact_history: %w", err)
	}

	var app, category, key string
	if err := tx.QueryRowContext(ctx, `SELECT app, category, key FROM app_facts WHERE id = $1`, opts.GapID).
		Scan(&app, &category, &key); err != nil {
		return nil, fmt.Errorf("kb_push_answer: re-read app_facts: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("kb_push_answer: commit: %w", err)
	}
	return &PushAnswerPayload{
		OK:       true,
		GapID:    opts.GapID,
		App:      app,
		Category: category,
		Key:      key,
	}, nil
}
