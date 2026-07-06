/*
Copyright (c) 2026 Security Research

Package classify is the DB-touching layer that materializes component.Apply
verdicts as rows in module_components. It is the only Phase 31 package that
touches the DB.

Per D-31-CLASSIFY-TX, Run opens its own short transaction with READ
COMMITTED isolation; the tx is NOT shared with ingest.

Per D-31-NO-COMPONENT-DELETES-ON-RECLASSIFY, the UPSERT preserves rows
where classifier='manual' (analyst override) or 'llm' (future v2). Only
'rule' / 'heuristic' rows are overwritten on re-classify.
*/
package classify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Report summarizes one classify run.
type Report struct {
	KBID              string         `json:"kb_id"`
	Epoch             int64          `json:"epoch"`
	ModulesClassified int            `json:"modules_classified"`
	Skipped           int            `json:"skipped"`
	BucketCounts      map[string]int `json:"bucket_counts"`
}

// Querier is the minimal interface classify.Run needs. *sql.DB satisfies it;
// tests can supply a mock.
type Querier interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// rowQuerier is the minimal subset of *sql.DB / *sql.Tx that
// LoadSnapshotModules needs. Defined here so the helper can run either
// inside an existing tx (classify.Run) or directly against a *sql.DB
// (corpus generator).
type rowQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// ModuleRow is the snapshot module shape consumed by both the classify
// pipeline and the corpus draft generator. Mirrors the columns selected by
// LoadSnapshotModules. JSON tags use snake_case to match P34 CLI parity.
type ModuleRow struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Path        string `json:"path"`         // sourced from modules.body_excerpt
	SymbolsJSON string `json:"symbols_json"` // sourced from modules.symbols_json
}

// LoadSnapshotModules returns every module belonging to (kbID, epoch) joined
// through knowledge_sources. Used by classify.Run (inside a tx) and by the
// corpus draft generator (directly on *sql.DB). Behavior-preserving extraction
// of the query previously inlined in Run.
func LoadSnapshotModules(ctx context.Context, db rowQuerier, kbID string, epoch int64) ([]ModuleRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT m.id, m.name, COALESCE(m.body_excerpt,''), COALESCE(m.symbols_json,'')
		 FROM modules m
		 JOIN knowledge_sources ks ON ks.id = m.first_source_id
		 WHERE ks.kb_id = $1 AND ks.epoch = $2`,
		kbID, epoch,
	)
	if err != nil {
		return nil, fmt.Errorf("load snapshot modules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ModuleRow
	for rows.Next() {
		var m ModuleRow
		if scanErr := rows.Scan(&m.ID, &m.Name, &m.Path, &m.SymbolsJSON); scanErr != nil {
			return nil, fmt.Errorf("scan module: %w", scanErr)
		}
		out = append(out, m)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate modules: %w", rowsErr)
	}
	return out, nil
}

// LoadCumulativeModules returns every module first sighted under kbID across
// ALL of its epochs — the "current modules for this app" union — as opposed to
// LoadSnapshotModules which is scoped to a single epoch. Used by cumulative
// consumers (kb show counts, mappers) that must not under-report when an app's
// modules are spread over multiple index epochs. classify.Run and the corpus
// generator deliberately keep using the per-epoch LoadSnapshotModules.
//
// Keyed on modules.first_source_id (set once at first INSERT and COALESCE-pinned
// thereafter), so each module maps to exactly one knowledge_sources row — the
// epoch it was FIRST seen in, not necessarily the latest. That is the right key
// for "union across epochs": a module first seen in epoch N is counted exactly
// once regardless of how many later epochs re-observe it.
func LoadCumulativeModules(ctx context.Context, db rowQuerier, kbID string) ([]ModuleRow, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT m.id, m.name, COALESCE(m.body_excerpt,''), COALESCE(m.symbols_json,'')
		   FROM modules m
		   JOIN knowledge_sources ks ON ks.id = m.first_source_id
		  WHERE ks.kb_id = $1
		  ORDER BY m.id`,
		kbID,
	)
	if err != nil {
		return nil, fmt.Errorf("load cumulative modules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ModuleRow
	for rows.Next() {
		var m ModuleRow
		if scanErr := rows.Scan(&m.ID, &m.Name, &m.Path, &m.SymbolsJSON); scanErr != nil {
			return nil, fmt.Errorf("scan module: %w", scanErr)
		}
		out = append(out, m)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterate modules: %w", rowsErr)
	}
	return out, nil
}

// Options parameterizes Run with the chosen Classifier strategy and (in
// future) per-run knobs. The zero value means "use RuleClassifier" so all
// existing callers stay green during the Phase 45 migration.
//
// D-45-CLASSIFY-V2-INTERFACE: the Classifier seam is the only mechanism
// by which classify.Run obtains per-module verdicts; concrete strategies
// (rule, mcp, composite) are constructed in Select.
type Options struct {
	// Classifier produces per-module verdicts. nil => RuleClassifier{}.
	Classifier Classifier
}

// Run classifies every module belonging to (kbID, epoch). When epoch <= 0,
// the latest epoch for kbID is resolved via SELECT MAX(epoch). Per
// D-31-CLASSIFY-TX, the call opens its own short transaction with READ
// COMMITTED isolation. Per D-31-NO-COMPONENT-DELETES-ON-RECLASSIFY (as
// extended by Plan 45-02), the UPSERT preserves rows where
// classifier='manual' (analyst override) — re-classify runs MAY UPDATE
// 'rule' / 'heuristic' / 'llm' rows so the MCP path can supersede a
// stale rule verdict on subsequent runs.
//
// Backwards-compatible signature: callers passing only (ctx,db,kbID,epoch)
// get the default RuleClassifier. New callers should use RunWithOptions.
func Run(ctx context.Context, db Querier, kbID string, epoch int64) (*Report, error) {
	return RunWithOptions(ctx, db, kbID, epoch, Options{})
}

// RunWithOptions is Run + an Options struct. Phase 45 / LLMC-02.
func RunWithOptions(ctx context.Context, db Querier, kbID string, epoch int64, opts Options) (*Report, error) {
	if kbID == "" {
		return nil, errors.New("kb_id is empty")
	}
	clf := opts.Classifier
	if clf == nil {
		clf = RuleClassifier{}
	}
	promptVer := clf.PromptVersion()
	if epoch <= 0 {
		var latest sql.NullInt64
		err := db.QueryRowContext(ctx,
			`SELECT MAX(epoch) FROM knowledge_sources WHERE kb_id = $1`, kbID,
		).Scan(&latest)
		if err != nil {
			return nil, fmt.Errorf("resolve latest epoch: %w", err)
		}
		if !latest.Valid {
			return &Report{KBID: kbID, BucketCounts: map[string]int{}}, nil
		}
		epoch = latest.Int64
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	mods, err := LoadSnapshotModules(ctx, tx, kbID, epoch)
	if err != nil {
		return nil, err
	}

	rep := &Report{KBID: kbID, Epoch: epoch, BucketCounts: map[string]int{}}
	now := time.Now().UnixMilli()
	for _, m := range mods {
		res, cerr := clf.Classify(ctx, m)
		if cerr != nil {
			slog.Warn("classify: classifier returned error", "module_id", m.ID, "classifier", clf.Name(), "err", cerr)
			rep.Skipped++
			continue
		}

		// Per-row prompt_version: written for classifier='llm' rows
		// (the MCP path), NULL otherwise. The composite wrapper may
		// have fallen back to rule for THIS module — in that case
		// res.Classifier == "rule" and we write NULL even though the
		// outer strategy is the composite.
		var pv any
		if res.Classifier == "llm" && promptVer != "" {
			pv = promptVer
		} else {
			pv = nil
		}

		// D-31-NO-COMPONENT-DELETES-ON-RECLASSIFY: UPSERT preserves
		// classifier='manual' rows (analyst override). Re-classify
		// runs MAY overwrite 'rule' / 'heuristic' / 'llm' rows so the
		// MCP path can supersede a stale rule verdict on subsequent
		// runs. (Plan 45-02 explicitly extends preservation to skip
		// 'manual' only.)
		if _, execErr := tx.ExecContext(ctx,
			`INSERT INTO module_components (module_id, component, confidence, classifier, classified_at, prompt_version)
			 VALUES ($1, $2, $3, $4, $5, $6)
			 ON CONFLICT (module_id) DO UPDATE
				SET component      = EXCLUDED.component,
				    confidence     = EXCLUDED.confidence,
				    classifier     = EXCLUDED.classifier,
				    classified_at  = EXCLUDED.classified_at,
				    prompt_version = EXCLUDED.prompt_version
			  WHERE module_components.classifier IN ('rule','heuristic','llm')`,
			m.ID, res.Component, res.Confidence, res.Classifier, now, pv,
		); execErr != nil {
			slog.Warn("classify upsert failed", "module_id", m.ID, "err", execErr)
			rep.Skipped++
			continue
		}
		rep.ModulesClassified++
		rep.BucketCounts[res.Component]++
	}
	if commitErr := tx.Commit(); commitErr != nil {
		return nil, fmt.Errorf("commit: %w", commitErr)
	}
	return rep, nil
}
