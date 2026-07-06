/*
Copyright (c) 2026 Security Research
*/
// kb_doctor — extracted out of internal/supervisor/kb_dispatch.go
// (Phase A7) so the supervisor dispatcher and the MCP tool share one
// source of truth. Folds in the catalog summary + meaning-layer
// coverage signal currently surfaced by pkg/mcp/tools/kb_resolve.go's
// handleKBDoctor.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/findings"
)

// DoctorOptions controls Doctor's behaviour. App is an optional filter
// echoed back in the report — kept open for tightening later.
type DoctorOptions struct {
	App string `json:"app,omitempty"`
}

// DoctorCatalogSummary is the cheap "is this catalog populated" signal
// surfaced alongside the connectivity probe. Mirrors the CatalogSummary
// in pkg/mcp/tools/kb_resolve.go.
type DoctorCatalogSummary struct {
	Apps             int    `json:"apps"`
	KnowledgeSources int    `json:"knowledge_sources"`
	MigrationVersion uint   `json:"migration_version"`
	MigrationDirty   bool   `json:"migration_dirty"`
	SummaryErr       string `json:"summary_error,omitempty"`
}

// DoctorReport is the response body for Doctor. Fields are stable JSON
// snake_case. ModulesTotal + AppCount are derived from kbstore.Stats so
// thin-client callers do not need to round-trip a second verb.
type DoctorReport struct {
	OK                      bool                 `json:"ok"`
	DBOpen                  bool                 `json:"db_open"`
	PingError               string               `json:"ping_error,omitempty"`
	StatsError              string               `json:"stats_error,omitempty"`
	ModulesTotal            int                  `json:"modules_total"`
	AppCount                int                  `json:"app_count"`
	MeaningLayerCoveragePct int                  `json:"meaning_layer_coverage_pct"`
	FindingsTotal           int                  `json:"findings_total"`
	OpenContradictionsCount int                  `json:"open_contradictions_count"`
	Catalog                 DoctorCatalogSummary `json:"catalog"`
	App                     string               `json:"app,omitempty"`
}

// Doctor runs a best-effort health check against db: pings the
// connection, summarises the kb_apps / knowledge_sources catalog,
// computes the meaning-layer coverage (modules with non-NULL summary),
// and folds the kbstore.Stats totals into the report. Any individual
// probe failure is captured in the corresponding *Err field rather than
// surfaced as a Go error — Doctor only returns an error when db is nil.
func Doctor(ctx context.Context, db *sql.DB, opts DoctorOptions) (*DoctorReport, error) {
	if db == nil {
		return nil, errors.New("kb_doctor: nil db")
	}

	report := &DoctorReport{
		DBOpen: true,
		App:    opts.App,
	}

	if err := db.PingContext(ctx); err != nil {
		report.DBOpen = false
		report.PingError = err.Error()
	}

	report.Catalog = doctorCatalog(ctx, db)
	report.MeaningLayerCoveragePct = doctorMeaningCoverage(ctx, db)

	// AI Adjudication findings (Phase 21 C)
	if fSum, err := findings.Summary(db, opts.App); err == nil {
		report.FindingsTotal = fSum.TotalFindings
		report.OpenContradictionsCount = fSum.ByStance[string(findings.StanceContradict)]
	}

	rows, err := Stats(db)
	if err != nil {
		report.StatsError = err.Error()
	} else {
		appSet := make(map[string]struct{})
		for _, r := range rows {
			report.ModulesTotal += r.Total
			appSet[r.App] = struct{}{}
		}
		report.AppCount = len(appSet)
	}

	report.OK = report.DBOpen && report.Catalog.SummaryErr == "" && report.StatsError == ""
	return report, nil
}

// doctorCatalog is best-effort; any error is captured in SummaryErr.
func doctorCatalog(ctx context.Context, db *sql.DB) DoctorCatalogSummary {
	var c DoctorCatalogSummary
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM kb_apps`).Scan(&c.Apps); err != nil {
		c.SummaryErr = fmt.Errorf("kb_apps: %w", err).Error()
		return c
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM knowledge_sources`).Scan(&c.KnowledgeSources); err != nil {
		c.SummaryErr = fmt.Errorf("knowledge_sources: %w", err).Error()
		return c
	}
	var v sql.NullInt64
	var d sql.NullBool
	if err := db.QueryRowContext(ctx, `SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&v, &d); err == nil {
		if v.Valid {
			c.MigrationVersion = uint(v.Int64)
		}
		c.MigrationDirty = d.Bool
	}
	return c
}

// doctorMeaningCoverage returns the percentage of modules (all apps)
// with a non-NULL summary. Returns 0 on any error (best-effort signal).
func doctorMeaningCoverage(ctx context.Context, db *sql.DB) int {
	var pct int
	err := db.QueryRowContext(ctx,
		`SELECT COALESCE(
			SUM(CASE WHEN summary IS NOT NULL THEN 1 ELSE 0 END) * 100
			/ NULLIF(COUNT(*), 0),
		0) FROM modules`).Scan(&pct)
	if err != nil {
		return 0
	}
	return pct
}
