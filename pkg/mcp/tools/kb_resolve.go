/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"

	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/pkg/config"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CatalogSummary is the cheapest "is this catalog populated" signal.
type CatalogSummary struct {
	Apps             int    `json:"apps"`
	Sources          int    `json:"knowledge_sources"`
	MigrationVersion uint   `json:"migration_version"`
	Dirty            bool   `json:"migration_dirty"`
	SummaryErr       string `json:"summary_error,omitempty"`
}

// ResolvedInfo describes which Postgres catalog a kb_* tool resolved,
// derived from the live connection (never from a DSN string) so no
// password is ever handled. Source records where the DSN came from.
type ResolvedInfo struct {
	Database string         `json:"database"`
	User     string         `json:"user"`
	Host     string         `json:"host"`
	Port     int            `json:"port"`
	Source   string         `json:"source"` // tool-arg | config.yaml
	Catalog  CatalogSummary `json:"catalog"`
}

// DSNDisplay is the password-free user@host:port/db identity string.
func (r ResolvedInfo) DSNDisplay() string {
	return fmt.Sprintf("%s@%s:%d/%s", r.User, r.Host, r.Port, r.Database)
}

// Text renders a single-line, password-free description.
func (r ResolvedInfo) Text() string {
	errSuffix := ""
	if r.Catalog.SummaryErr != "" {
		errSuffix = " summary_error=" + r.Catalog.SummaryErr
	}
	return fmt.Sprintf("resolved postgres %s@%s:%d/%s source=%s catalog: kb_apps=%d knowledge_sources=%d migration=%d dirty=%t%s",
		r.User, r.Host, r.Port, r.Database, r.Source,
		r.Catalog.Apps, r.Catalog.Sources, r.Catalog.MigrationVersion, r.Catalog.Dirty, errSuffix)
}

// resolveDSN reports the effective DSN and its source. config.yaml is the single
// source of truth (written by `unravel db setup`), matching the CLI resolver
// (cmd/kb_output.ResolveDSN) and the MCP startup pool; the legacy UNRAVEL_KB_DSN /
// UNRAVEL_KB_DB env fallbacks were removed so there is exactly one DSN source.
// Precedence: explicit per-call tool-arg > config.yaml.
func resolveDSN(dsnOverride string) (dsn, source string) {
	if dsnOverride != "" {
		return dsnOverride, "tool-arg"
	}
	cfg, err := config.Load()
	if err != nil {
		return "", "config.yaml"
	}
	d, err := cfg.DSN(context.Background())
	if err != nil {
		return "", "config.yaml"
	}
	return d, "config.yaml"
}

// resolveSource reports where the DSN originates (thin wrapper over resolveDSN).
func resolveSource(dsnOverride string) string {
	_, s := resolveDSN(dsnOverride)
	return s
}

// kbResolve opens the Postgres catalog and derives a password-free
// ResolvedInfo from the live connection plus a best-effort catalog
// summary. The summary never blocks the caller — on failure it is
// reported via Catalog.SummaryErr.
func kbResolve(ctx context.Context, dsnOverride string) (*sql.DB, ResolvedInfo, error) {
	eff, src := resolveDSN(dsnOverride)
	db, err := kbdb.Open(ctx, eff)
	if err != nil {
		return nil, ResolvedInfo{Source: src}, fmt.Errorf("kb open (source=%s): %w", src, err)
	}
	info := ResolvedInfo{Source: src}
	var host sql.NullString
	var port sql.NullInt64
	if err := db.QueryRowContext(ctx,
		`SELECT current_database(), current_user,
		        host(coalesce(inet_server_addr(),'127.0.0.1'::inet)),
		        coalesce(inet_server_port(),5432)`).
		Scan(&info.Database, &info.User, &host, &port); err != nil {
		slog.Debug("kbResolve: identity probe failed", "err", err, "source", src)
	}
	if host.Valid {
		info.Host = host.String
	}
	if port.Valid {
		info.Port = int(port.Int64)
	}
	info.Catalog = summarizeCatalog(ctx, db)
	return db, info, nil
}

// emptyResultDiagnostic builds the text + structured payload attached to
// any kb_* result that came back empty/zero, so "nothing matched" is
// never confusable with "wrong/empty catalog".
func emptyResultDiagnostic(info ResolvedInfo, what string) (string, map[string]any) {
	hint := ""
	if info.Catalog.Sources == 0 && info.Catalog.SummaryErr == "" {
		hint = " — catalog has zero knowledge_sources; this DB is empty (wrong DSN, or corpus not captured here)"
	}
	text := fmt.Sprintf("no %s matched. %s%s", what, info.Text(), hint)
	structured := map[string]any{
		"returned":    0,
		"resolved_db": info.DSNDisplay(),
		"source":      info.Source,
		"catalog":     info.Catalog,
		"hint":        hint,
	}
	return text, structured
}

type kbDoctorInput struct {
	DB  string `json:"db,omitempty"  jsonschema:"DEPRECATED: ignored. Supervisor-routed since v2.17."`
	App string `json:"app,omitempty" jsonschema:"optional app slug filter forwarded to supervisor"`
}

// handleKBDoctor routes through the supervisor thin-client (v2.17 / B3).
// Wire-shape NOTE: prior to B3 this tool emitted
// {meaning_layer_coverage_pct, ok, resolved_db, source, catalog, text}.
// From B3 onward it emits the supervisor.KBDoctorResult payload (which
// is the kbstore.DoctorReport snake_case shape) with an added `source`
// field recording where the DSN originates. `resolved_db` and `text` are
// dropped — the supervisor never reveals server-side identity strings
// through this verb.
func handleKBDoctor(ctx context.Context, _ *mcp.CallToolRequest, in kbDoctorInput) (*mcp.CallToolResult, any, error) {
	cli, err := getKBClient(ctx)
	if err != nil {
		if r := supervisorUnavailableResult(err); r != nil {
			return r, nil, nil
		}
		return errorResult(err), nil, nil
	}

	out, err := cli.Doctor(ctx, supervisor.KBDoctorParams{App: in.App})
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(map[string]any{
		"report": out,
		"source": resolveSource(in.DB),
	}), nil, nil
}

// meaningLayerCoveragePct returns the percentage of modules (all apps) that
// have a non-NULL summary. Returns 0 on any error (best-effort).
func meaningLayerCoveragePct(ctx context.Context, db *sql.DB) int {
	if db == nil {
		return 0
	}
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

// summarizeCatalog is best-effort; any error is captured, not fatal.
func summarizeCatalog(ctx context.Context, db *sql.DB) CatalogSummary {
	var c CatalogSummary
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM kb_apps`).Scan(&c.Apps); err != nil {
		c.SummaryErr = err.Error()
		return c
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM knowledge_sources`).Scan(&c.Sources); err != nil {
		c.SummaryErr = err.Error()
		return c
	}
	var v sql.NullInt64
	var d sql.NullBool
	if err := db.QueryRowContext(ctx, `SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&v, &d); err == nil {
		if v.Valid {
			c.MigrationVersion = uint(v.Int64)
		}
		c.Dirty = d.Bool // false is the safe default when the column is NULL
	}
	return c
}
