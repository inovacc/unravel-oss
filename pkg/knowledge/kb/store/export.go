/*
Copyright (c) 2026 Security Research
*/
// Export — legacy-format KB DB-row collection.
//
// Extracted out of cmd/kb_export.go (the `runKbExport` / `collectDBRows`
// pair) so the supervisor dispatcher (internal/supervisor/kb_dispatch.go)
// and the cmd-side CLI share one source of truth for the DB-reading
// portion of the legacy export. File-I/O, tarball assembly, manifest
// generation, and signing remain in cmd/kb_export.go (legacy + bundle +
// fidelity modes). See
// docs/superpowers/plans/2026-05-27-v2.17-thinclient-refactor.md
// (Phase A2).
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

// ExportSchemaVersion is the legacy kb-export.json schema version. Bump
// only when on-disk consumers (kb import) need a coordinated change.
const ExportSchemaVersion = 1

// ExportKBAppRow is the kb_apps row dumped by Export.
type ExportKBAppRow struct {
	KBID          string          `json:"kb_id"`
	CanonicalName string          `json:"canonical_name"`
	DisplayName   string          `json:"display_name"`
	Platform      string          `json:"platform"`
	Publisher     sql.NullString  `json:"publisher"`
	PublisherCN   sql.NullString  `json:"publisher_cn"`
	Framework     sql.NullString  `json:"framework"`
	PackageID     sql.NullString  `json:"package_id"`
	FirstSeenAt   int64           `json:"first_seen_at"`
	LastSeenAt    int64           `json:"last_seen_at"`
	Tags          []string        `json:"tags"`
	Metadata      json.RawMessage `json:"metadata"`
}

// ExportAliasRow is a kb_aliases row.
type ExportAliasRow struct {
	AliasKBID     string         `json:"alias_kb_id"`
	CanonicalKBID string         `json:"canonical_kb_id"`
	MergedAt      int64          `json:"merged_at"`
	MergedBy      sql.NullString `json:"merged_by"`
	Reason        sql.NullString `json:"reason"`
}

// ExportSnapshotRow is a knowledge_sources row.
type ExportSnapshotRow struct {
	ID             int64          `json:"id"`
	App            string         `json:"app"`
	Epoch          int64          `json:"epoch"`
	SourcePath     string         `json:"source_path"`
	SourceKind     string         `json:"source_kind"`
	AppVersion     sql.NullString `json:"app_version"`
	SourceSHA256   sql.NullString `json:"source_sha256"`
	CapturedAt     int64          `json:"captured_at"`
	ModulesIndexed int64          `json:"modules_indexed"`
	BodiesIndexed  int64          `json:"bodies_indexed"`
	KBID           string         `json:"kb_id"`
	KSID           string         `json:"ks_id"`
	Framework      sql.NullString `json:"framework"`
	RiskScore      sql.NullInt64  `json:"risk_score"`
	RiskLevel      sql.NullString `json:"risk_level"`
	DepthScore     sql.NullInt64  `json:"depth_score"`
	DepthCovered   []string       `json:"depth_covered"`
	DepthMissing   []string       `json:"depth_missing"`
	BinarySHA256   sql.NullString `json:"binary_sha256"`
}

// ExportModuleRow is a modules row joined to module_components.
type ExportModuleRow struct {
	ID               int64          `json:"id"`
	App              string         `json:"app"`
	Name             string         `json:"name"`
	BodySHA256       string         `json:"body_sha256"`
	BodySize         sql.NullInt64  `json:"body_size"`
	FirstSeenAt      sql.NullInt64  `json:"first_seen_at"`
	LastSeenAt       sql.NullInt64  `json:"last_seen_at"`
	FirstSourceID    sql.NullInt64  `json:"first_source_id"`
	LastSourceID     sql.NullInt64  `json:"last_source_id"`
	Component        sql.NullString `json:"component"`
	ClassifierSource sql.NullString `json:"classifier_source"`
}

// ExportMARRow is a module_app_refs row.
type ExportMARRow struct {
	BodySHA256 string `json:"body_sha256"`
	App        string `json:"app"`
	SourceID   int64  `json:"source_id"`
	ObservedAt int64  `json:"observed_at"`
}

// ExportFileRow is a files row.
type ExportFileRow struct {
	FileSHA256  string `json:"file_sha256"`
	FileSize    int64  `json:"file_size"`
	FirstSeenAt int64  `json:"first_seen_at"`
}

// ExportFARRow is a file_app_refs row.
type ExportFARRow struct {
	FileSHA256 string `json:"file_sha256"`
	SourceID   int64  `json:"source_id"`
	RelPath    string `json:"rel_path"`
	ObservedAt int64  `json:"observed_at"`
}

// ExportFactRow is an app_facts row.
type ExportFactRow struct {
	App        string         `json:"app"`
	Category   string         `json:"category"`
	Key        string         `json:"key"`
	Value      sql.NullString `json:"value"`
	SourceStep sql.NullString `json:"source_step"`
}

// ExportDiffRow is a kb_diffs row.
type ExportDiffRow struct {
	FromSourceID int64           `json:"from_source_id"`
	ToSourceID   int64           `json:"to_source_id"`
	Category     string          `json:"category"`
	ChangeType   string          `json:"change_type"`
	Identifier   string          `json:"identifier"`
	Payload      json.RawMessage `json:"payload"`
	ComputedAt   int64           `json:"computed_at"`
}

// ExportPayload is the in-memory result of Export. Its JSON shape is
// byte-for-byte compatible with the kb-export.json file emitted by the
// legacy `unravel kb export` command prior to the A2 extraction.
type ExportPayload struct {
	SchemaVersion      int                 `json:"schema_version"`
	ExportedAt         int64               `json:"exported_at"`
	ExportedUnderAlias bool                `json:"exported_under_alias"`
	KBApp              *ExportKBAppRow     `json:"kb_app"`
	Aliases            []ExportAliasRow    `json:"aliases"`
	Snapshots          []ExportSnapshotRow `json:"snapshots"`
	Modules            []ExportModuleRow   `json:"modules"`
	ModuleAppRefs      []ExportMARRow      `json:"module_app_refs"`
	Files              []ExportFileRow     `json:"files"`
	FileAppRefs        []ExportFARRow      `json:"file_app_refs"`
	AppFacts           []ExportFactRow     `json:"app_facts"`
	KBDiffs            []ExportDiffRow     `json:"kb_diffs"`

	// SnapshotIDs is the list of knowledge_sources.id values that backed
	// the export. Callers that need to walk the on-disk version dirs use
	// this to enumerate per-epoch artefacts. Not part of the wire schema
	// emitted to kb-export.json — JSON tag is "-".
	SnapshotIDs []int64 `json:"-"`
	// Canonical is the resolved canonical kb_id (after alias resolution).
	Canonical string `json:"-"`
}

// ExportOptions controls Export's scoping.
type ExportOptions struct {
	// LatestOnly limits the export to the newest epoch's snapshot.
	LatestOnly bool
}

// Export collects all DB rows that constitute a legacy kb-export.json
// payload for kbID. Alias resolution is performed first: if kbID is an
// alias, the canonical id is used and ExportedUnderAlias is set true.
//
// Filesystem artefacts (per-epoch version dirs, tarball assembly,
// signing) are the CLI's responsibility — call SnapshotIDs to enumerate
// epochs that need to be walked.
//
// kbID must be non-empty.
func Export(ctx context.Context, db *sql.DB, kbID string, opts ExportOptions) (*ExportPayload, error) {
	if kbID == "" {
		return nil, fmt.Errorf("kb_id required")
	}

	canonical, err := identity.ResolveAlias(ctx, db, kbID)
	if err != nil {
		return nil, fmt.Errorf("resolve alias: %w", err)
	}
	underAlias := canonical != kbID

	ksIDs, err := queryExportSnapshotIDs(ctx, db, canonical, opts.LatestOnly)
	if err != nil {
		return nil, err
	}

	payload, err := collectExportRows(ctx, db, canonical, ksIDs, underAlias)
	if err != nil {
		return nil, err
	}
	payload.SnapshotIDs = ksIDs
	payload.Canonical = canonical
	return payload, nil
}

// queryExportSnapshotIDs returns the knowledge_sources.id values to
// include in the export, ordered ASC by epoch (DESC LIMIT 1 if
// latestOnly).
func queryExportSnapshotIDs(ctx context.Context, db *sql.DB, canonical string, latestOnly bool) ([]int64, error) {
	var query string
	if latestOnly {
		query = `SELECT id FROM knowledge_sources
		         WHERE kb_id = $1 AND ks_id IS NOT NULL
		         ORDER BY epoch DESC LIMIT 1`
	} else {
		query = `SELECT id FROM knowledge_sources
		         WHERE kb_id = $1 AND ks_id IS NOT NULL
		         ORDER BY epoch ASC`
	}
	rows, err := db.QueryContext(ctx, query, canonical)
	if err != nil {
		return nil, fmt.Errorf("query snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan snapshot id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshots: %w", err)
	}
	return ids, nil
}

// collectExportRows fills an ExportPayload with all per-row data for the
// given canonical kb_id and ks_id set. Mirrors the legacy
// collectDBRows from cmd/kb_export.go byte-for-byte at the SQL level.
func collectExportRows(ctx context.Context, db *sql.DB, kbID string, ksIDs []int64, underAlias bool) (*ExportPayload, error) {
	payload := &ExportPayload{
		SchemaVersion:      ExportSchemaVersion,
		ExportedAt:         time.Now().Unix(),
		ExportedUnderAlias: underAlias,
	}

	if err := loadExportKBApp(ctx, db, kbID, payload); err != nil {
		return nil, err
	}
	if err := loadExportAliases(ctx, db, kbID, payload); err != nil {
		return nil, err
	}
	if err := loadExportSnapshots(ctx, db, ksIDs, payload); err != nil {
		return nil, err
	}
	if err := loadExportModuleAppRefs(ctx, db, ksIDs, payload); err != nil {
		return nil, err
	}
	if err := loadExportModules(ctx, db, ksIDs, payload); err != nil {
		return nil, err
	}
	if err := loadExportFileAppRefs(ctx, db, ksIDs, payload); err != nil {
		return nil, err
	}
	if err := loadExportFiles(ctx, db, ksIDs, payload); err != nil {
		return nil, err
	}
	if err := loadExportAppFacts(ctx, db, payload); err != nil {
		return nil, err
	}
	if err := loadExportKBDiffs(ctx, db, ksIDs, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func loadExportKBApp(ctx context.Context, db *sql.DB, kbID string, payload *ExportPayload) error {
	payload.KBApp = &ExportKBAppRow{}
	err := db.QueryRowContext(ctx, `
		SELECT kb_id, canonical_name, display_name, platform, publisher,
		       publisher_cn, framework, package_id, first_seen_at, last_seen_at,
		       tags, COALESCE(metadata, '{}'::jsonb)
		FROM kb_apps WHERE kb_id = $1`,
		kbID).Scan(
		&payload.KBApp.KBID, &payload.KBApp.CanonicalName, &payload.KBApp.DisplayName,
		&payload.KBApp.Platform, &payload.KBApp.Publisher,
		&payload.KBApp.PublisherCN, &payload.KBApp.Framework, &payload.KBApp.PackageID,
		&payload.KBApp.FirstSeenAt, &payload.KBApp.LastSeenAt,
		(*pq.StringArray)(&payload.KBApp.Tags), &payload.KBApp.Metadata,
	)
	if err != nil {
		return fmt.Errorf("query kb_app: %w", err)
	}
	return nil
}

func loadExportAliases(ctx context.Context, db *sql.DB, kbID string, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT alias_kb_id, canonical_kb_id, merged_at, merged_by, reason
		FROM kb_aliases WHERE canonical_kb_id = $1`, kbID)
	if err != nil {
		return fmt.Errorf("query aliases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportAliasRow
		if err := rows.Scan(&r.AliasKBID, &r.CanonicalKBID, &r.MergedAt, &r.MergedBy, &r.Reason); err != nil {
			return fmt.Errorf("scan alias: %w", err)
		}
		payload.Aliases = append(payload.Aliases, r)
	}
	return rows.Err()
}

func loadExportSnapshots(ctx context.Context, db *sql.DB, ksIDs []int64, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT
		id, app, epoch, source_path, source_kind, app_version,
		source_sha256, captured_at, modules_indexed, bodies_indexed,
		kb_id, ks_id, framework, risk_score, risk_level,
		depth_score, depth_covered, depth_missing, binary_sha256
		FROM knowledge_sources WHERE id = ANY($1)`, pq.Array(ksIDs))
	if err != nil {
		return fmt.Errorf("query snapshots: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportSnapshotRow
		if err := rows.Scan(
			&r.ID, &r.App, &r.Epoch, &r.SourcePath, &r.SourceKind, &r.AppVersion,
			&r.SourceSHA256, &r.CapturedAt, &r.ModulesIndexed, &r.BodiesIndexed,
			&r.KBID, &r.KSID, &r.Framework, &r.RiskScore, &r.RiskLevel,
			&r.DepthScore, (*pq.StringArray)(&r.DepthCovered), (*pq.StringArray)(&r.DepthMissing), &r.BinarySHA256,
		); err != nil {
			return fmt.Errorf("scan snapshot: %w", err)
		}
		payload.Snapshots = append(payload.Snapshots, r)
	}
	return rows.Err()
}

func loadExportModuleAppRefs(ctx context.Context, db *sql.DB, ksIDs []int64, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT body_sha256, app, source_id, observed_at
		FROM module_app_refs WHERE source_id = ANY($1)`, pq.Array(ksIDs))
	if err != nil {
		return fmt.Errorf("query module_app_refs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportMARRow
		if err := rows.Scan(&r.BodySHA256, &r.App, &r.SourceID, &r.ObservedAt); err != nil {
			return fmt.Errorf("scan module_app_ref: %w", err)
		}
		payload.ModuleAppRefs = append(payload.ModuleAppRefs, r)
	}
	return rows.Err()
}

func loadExportModules(ctx context.Context, db *sql.DB, ksIDs []int64, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT m.id, m.app, m.name, m.body_sha256, m.body_size,
		m.first_seen_at, m.last_seen_at, m.first_source_id, m.last_source_id,
		mc.component, mc.classifier
		FROM modules m
		LEFT JOIN module_components mc ON mc.module_id = m.id
		WHERE m.id IN (SELECT module_id FROM module_app_refs WHERE source_id = ANY($1))`, pq.Array(ksIDs))
	if err != nil {
		return fmt.Errorf("query modules: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportModuleRow
		if err := rows.Scan(
			&r.ID, &r.App, &r.Name, &r.BodySHA256, &r.BodySize,
			&r.FirstSeenAt, &r.LastSeenAt, &r.FirstSourceID, &r.LastSourceID,
			&r.Component, &r.ClassifierSource,
		); err != nil {
			return fmt.Errorf("scan module: %w", err)
		}
		payload.Modules = append(payload.Modules, r)
	}
	return rows.Err()
}

func loadExportFileAppRefs(ctx context.Context, db *sql.DB, ksIDs []int64, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT file_sha256, source_id, rel_path, observed_at
		FROM file_app_refs WHERE source_id = ANY($1)`, pq.Array(ksIDs))
	if err != nil {
		return fmt.Errorf("query file_app_refs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportFARRow
		if err := rows.Scan(&r.FileSHA256, &r.SourceID, &r.RelPath, &r.ObservedAt); err != nil {
			return fmt.Errorf("scan file_app_ref: %w", err)
		}
		payload.FileAppRefs = append(payload.FileAppRefs, r)
	}
	return rows.Err()
}

func loadExportFiles(ctx context.Context, db *sql.DB, ksIDs []int64, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT file_sha256, file_size, first_seen_at
		FROM files WHERE file_sha256 IN (SELECT file_sha256 FROM file_app_refs WHERE source_id = ANY($1))`, pq.Array(ksIDs))
	if err != nil {
		return fmt.Errorf("query files: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportFileRow
		if err := rows.Scan(&r.FileSHA256, &r.FileSize, &r.FirstSeenAt); err != nil {
			return fmt.Errorf("scan file: %w", err)
		}
		payload.Files = append(payload.Files, r)
	}
	return rows.Err()
}

func loadExportAppFacts(ctx context.Context, db *sql.DB, payload *ExportPayload) error {
	if payload.KBApp == nil {
		return nil
	}
	rows, err := db.QueryContext(ctx, `SELECT app, category, key, value, source_step
		FROM app_facts WHERE app = $1`, payload.KBApp.CanonicalName)
	if err != nil {
		return fmt.Errorf("query app_facts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportFactRow
		if err := rows.Scan(&r.App, &r.Category, &r.Key, &r.Value, &r.SourceStep); err != nil {
			return fmt.Errorf("scan app_fact: %w", err)
		}
		payload.AppFacts = append(payload.AppFacts, r)
	}
	return rows.Err()
}

func loadExportKBDiffs(ctx context.Context, db *sql.DB, ksIDs []int64, payload *ExportPayload) error {
	rows, err := db.QueryContext(ctx, `SELECT from_source_id, to_source_id, category, change_type,
		identifier, payload, computed_at
		FROM kb_diffs WHERE from_source_id = ANY($1) AND to_source_id = ANY($1)`, pq.Array(ksIDs))
	if err != nil {
		return fmt.Errorf("query kb_diffs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r ExportDiffRow
		if err := rows.Scan(&r.FromSourceID, &r.ToSourceID, &r.Category, &r.ChangeType, &r.Identifier, &r.Payload, &r.ComputedAt); err != nil {
			return fmt.Errorf("scan kb_diff: %w", err)
		}
		payload.KBDiffs = append(payload.KBDiffs, r)
	}
	return rows.Err()
}
