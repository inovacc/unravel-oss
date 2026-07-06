/*
Copyright (c) 2026 Security Research
*/
// Import — legacy-format KB DB-row write back from a D-43 bundle.
//
// Extracted out of cmd/kb_import.go (and pkg/knowledge/kb/import_) so the
// supervisor dispatcher (internal/supervisor/kb_dispatch.go) and the
// cmd-side CLI share one source of truth for the DB-writing portion of
// the legacy import. File I/O, tarball extraction, manifest parsing,
// path-traversal guards, and Ed25519 signature verification remain in
// cmd/kb_import.go and pkg/knowledge/kb/import_ (the bundle materializer +
// reader). See
// docs/superpowers/plans/2026-05-27-v2.17-thinclient-refactor.md
// (Phase A3).
//
// The store-level Import is a thin DB-write wrapper around
// pkg/knowledge/kb/import_.Import: it performs the bundle-path → *sql.DB
// transaction and returns a stable snake_case payload that mirrors what
// the wire surface emits.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	kbimport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/import_"
)

// ImportOptions controls Import's behavior.
//
// BundlePath is required and points at either:
//   - a .kbb.tar.gz file produced by kb export --bundle, or
//   - a directory tree at <root>/<kb_id>.kbb/ (or that directory itself).
//
// Filesystem reads, tarball extraction, manifest parsing, and signature
// verification are the caller's responsibility (the CLI runs those before
// invoking Import). The bundle materializer in pkg/knowledge/kb/import_
// re-runs path-traversal guards as defense-in-depth.
type ImportOptions struct {
	BundlePath string `json:"bundle_path"`
	// App is an optional override for the app/canonical-name field. When
	// empty (the common case), the manifest's kb_id is used. Reserved for
	// callers that want to retarget the import; carried for wire-shape
	// compatibility with KBImportParams.App.
	App string `json:"app,omitempty"`
	// VerifyKeyPath is an optional path to a 32-byte raw Ed25519 public key
	// ("-" reads stdin). When non-empty, Import enforces signature
	// verification of a V2 bundle before any DB write — closing the
	// provenance-bypass parity gap so the supervisor/MCP import path can
	// verify, not only the CLI (hardening finding #7). Empty (the default)
	// preserves existing opt-in behavior per ADR-0007.
	VerifyKeyPath string `json:"verify_key_path,omitempty"`
}

// ImportPayload is the result of Import. Counts are per-table:
//
//   - new_rows: rows that were freshly inserted (RowsAffected > 0).
//   - conflicts_skipped: rows that collided on the table's ON CONFLICT
//     key and were left untouched (re-import path; KBIM-03 idempotency).
//
// imported_count is the sum of all new_rows values — a convenience
// scalar so callers can short-circuit on "did anything change".
type ImportPayload struct {
	KBID             string         `json:"kb_id"`
	ImportedCount    int            `json:"imported_count"`
	NewRows          map[string]int `json:"new_rows"`
	ConflictsSkipped map[string]int `json:"conflicts_skipped"`
	Counts           ImportCounts   `json:"counts"`
}

// ImportCounts mirrors the bundle manifest's per-table totals (the
// declared row counts the bundle was built with). Drift between Counts
// and NewRows+ConflictsSkipped indicates a malformed bundle.
type ImportCounts struct {
	KnowledgeSources int `json:"knowledge_sources"`
	AppFacts         int `json:"app_facts"`
	KBDiffs          int `json:"kb_diffs"`
}

// Import reads the bundle pointed at by opts.BundlePath, validates its
// checksum, and writes its rows into db inside a single transaction.
// Idempotent on re-import: every upsert uses ON CONFLICT DO NOTHING.
//
// Returns a stable snake_case ImportPayload that mirrors the wire shape
// the supervisor emits over IPC.
func Import(ctx context.Context, db *sql.DB, opts ImportOptions) (*ImportPayload, error) {
	if db == nil {
		return nil, errors.New("kb_import: nil db")
	}
	if opts.BundlePath == "" {
		return nil, errors.New("kb_import: bundle_path required")
	}

	// Provenance gate (hardening finding #7): when an operator supplies a
	// pinned verify key, enforce the Ed25519 bundle signature before any DB
	// write — so the supervisor/MCP path reaches CLI parity instead of
	// importing with zero integrity enforcement. Opt-in: a no-op when
	// VerifyKeyPath is empty (the default), preserving ADR-0007 behavior.
	if err := VerifyBundleProvenance(opts.BundlePath, opts.VerifyKeyPath); err != nil {
		return nil, fmt.Errorf("kb_import: %w", err)
	}

	report, err := kbimport.Import(ctx, db, opts.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("import bundle: %w", err)
	}

	out := &ImportPayload{
		KBID:             report.KbID,
		NewRows:          report.NewRowsCount,
		ConflictsSkipped: report.ConflictsSkipped,
		Counts: ImportCounts{
			KnowledgeSources: report.Counts.KnowledgeSources,
			AppFacts:         report.Counts.AppFacts,
			KBDiffs:          report.Counts.KbDiffs,
		},
	}
	if out.NewRows == nil {
		out.NewRows = map[string]int{}
	}
	if out.ConflictsSkipped == nil {
		out.ConflictsSkipped = map[string]int{}
	}
	for _, n := range out.NewRows {
		out.ImportedCount += n
	}
	return out, nil
}
