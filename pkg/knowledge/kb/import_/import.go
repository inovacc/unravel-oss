/*
Copyright (c) 2026 Security Research

Package import_ reads a D-43-BUNDLE-SCHEMA-V1 bundle (directory tree or
.kbb.tar.gz) and writes its rows back into kb_apps + knowledge_sources +
app_facts + kb_diffs idempotently via ON CONFLICT DO NOTHING (round-trip
counterpart to pkg/knowledge/kb/export).

Package name is `import_` (with trailing underscore) because `import` is a
Go reserved word. The underscored suffix is the canonical Go workaround.

D-09 inviolate: NO anthropic / claude imports.
*/
package import_

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
)

// MaxBundleEntries caps tar entry count to bound DoS impact (T-43-08).
const MaxBundleEntries = 100_000

// ImportReport summarizes what an Import call applied to the database.
//
// NewRowsCount and ConflictsSkipped are mutually exclusive per row: every
// upserted row is counted in exactly one bucket per table.
type ImportReport struct {
	KbID             string         `json:"kb_id"`
	Counts           export.Counts  `json:"counts"`
	NewRowsCount     map[string]int `json:"new_rows"`
	ConflictsSkipped map[string]int `json:"conflicts_skipped"`
}

// Importer is the testable DB-write seam. Production callers use Import
// (which wraps a *sql.DB via dbImporter); tests substitute an in-memory
// implementation.
type Importer interface {
	BeginTx(ctx context.Context) (Tx, error)
}

// Tx is the per-transaction write surface. ON CONFLICT DO NOTHING is the
// only conflict policy used; each method returns (newRow bool) — true when
// a fresh row was inserted, false when the row collided.
type Tx interface {
	UpsertKbApp(ctx context.Context, kbID, platform, packageID string) (bool, error)
	UpsertSource(ctx context.Context, kbID string, epoch int64, sourceSHA string, payload json.RawMessage) (bool, error)
	UpsertFact(ctx context.Context, kbID string, epoch int64, category, key, value string) (bool, error)
	UpsertDiff(ctx context.Context, kbID string, fromEpoch, toEpoch int64, payload json.RawMessage) (bool, error)
	Commit() error
	Rollback() error
}

// Import reads a bundle (.kbb.tar.gz file OR a bundle directory tree),
// validates the manifest checksum, and writes rows back into the supplied
// *sql.DB inside a single transaction. ON CONFLICT DO NOTHING for every
// upsert — re-importing the same bundle is a no-op (KBIM-03 idempotency).
//
// Mitigates:
//   - T-43-05 (path traversal): tar entries with `..` or absolute paths are rejected.
//   - T-43-06 (tampered knowledge.json): sha256 checksum re-computed and compared.
//   - T-43-08 (zip-bomb-style nesting): MaxBundleEntries cap on tar entry count.
//   - T-43-09 (cross-major schema bundle): bundle_schema_version != 1 rejected.
func Import(ctx context.Context, db *sql.DB, bundlePath string) (*ImportReport, error) {
	if db == nil {
		return nil, errors.New("kb_import: nil db")
	}
	return ImportWithImporter(ctx, &dbImporter{db: db}, bundlePath)
}

// ImportWithImporter is the testable entry point. Production callers should
// use Import.
func ImportWithImporter(ctx context.Context, im Importer, bundlePath string) (*ImportReport, error) {
	if im == nil {
		return nil, errors.New("kb_import: nil importer")
	}
	if bundlePath == "" {
		return nil, errors.New("kb_import: bundlePath is empty")
	}

	dir, cleanup, err := materializeBundle(bundlePath)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	manifest, knowledgeBytes, sources, facts, diffs, err := readBundle(dir)
	if err != nil {
		return nil, err
	}

	// Verify checksum (T-43-06).
	if manifest.Checksum != "" {
		sum := sha256.Sum256(knowledgeBytes)
		got := hex.EncodeToString(sum[:])
		if got != manifest.Checksum {
			return nil, fmt.Errorf("kb_import: checksum mismatch (manifest=%s computed=%s)", manifest.Checksum, got)
		}
	}

	report := &ImportReport{
		KbID:             manifest.KbID,
		Counts:           manifest.Counts,
		NewRowsCount:     map[string]int{},
		ConflictsSkipped: map[string]int{},
	}

	tx, err := im.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("kb_import: begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// kb_apps
	{
		newRow, err := tx.UpsertKbApp(ctx, manifest.KbID, manifest.Platform, manifest.PackageID)
		if err != nil {
			return nil, fmt.Errorf("kb_import: upsert kb_apps: %w", err)
		}
		bumpCount(report, "kb_apps", newRow)
	}

	// knowledge_sources
	for _, s := range sources {
		newRow, err := tx.UpsertSource(ctx, manifest.KbID, s.Epoch, s.SourceSHA256, s.JSON)
		if err != nil {
			return nil, fmt.Errorf("kb_import: upsert source epoch=%d: %w", s.Epoch, err)
		}
		bumpCount(report, "knowledge_sources", newRow)
	}

	// app_facts
	for _, f := range facts {
		newRow, err := tx.UpsertFact(ctx, manifest.KbID, f.Epoch, f.Category, f.Key, f.Value)
		if err != nil {
			return nil, fmt.Errorf("kb_import: upsert fact %s/%s: %w", f.Category, f.Key, err)
		}
		bumpCount(report, "app_facts", newRow)
	}

	// kb_diffs
	for _, d := range diffs {
		newRow, err := tx.UpsertDiff(ctx, manifest.KbID, d.FromEpoch, d.ToEpoch, d.Payload)
		if err != nil {
			return nil, fmt.Errorf("kb_import: upsert diff %d->%d: %w", d.FromEpoch, d.ToEpoch, err)
		}
		bumpCount(report, "kb_diffs", newRow)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("kb_import: commit: %w", err)
	}
	committed = true
	return report, nil
}

func bumpCount(r *ImportReport, table string, newRow bool) {
	if newRow {
		r.NewRowsCount[table]++
	} else {
		r.ConflictsSkipped[table]++
	}
}

// materializeBundle returns a directory containing bundle.json. If
// bundlePath is a directory, it's used as-is (cleanup is a no-op). If
// bundlePath is a regular file, it's treated as .kbb.tar.gz and extracted
// into a tempdir; cleanup removes that tempdir.
func materializeBundle(bundlePath string) (string, func(), error) {
	info, err := os.Stat(bundlePath)
	if err != nil {
		return "", func() {}, fmt.Errorf("kb_import: stat bundle: %w", err)
	}
	if info.IsDir() {
		return bundlePath, func() {}, nil
	}

	// Tar.gz extraction.
	tmp, err := os.MkdirTemp("", "unravel-kb-import-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("kb_import: mktemp: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(tmp) }

	if err := extractTarGz(bundlePath, tmp); err != nil {
		cleanup()
		return "", func() {}, err
	}

	// Bundle inside the tarball is wrapped as <kb_id>.kbb/. Find it.
	entries, err := os.ReadDir(tmp)
	if err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("kb_import: read tmp: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		full := filepath.Join(tmp, e.Name())
		if _, err := os.Stat(filepath.Join(full, "bundle.json")); err == nil {
			return full, cleanup, nil
		}
	}
	cleanup()
	return "", func() {}, errors.New("kb_import: bundle.json not found in tarball")
}

// extractTarGz extracts bundlePath into dest. Reject entries with `..` or
// absolute paths (T-43-05). Cap entry count at MaxBundleEntries (T-43-08).
func extractTarGz(bundlePath, dest string) error {
	f, err := os.Open(bundlePath) //nolint:gosec // bundle path supplied by operator
	if err != nil {
		return fmt.Errorf("kb_import: open tarball: %w", err)
	}
	defer func() { _ = f.Close() }()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("kb_import: gzip: %w", err)
	}
	defer func() { _ = gr.Close() }()

	// maxBundleTotalBytes caps total decompressed output at 2 GiB across all
	// entries — bundles beyond this size are indicative of a decompression bomb.
	const maxBundleTotalBytes int64 = 2 * 1024 << 20 // 2 GiB

	tr := tar.NewReader(gr)
	count := 0
	var totalDecompressed int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("kb_import: tar.Next: %w", err)
		}
		count++
		if count > MaxBundleEntries {
			return fmt.Errorf("kb_import: bundle entry count exceeds limit %d", MaxBundleEntries)
		}

		name := hdr.Name
		// T-43-05 path-traversal guards.
		if strings.Contains(name, "..") || filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
			return fmt.Errorf("kb_import: bundle entry %q is unsafe", name)
		}
		// Defense in depth: also clean and re-check.
		clean := filepath.ToSlash(filepath.Clean(name))
		if strings.HasPrefix(clean, "..") || strings.Contains(clean, "/../") {
			return fmt.Errorf("kb_import: bundle entry %q is unsafe (post-clean)", name)
		}

		target := filepath.Join(dest, filepath.FromSlash(name))
		// Final defense — ensure the resolved path stays under dest.
		absDest, _ := filepath.Abs(dest)
		absTarget, _ := filepath.Abs(target)
		rel, relErr := filepath.Rel(absDest, absTarget)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("kb_import: bundle entry %q escapes destination", name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("kb_import: mkdir %s: %w", target, err)
			}
		case tar.TypeReg:
			// Per-entry cap: a single bundle entry should never legitimately
			// exceed 256 MiB; reject it up-front using the declared header size.
			const maxBundleEntryBytes = 256 << 20 // 256 MiB
			if hdr.Size > maxBundleEntryBytes {
				return fmt.Errorf("kb_import: entry %q declared size %d exceeds %d-byte cap", name, hdr.Size, maxBundleEntryBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("kb_import: mkdir parent %s: %w", target, err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec // dest is operator-controlled tempdir
			if err != nil {
				return fmt.Errorf("kb_import: create %s: %w", target, err)
			}
			// Use LimitReader on top of CopyN so that even if the actual
			// decompressed stream exceeds hdr.Size we stay bounded.
			n, copyErr := io.CopyN(out, io.LimitReader(tr, maxBundleEntryBytes), hdr.Size)
			if copyErr != nil && !errors.Is(copyErr, io.EOF) {
				_ = out.Close()
				return fmt.Errorf("kb_import: copy %s: %w", target, copyErr)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("kb_import: close %s: %w", target, err)
			}
			totalDecompressed += n
			if totalDecompressed > maxBundleTotalBytes {
				return fmt.Errorf("kb_import: total decompressed size exceeds %d-byte cap (decompression bomb)", maxBundleTotalBytes)
			}
		default:
			// Symlinks / hardlinks / device nodes are rejected outright.
			return fmt.Errorf("kb_import: bundle entry %q has unsupported type %d", name, hdr.Typeflag)
		}
	}
	return nil
}

// readBundle parses bundle.json and per-table sub-trees from a bundle
// directory. Returns manifest, raw knowledge.json bytes (for checksum
// verification), and per-table row slices.
func readBundle(dir string) (*export.BundleManifest, []byte, []export.Source, []export.Fact, []export.Diff, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("kb_import: read bundle.json: %w", err)
	}
	manifest, err := export.UnmarshalManifest(manifestBytes)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if manifest.BundleSchemaVersion != export.BundleSchemaVersion {
		return nil, nil, nil, nil, nil, fmt.Errorf("kb_import: bundle_schema_version %d unsupported (want %d)",
			manifest.BundleSchemaVersion, export.BundleSchemaVersion)
	}

	knowledgeBytes, err := os.ReadFile(filepath.Join(dir, "knowledge.json"))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("kb_import: read knowledge.json: %w", err)
	}

	sources, err := readSources(filepath.Join(dir, "knowledge_sources"))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	facts, err := readFacts(filepath.Join(dir, "app_facts"))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	diffs, err := readDiffs(filepath.Join(dir, "kb_diffs"))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return manifest, knowledgeBytes, sources, facts, diffs, nil
}

func readSources(dir string) ([]export.Source, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("kb_import: read knowledge_sources: %w", err)
	}
	var out []export.Source
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Filename: <epoch>-<shortSHA>.json
		base := strings.TrimSuffix(e.Name(), ".json")
		var epoch int64
		var sha string
		i := strings.IndexByte(base, '-')
		if i <= 0 {
			return nil, fmt.Errorf("kb_import: malformed source filename %q", e.Name())
		}
		n, _ := fmt.Sscanf(base[:i], "%d", &epoch)
		if n != 1 {
			return nil, fmt.Errorf("kb_import: malformed source filename %q", e.Name())
		}
		sha = base[i+1:]
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("kb_import: read source %s: %w", e.Name(), err)
		}
		out = append(out, export.Source{Epoch: epoch, SourceSHA256: sha, JSON: json.RawMessage(raw)})
	}
	return out, nil
}

func readFacts(dir string) ([]export.Fact, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("kb_import: read app_facts: %w", err)
	}
	var out []export.Fact
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("kb_import: read facts %s: %w", e.Name(), err)
		}
		for _, line := range splitLines(raw) {
			if len(line) == 0 {
				continue
			}
			var rec struct {
				Epoch    int64  `json:"epoch"`
				Category string `json:"category"`
				Key      string `json:"key"`
				Value    string `json:"value"`
			}
			if err := json.Unmarshal(line, &rec); err != nil {
				return nil, fmt.Errorf("kb_import: parse fact line in %s: %w", e.Name(), err)
			}
			out = append(out, export.Fact{
				Epoch: rec.Epoch, Category: rec.Category, Key: rec.Key, Value: rec.Value,
			})
		}
	}
	return out, nil
}

func splitLines(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := range b {
		if b[i] == '\n' {
			if i > start {
				out = append(out, b[start:i])
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func readDiffs(dir string) ([]export.Diff, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("kb_import: read kb_diffs: %w", err)
	}
	var out []export.Diff
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		// Filename: <from>-<to>.json
		base := strings.TrimSuffix(e.Name(), ".json")
		var fromEp, toEp int64
		n, _ := fmt.Sscanf(base, "%d-%d", &fromEp, &toEp)
		if n != 2 {
			return nil, fmt.Errorf("kb_import: malformed diff filename %q", e.Name())
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("kb_import: read diff %s: %w", e.Name(), err)
		}
		out = append(out, export.Diff{FromEpoch: fromEp, ToEpoch: toEp, Payload: json.RawMessage(raw)})
	}
	return out, nil
}

// dbImporter wraps *sql.DB to satisfy Importer.
type dbImporter struct{ db *sql.DB }

func (d *dbImporter) BeginTx(ctx context.Context) (Tx, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &dbTx{tx: tx, now: time.Now().UnixMilli()}, nil
}

// dbTx writes import rows into a real Postgres database. ON CONFLICT keys:
//   - kb_apps: PRIMARY KEY (kb_id)
//   - knowledge_sources: partial UNIQUE INDEX (kb_id, epoch) WHERE kb_id IS NOT NULL
//   - app_facts: UNIQUE (app, category, key) — uses canonical name from kb_apps
//   - kb_diffs: PK (from_source_id, to_source_id, category, change_type, identifier)
//
// kb_diffs storage shape differs from the bundle's per-(from_epoch,to_epoch)
// payload: each bundle entry materializes as one row with category='import',
// change_type='added', identifier='<from>-<to>' so re-import collides cleanly.
type dbTx struct {
	tx  *sql.Tx
	now int64
}

func (t *dbTx) UpsertKbApp(ctx context.Context, kbID, platform, packageID string) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `
INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, package_id, first_seen_at, last_seen_at)
VALUES ($1, $1, $1, $2, NULLIF($3, ''), $4, $4)
ON CONFLICT (kb_id) DO NOTHING`,
		kbID, platform, packageID, t.now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (t *dbTx) UpsertSource(ctx context.Context, kbID string, epoch int64, sourceSHA string, payload json.RawMessage) (bool, error) {
	// knowledge_sources requires app/source_path/source_kind/captured_at NOT NULL.
	// Use kbID as `app` (legacy column) plus deterministic synthetic values so
	// re-import is idempotent.
	res, err := t.tx.ExecContext(ctx, `
INSERT INTO knowledge_sources
  (app, epoch, source_path, source_kind, source_sha256, captured_at, kb_id, ks_id)
VALUES
  ($1, $2, $3, $4, NULLIF($5, ''), $6, $1, $7)
ON CONFLICT (kb_id, epoch) WHERE kb_id IS NOT NULL DO NOTHING`,
		kbID, epoch, fmt.Sprintf("imported://%s/%d", kbID, epoch), "import", sourceSHA, t.now, fmt.Sprintf("%s-%d", kbID, epoch))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (t *dbTx) UpsertFact(ctx context.Context, kbID string, epoch int64, category, key, value string) (bool, error) {
	res, err := t.tx.ExecContext(ctx, `
INSERT INTO app_facts (app, category, key, value, filled_at, updated_at)
VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5)
ON CONFLICT (app, category, key) DO NOTHING`,
		kbID, category, key, value, t.now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (t *dbTx) UpsertDiff(ctx context.Context, kbID string, fromEpoch, toEpoch int64, payload json.RawMessage) (bool, error) {
	// Resolve source IDs for the given (kb_id, epoch) pairs. If either is
	// missing (e.g. import order vs source upsert), skip with conflict.
	var fromID, toID int64
	err := t.tx.QueryRowContext(ctx,
		`SELECT id FROM knowledge_sources WHERE kb_id = $1 AND epoch = $2`, kbID, fromEpoch).Scan(&fromID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = t.tx.QueryRowContext(ctx,
		`SELECT id FROM knowledge_sources WHERE kb_id = $1 AND epoch = $2`, kbID, toEpoch).Scan(&toID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	res, err := t.tx.ExecContext(ctx, `
INSERT INTO kb_diffs (from_source_id, to_source_id, category, change_type, identifier, payload, computed_at)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
ON CONFLICT (from_source_id, to_source_id, category, change_type, identifier) DO NOTHING`,
		fromID, toID, "import", "added", fmt.Sprintf("%d-%d", fromEpoch, toEpoch), string(payload), t.now)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (t *dbTx) Commit() error   { return t.tx.Commit() }
func (t *dbTx) Rollback() error { return t.tx.Rollback() }

// Compile-time interface checks.
var _ Importer = (*dbImporter)(nil)
var _ Tx = (*dbTx)(nil)
