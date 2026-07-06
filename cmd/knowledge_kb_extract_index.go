/*
Copyright (c) 2026 Security Research
*/
// Package cmd / knowledge_kb_extract_index.go houses the `kb extract`,
// `kb index`, `kb search`, and `kb dump` subcommands of `unravel knowledge`,
// along with their co-located unexported helpers and SQL constants.
// Split out from cmd/knowledge.go in Phase 66 Plan 02 (D-66-01, D-66-03,
// D-66-06). Zero behavior change vs. pre-refactor layout — cobra
// `AddCommand` registration order for these commands is preserved in
// cmd/knowledge.go's init() function.
//
// Symbols owned by this file (canonical D-66-03 set):
//
//	kbOpenDB(dsnOverride)            — DB-open thin wrapper (also called by
//	                                   knowledge_doctor.go, knowledge_ingest.go,
//	                                   knowledge_sources.go, db_migrate.go,
//	                                   and the remaining run* funcs in
//	                                   knowledge.go — all same-package).
//	kbBundleMarkers [][]byte         — JS bundle detection patterns
//	                                   (runKBExtract-only).
//	readAll(r, max)                  — bounded io.Reader drain
//	                                   (runKBExtract-only).
//	anyContains(haystack, needles)   — multi-needle bytes.Contains
//	                                   (runKBExtract-only).
//	kbIndexUpsertSQL                 — modules upsert (also referenced by
//	                                   knowledge_ingest.go — same package).
//	kbIndexSightingSQL               — module_sightings upsert (also ingest).
//	kbIndexBodySQL                   — module_bodies upsert (also ingest).
//	kbExtractCmd / kbIndexCmd /
//	kbSearchCmd / kbDumpCmd          — cobra command declarations.
//	runKBExtract / runKBIndex /
//	runKBSearch / runKBDump          — RunE entry points.
//
// Transitive-sweep additions beyond D-66-03: NONE. The grep across cmd/
// confirmed all unexported funcs/types/consts/vars in the moving range
// either (a) are in the canonical D-66-03 set above, or (b) are referenced
// from outside the moving cohort and must stay in cmd/knowledge.go
// (e.g. kbOpenDB references from runKBPending/Summarize/Stats/Enrich/etc.
// remain valid via package-scoped cross-file access — that's the whole
// point of D-66-03's co-location-with-primary-caller rule).
package cmd

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	kbscan "github.com/inovacc/unravel-oss/pkg/knowledge/kb/scanner"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/sources"
	kbstore "github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"

	"github.com/spf13/cobra"
)

// ─────────────────────────────────────────────────────────────────────
// command definitions
// ─────────────────────────────────────────────────────────────────────

var kbExtractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract JS bundles from a Chromium Block File Cache directory",
	Long: `Walk a Cache_Data directory (Chromium block-file format), gunzip each
f_NNNNNN body, and write any that look like JS bundles (Meta __d / standard
webpack / next-stream / SystemJS) into the destination directory.

Examples:
  unravel knowledge extract \
      --src "$LOCALAPPDATA/Packages/<aumid>/.../Cache/Cache_Data" \
      --dst "$KB_ROOT/WhatsApp/08-extracted-modules"`,
	RunE: runKBExtract,
}

var kbIndexCmd = &cobra.Command{
	Use:   "index",
	Short: "Index extracted JS bundles into a Postgres + pg_trgm knowledge base",
	Long: `Walk a directory of .js bundles, parse out every module definition
(Meta __d for WhatsApp, webpack numeric ids for Teams/Slack/LinkedIn), and
insert one row per module into the knowledge DB. Every body is SHA-256 hashed
and tracked in module_history so repeat runs surface code drift.`,
	RunE: runKBIndex,
}

var kbDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Print one module row (full body excerpt, summary, tags)",
	RunE:  runKBDump,
}

// ─────────────────────────────────────────────────────────────────────
// catalog: kbOpenDB + extract / index / search / dump
// ─────────────────────────────────────────────────────────────────────

// kbOpenDB opens the catalog DB. Thin wrapper around pkg/knowledge/kb/db.Open
// retained so the rest of cmd/* keeps the same call shape.
//
// As of v3.0 the argument is a DSN override (postgres:// URL), not a SQLite
// file path. An empty string falls back to config.yaml + keychain.
func kbOpenDB(dsnOverride string) (*sql.DB, error) {
	return kbdb.Open(context.Background(), dsnOverride)
}

// JS bundle marker patterns that appear in the first ~4 KB of a real bundle.
// We want false positives to be cheap to discard later, false negatives are
// expensive (we miss a bundle entirely), so the list errs broad.
var kbBundleMarkers = [][]byte{
	[]byte("WAWeb"),
	[]byte("webpackJsonp"),
	[]byte("webpackChunk"),
	[]byte(`__d("`),
	[]byte("System.register"),
	[]byte("__webpack_require"),
	[]byte("self.__next_f"),
}

func runKBExtract(_ *cobra.Command, _ []string) error {
	if err := os.MkdirAll(kbExtractDst, 0o755); err != nil {
		return fmt.Errorf("mkdir dst: %w", err)
	}
	entries, err := os.ReadDir(kbExtractSrc)
	if err != nil {
		return fmt.Errorf("read src: %w", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "f_") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(kbExtractSrc, e.Name()))
		if err != nil {
			continue
		}
		// Try gzip → brotli → raw. Chromium stores responses with the original
		// transport encoding; modern web servers commonly use brotli, so the
		// raw f_NNN body for many sites is `Content-Encoding: br`.
		body := raw
		if gz, err := gzip.NewReader(bytes.NewReader(raw)); err == nil {
			if dec, derr := readAll(gz, 8<<20); derr == nil && len(dec) > 0 {
				body = dec
			}
			_ = gz.Close()
		} else if dec, derr := readAll(brotli.NewReader(bytes.NewReader(raw)), 8<<20); derr == nil && len(dec) > len(raw)/2 {
			// Heuristic: a successful brotli decode usually expands the input
			// well past the compressed size. Bail if it didn't expand at all
			// to avoid keeping garbage from a misclassified file.
			body = dec
		}
		head := body
		if len(head) > 4096 {
			head = head[:4096]
		}
		if !anyContains(head, kbBundleMarkers) {
			continue
		}
		out := filepath.Join(kbExtractDst, e.Name()+".js")
		if err := os.WriteFile(out, body, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "warn: write %s: %v\n", out, err)
			continue
		}
		count++
	}
	fmt.Printf("%d bundles -> %s\n", count, kbExtractDst)
	return nil
}

func readAll(r interface {
	Read(p []byte) (int, error)
}, max int) ([]byte, error) {
	var buf bytes.Buffer
	tmp := make([]byte, 64*1024)
	for buf.Len() < max {
		n, err := r.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.Bytes(), nil
}

func anyContains(haystack []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// SQL prepared by runKBIndex per micro-transaction. Kept as package-level
// constants so each new tx in the per-batch loop can re-prepare them
// (statements are tx-scoped and become invalid after commit).
const kbIndexUpsertSQL = `INSERT INTO modules
		(app, name, synthetic_name, prefix, body_size, body_excerpt, body_sha256,
		 symbols_json, first_seen_at, last_seen_at, is_vendored)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (app, body_sha256) DO UPDATE SET
			last_seen_at = excluded.last_seen_at,
			-- Vendored-OSS mark (KB-OVERSEG P3): latch to true once any pass
			-- recognises the body as third-party. Never flips back to false so
			-- a later partial-excerpt pass can't un-mark a known vendored row.
			is_vendored = modules.is_vendored OR excluded.is_vendored,
			-- Promote a richer name if the new pass managed to extract one
			-- (e.g. WAWebMsgCollection wins over teams_module_509).
			name = CASE
				WHEN modules.name LIKE E'%\\_module\\_%' AND excluded.name NOT LIKE E'%\\_module\\_%'
				THEN excluded.name
				ELSE modules.name
			END,
			-- Refresh symbols_json when the new pass produced a richer JSON
			-- (heuristic: prefer the longer payload). Lets re-sweeps benefit
			-- from extractor improvements without nuking the DB.
			symbols_json = CASE
				WHEN excluded.symbols_json IS NOT NULL
					AND LENGTH(excluded.symbols_json) > COALESCE(LENGTH(modules.symbols_json), 0)
				THEN excluded.symbols_json
				ELSE modules.symbols_json
			END`

const kbIndexSightingSQL = `INSERT INTO module_sightings
		(module_id, source_file, byte_offset, observed_at)
		VALUES (
			(SELECT id FROM modules WHERE app = $1 AND body_sha256 = $2),
			$3, $4, $5)
		ON CONFLICT (module_id, source_file, byte_offset) DO NOTHING`

const kbIndexBodySQL = `INSERT INTO module_bodies
		(body_sha256, body, body_size, stored_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (body_sha256) DO NOTHING`

func runKBIndex(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(kbIndexDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	// Allocate the knowledge_sources row for this pass before any modules
	// land. Epoch is per-app monotonic; LinkLastSource at the end fills
	// modules.first_source_id / last_source_id for every row touched
	// during this pass (60s grace window covers clock skew + the indexer
	// loop itself).
	src, err := sources.Begin(context.Background(), db, sources.Source{
		App:        kbIndexApp,
		SourcePath: kbIndexSrc,
		Kind:       sources.KindCache,
		ReuseEpoch: kbIndexReuseEpoch,
	})
	if err != nil {
		return fmt.Errorf("source begin: %w", err)
	}
	kbIndexLastEpoch = src.Epoch
	fmt.Fprintf(os.Stderr, "source: app=%s epoch=%d id=%d\n", src.App, src.Epoch, src.ID)

	// Effective batch size: env var overrides --batch / programmatic value.
	// 0 means "single transaction (legacy)" so completed sweeps end with
	// identical on-disk state to the old code path.
	batchSize := kbIndexBatch
	if v := strings.TrimSpace(os.Getenv("UNRAVEL_KB_BATCH")); v != "" {
		if n, perr := strconv.Atoi(v); perr == nil && n >= 0 {
			batchSize = n
		} else {
			fmt.Fprintf(os.Stderr, "warn: ignoring invalid UNRAVEL_KB_BATCH=%q\n", v)
		}
	}

	// Per-batch tx state. Statements are re-prepared on each new tx because
	// prepared statements are scoped to the tx that created them.
	var (
		tx       *sql.Tx
		upsert   *sql.Stmt
		sighting *sql.Stmt
		bodyStmt *sql.Stmt
	)
	closeStmts := func() {
		if upsert != nil {
			_ = upsert.Close()
		}
		if sighting != nil {
			_ = sighting.Close()
		}
		if bodyStmt != nil {
			_ = bodyStmt.Close()
		}
		upsert, sighting, bodyStmt = nil, nil, nil
	}
	beginBatch := func() error {
		t, berr := db.Begin()
		if berr != nil {
			return fmt.Errorf("begin tx: %w", berr)
		}
		tx = t
		// Upsert is keyed on (app, body_sha256) — one row per distinct body.
		// Re-running the indexer over the same files is now a near no-op except
		// for last_seen_at refresh + new sightings.
		upsert, err = tx.Prepare(kbIndexUpsertSQL)
		if err != nil {
			return fmt.Errorf("prepare upsert: %w", err)
		}
		sighting, err = tx.Prepare(kbIndexSightingSQL)
		if err != nil {
			return fmt.Errorf("prepare sighting: %w", err)
		}
		bodyStmt, err = tx.Prepare(kbIndexBodySQL)
		if err != nil {
			return fmt.Errorf("prepare bodies: %w", err)
		}
		return nil
	}
	if err := beginBatch(); err != nil {
		return err
	}
	// Safety net: if we exit via panic/early return after this point, drop
	// the in-flight tx so we don't leak a busy connection. On the happy
	// path tx is already nil by the time we return.
	defer func() {
		closeStmts()
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	// flushBatch commits the in-flight tx (releasing per-batch progress to
	// disk so a subsequent crash/timeout cannot wipe it) and immediately
	// opens a fresh tx + statements so the caller can keep writing.
	// The search_text generated column is maintained by Postgres on write,
	// so per-batch commit is safe — every committed row is already covered
	// by the GIN pg_trgm index.
	batchModules := 0
	flushBatch := func() error {
		if tx == nil {
			return nil
		}
		closeStmts()
		if cerr := tx.Commit(); cerr != nil {
			tx = nil
			return fmt.Errorf("commit batch: %w", cerr)
		}
		tx = nil
		return beginBatch()
	}

	var totalFiles, totalModules, kept, droppedTiny, droppedHuge int
	werr := filepath.WalkDir(kbIndexSrc, func(path string, d iofs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".js") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "warn: read %s: %v\n", path, rerr)
			return nil
		}
		totalFiles++
		mods := kbscan.ScanMeta(data)
		if len(mods) == 0 {
			mods = kbscan.ScanWebpack(data, kbIndexApp)
		}
		if len(mods) == 0 {
			// Plain CommonJS / ES module file — extract from app.asar dump.
			mods = kbscan.ScanSingle(data, kbIndexSrc, path, kbIndexMinBytes)
		}
		rel, _ := filepath.Rel(kbIndexSrc, path)
		now := time.Now().Unix()
		for _, m := range mods {
			totalModules++
			if m.Size < kbIndexMinBytes {
				droppedTiny++
				continue
			}
			if kbIndexMaxBytes > 0 && m.Size > kbIndexMaxBytes {
				droppedHuge++
				continue
			}
			// Excerpt feeds the trigram-searchable columns; full body for
			// module_bodies blob storage.
			body := m.Body(data, kbIndexExcerpt)
			fullBody := m.Body(data, m.Size)
			sum := sha256.Sum256([]byte(body))
			h := hex.EncodeToString(sum[:])

			// Promote a real name if we synthesised app_module_NNN.
			displayName := m.Name
			synthetic := ""
			if strings.Contains(m.Name, "_module_") {
				synthetic = m.Name
				if better := kbscan.Promote(body); better != "" {
					displayName = better
				}
			}
			symbolsJSON := kbscan.Symbols(body)
			// KB-OVERSEG P3: MARK (never skip) vendored-OSS rows so enrichment
			// can exclude them later. Detect over the full body (not the
			// excerpt, so banners/specifiers beyond the excerpt window count)
			// AND the resolved chunk name (catches minified lib chunks that
			// dropped their banner, e.g. react/cytoscape/pdf.worker).
			vendored := kbscan.IsVendored(displayName, []byte(fullBody))

			if _, uerr := upsert.Exec(kbIndexApp, displayName, synthetic, m.Prefix(),
				m.Size, body, h, symbolsJSON, now, now, vendored); uerr != nil {
				fmt.Fprintf(os.Stderr, "warn: upsert %s: %v\n", m.Name, uerr)
				continue
			}
			if _, serr := sighting.Exec(kbIndexApp, h, rel, m.Offset, now); serr != nil {
				fmt.Fprintf(os.Stderr, "warn: sighting %s: %v\n", m.Name, serr)
			}
			if _, berr := bodyStmt.Exec(h, []byte(fullBody), m.Size, now); berr != nil {
				fmt.Fprintf(os.Stderr, "warn: body store %s: %v\n", m.Name, berr)
			}
			kept++
			batchModules++
			// Commit the in-flight tx every batchSize kept modules so a
			// mid-run timeout/crash leaves partial progress on disk. The
			// final partial batch is committed after WalkDir returns.
			if batchSize > 0 && batchModules >= batchSize {
				if ferr := flushBatch(); ferr != nil {
					return ferr
				}
				fmt.Fprintf(os.Stderr, "committed batch: %d modules (total %d kept)\n",
					batchModules, kept)
				batchModules = 0
			}
		}
		if totalFiles%50 == 0 {
			fmt.Fprintf(os.Stderr, "progress: %d files / %d modules (%d kept, %d tiny, %d huge)\n",
				totalFiles, totalModules, kept, droppedTiny, droppedHuge)
		}
		return nil
	})
	if werr != nil {
		return fmt.Errorf("walk: %w", werr)
	}
	// Final partial batch.
	if tx != nil {
		closeStmts()
		if cerr := tx.Commit(); cerr != nil {
			tx = nil
			return fmt.Errorf("commit final: %w", cerr)
		}
		tx = nil
		if batchModules > 0 {
			fmt.Fprintf(os.Stderr, "committed final batch: %d modules (total %d kept)\n",
				batchModules, kept)
		}
	}
	fmt.Printf("indexed app=%s files=%d modules_seen=%d kept=%d tiny=%d huge=%d\n",
		kbIndexApp, totalFiles, totalModules, kept, droppedTiny, droppedHuge)

	// Persist final counts on the source row + back-link every module
	// that landed during this pass so `unravel knowledge sources` can
	// answer "what changed in epoch N".
	if kbIndexReuseEpoch > 0 {
		if err := sources.AddCounts(context.Background(), db, src.ID, int64(kept), int64(kept)); err != nil {
			fmt.Fprintf(os.Stderr, "warn: source add-counts: %v\n", err)
		}
	} else {
		if err := sources.FinishWithCounts(context.Background(), db, src.ID, int64(kept), int64(kept)); err != nil {
			fmt.Fprintf(os.Stderr, "warn: source finish: %v\n", err)
		}
	}
	if err := sources.LinkLastSource(context.Background(), db, kbIndexApp, src.ID); err != nil {
		fmt.Fprintf(os.Stderr, "warn: source link: %v\n", err)
	}
	return nil
}

func runKBDump(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(kbDumpDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	row, err := kbstore.Dump(db, kbDumpID, 5)
	if err != nil {
		return err
	}
	fmt.Printf("id=%d  app=%s  name=%s\n", row.ID, row.App, row.Name)
	if row.Synthetic.Valid && row.Synthetic.String != "" {
		fmt.Printf("synthetic_name=%s\n", row.Synthetic.String)
	}
	fmt.Printf("body_size=%d  sha256=%s\n", row.BodySize, row.Sha256)

	if len(row.Sightings) > 0 {
		fmt.Println("\n=== sightings (most recent first) ===")
		for _, s := range row.Sightings {
			fmt.Printf("  %s @ %d\n", s.SourceFile, s.Offset)
		}
	}
	if row.Symbols.Valid && row.Symbols.String != "" {
		fmt.Printf("\n=== symbols (extracted) ===\n%s\n", row.Symbols.String)
	}
	if row.Summary.Valid && row.Summary.String != "" {
		fmt.Printf("\n=== summary ===\n%s\n", row.Summary.String)
	}
	if row.LongSummary.Valid && row.LongSummary.String != "" {
		fmt.Printf("\n=== long_summary ===\n%s\n", row.LongSummary.String)
	}
	if row.Role.Valid && row.Role.String != "" {
		fmt.Printf("\n=== role ===\n%s\n", row.Role.String)
	}
	if row.Inputs.Valid && row.Inputs.String != "" && row.Inputs.String != "null" {
		fmt.Printf("\n=== inputs ===\n%s\n", row.Inputs.String)
	}
	if row.Outputs.Valid && row.Outputs.String != "" && row.Outputs.String != "null" {
		fmt.Printf("\n=== outputs ===\n%s\n", row.Outputs.String)
	}
	if row.SideEffects.Valid && row.SideEffects.String != "" && row.SideEffects.String != "null" {
		fmt.Printf("\n=== side_effects ===\n%s\n", row.SideEffects.String)
	}
	if row.Deps.Valid && row.Deps.String != "" && row.Deps.String != "null" {
		fmt.Printf("\n=== deps ===\n%s\n", row.Deps.String)
	}
	if row.Tags.Valid && row.Tags.String != "" {
		fmt.Printf("\n=== tags ===\n%s\n", row.Tags.String)
	}
	fmt.Printf("\n=== body excerpt ===\n%s\n", row.BodyExcerpt)
	return nil
}
