/*
Copyright (c) 2026 Security Research
*/
// cmd/knowledge_ingest.go owns the `unravel knowledge ingest` walker that
// turns a source-code repository on disk into rows on the same modules /
// module_sightings / module_bodies tables that the JS sweep already feeds.
//
// Design summary (full SPEC at docs/spec/source-ingest.md):
//
//   - Per-file granularity: 1 modules row per source file. Top-level decl
//     names go into symbols_json so pg_trgm lights up on identifier search.
//   - Per-app partition: modules.app == repo slug (--slug or basename).
//     modules.repo_root carries the absolute path so multiple repos can
//     coexist in one knowledge catalog.
//   - Orphan sweep on re-ingest: any module previously indexed under
//     (app, repo_root) but not seen this run is deleted; FK CASCADE drops
//     the related module_sightings rows.
//   - Reuses the JS indexer's per-batch transaction shape (see runKBIndex).
//
// The package-level helpers it borrows from cmd/knowledge.go:
//
//	kbOpenDB           — opens & migrates the Postgres catalog.
//	kbIndexUpsertSQL   — modules upsert keyed on (app, body_sha256).
//	kbIndexSightingSQL — module_sightings upsert.
//	kbIndexBodySQL     — module_bodies upsert.
//
// The walker does NOT consume kbscan; that stays bound to the JS pipeline.
// All routing happens through pkg/knowledge/kb/langs.

package cmd

import (
	"bufio"
	"database/sql"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	kblangs "github.com/inovacc/unravel-oss/pkg/knowledge/kb/langs"

	"github.com/spf13/cobra"
)

// ── flag-backing variables ───────────────────────────────────────────

var (
	ingestDB           string
	ingestSlug         string
	ingestIncludeTests bool
	ingestLangFilter   []string
	ingestBatch        int
	ingestOrphanSweep  bool
	ingestDryRun       bool

	reposListDB string
)

// Skip directories that virtually never contain first-party source we want
// to index. The walker honors these in addition to .git.
var ingestSkipDirs = map[string]struct{}{
	".git":         {},
	".hg":          {},
	".svn":         {},
	"node_modules": {},
	"vendor":       {},
	"dist":         {},
	"build":        {},
	"target":       {},
	".next":        {},
	".idea":        {},
	".vscode":      {},
}

// ── command wiring ──────────────────────────────────────────────────

// kbIngestCmd is the former `knowledge ingest`, now `kb enrich ingest-repo`.
// It is renamed from the bare `ingest` verb to avoid colliding with
// `kb enrich ingest` (the KS-folder re-ingest in kb_ingest.go), which is a
// distinct operation. NEEDS-REVIEW: the taxonomy has no dedicated verb for
// source-repo ingestion; `ingest-repo` is a placeholder chosen to preserve
// this behavior rather than drop it.
var kbIngestCmd = &cobra.Command{
	Use:   "ingest-repo <path>",
	Short: "Walk a source-code repo and persist modules into the knowledge DB",
	Long: `Ingest a source-code repository into the same modules / module_sightings /
module_bodies tables that 'unravel kb enrich sweep' uses for JS bundles.
Each file produces one modules row tagged with --slug as the app, plus a
sightings entry pointing back to the source path on disk.

The walker:
  • routes per-file extraction through pkg/knowledge/kb/langs (.go uses
    go/parser; everything else falls back to the generic extractor)
  • reuses the JS indexer's batched transaction shape so a mid-run crash
    leaves partial progress on disk
  • performs an "orphan sweep" by default — modules previously indexed
    under (app, repo_root) but not seen this run are deleted, with their
    sightings dropped via FK CASCADE
  • UPSERTs the repo into the new repos table (slug PK)

Examples:
  unravel kb enrich ingest-repo ./my-go-repo
  unravel kb enrich ingest-repo /abs/path --slug myrepo --database kb.db
  unravel kb enrich ingest-repo . --include-tests --lang go --batch 500`,
	Args: cobra.ExactArgs(1),
	RunE: runKBIngest,
}

var kbReposCmd = &cobra.Command{
	Use:   "repos",
	Short: "List repos indexed by 'kb enrich ingest-repo'",
	RunE:  runKBRepos,
}

func init() {
	kbIngestCmd.Flags().StringVar(&ingestDB, "database", "", "knowledge.db path (optional; falls back to config.yaml)")
	kbIngestCmd.Flags().StringVar(&ingestSlug, "slug", "", "repo slug (default: basename of path)")
	kbIngestCmd.Flags().BoolVar(&ingestIncludeTests, "include-tests", false, "index *_test.go files")
	kbIngestCmd.Flags().StringSliceVar(&ingestLangFilter, "lang", nil, "only ingest these langs (default: all registered)")
	kbIngestCmd.Flags().IntVar(&ingestBatch, "batch", 1000, "per-batch commit size")
	kbIngestCmd.Flags().BoolVar(&ingestOrphanSweep, "orphan-sweep", true, "delete modules whose source files are gone")
	kbIngestCmd.Flags().BoolVar(&ingestDryRun, "dry-run", false, "walk + report counts, no DB writes")
	kbEnrichCmd.AddCommand(kbIngestCmd)

	kbReposCmd.Flags().StringVar(&reposListDB, "database", "", "knowledge.db path (optional; falls back to config.yaml)")
	kbCatalogCmd.AddCommand(kbReposCmd)
}

// ── ingest implementation ───────────────────────────────────────────

func runKBIngest(_ *cobra.Command, args []string) error {
	rawPath := args[0]
	root, err := filepath.Abs(rawPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}
	st, err := os.Stat(root)
	if err != nil {
		return fmt.Errorf("stat repo root: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("ingest target must be a directory: %s", root)
	}

	slug := strings.TrimSpace(ingestSlug)
	if slug == "" {
		slug = filepath.Base(root)
	}

	langSet := map[string]struct{}{}
	for _, l := range ingestLangFilter {
		l = strings.TrimSpace(strings.ToLower(l))
		if l != "" {
			langSet[l] = struct{}{}
		}
	}

	db, err := kbOpenDB(ingestDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	vcs, vcsHead := detectVCS(root)

	// Track module ids touched this run for the orphan sweep at the end.
	touchedIDs := map[int64]struct{}{}
	langCounts := map[string]int{}
	var totalFiles, totalModules, dropped int
	var totalBytes int64

	// Per-batch tx state (mirrors runKBIndex).
	var (
		tx       *sql.Tx
		upsert   *sql.Stmt
		sighting *sql.Stmt
		bodyStmt *sql.Stmt
	)
	closeStmts := func() {
		for _, s := range []**sql.Stmt{&upsert, &sighting, &bodyStmt} {
			if *s != nil {
				_ = (*s).Close()
				*s = nil
			}
		}
	}
	beginBatch := func() error {
		t, berr := db.Begin()
		if berr != nil {
			return fmt.Errorf("begin tx: %w", berr)
		}
		tx = t
		if upsert, err = tx.Prepare(kbIndexUpsertSQL); err != nil {
			return fmt.Errorf("prepare upsert: %w", err)
		}
		if sighting, err = tx.Prepare(kbIndexSightingSQL); err != nil {
			return fmt.Errorf("prepare sighting: %w", err)
		}
		if bodyStmt, err = tx.Prepare(kbIndexBodySQL); err != nil {
			return fmt.Errorf("prepare body: %w", err)
		}
		return nil
	}
	if !ingestDryRun {
		if err := beginBatch(); err != nil {
			return err
		}
	}
	defer func() {
		closeStmts()
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

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

	werr := filepath.WalkDir(root, func(path string, d iofs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			if _, skip := ingestSkipDirs[d.Name()]; skip {
				return iofs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		// Skip Go test files unless --include-tests.
		if !ingestIncludeTests && strings.HasSuffix(strings.ToLower(d.Name()), "_test.go") {
			return nil
		}

		extract, lang, ok := kblangs.Lookup(ext)
		if !ok {
			extract = kblangs.DefaultExtractor
			lang = ""
		}
		if len(langSet) > 0 {
			if _, want := langSet[lang]; !want {
				return nil
			}
		}

		body, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "warn: read %s: %v\n", path, rerr)
			return nil
		}
		totalFiles++
		mod, eerr := extract(path, body)
		if eerr != nil {
			// Parse failures fall back to the generic extractor so we still
			// persist a row (with empty symbols).
			fmt.Fprintf(os.Stderr, "warn: extract %s: %v (falling back)\n", path, eerr)
			mod, eerr = kblangs.DefaultExtractor(path, body)
			if eerr != nil {
				dropped++
				return nil
			}
			if lang != "" {
				mod.Lang = lang
			}
		}
		if mod.Lang == "" {
			mod.Lang = lang
		}
		// Prefix from first dir segment relative to root.
		if mod.Prefix == "" {
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			if i := strings.IndexByte(rel, '/'); i > 0 {
				mod.Prefix = rel[:i]
			}
		}

		totalModules++
		totalBytes += int64(mod.Size)
		if mod.Lang != "" {
			langCounts[mod.Lang]++
		} else {
			langCounts["(other)"]++
		}

		if ingestDryRun {
			return nil
		}

		now := time.Now().Unix()
		if _, uerr := upsert.Exec(slug, mod.Name, "", mod.Prefix,
			mod.Size, mod.BodyExcerpt, mod.BodySHA256, mod.SymbolsJSON, now, now, false); uerr != nil {
			fmt.Fprintf(os.Stderr, "warn: upsert %s: %v\n", mod.Name, uerr)
			return nil
		}
		// Backfill the new lang/repo_root columns. The shared upsert SQL
		// predates this command so we patch the row we just touched.
		if _, perr := tx.Exec(
			`UPDATE modules SET lang = $1, repo_root = $2 WHERE app = $3 AND body_sha256 = $4`,
			mod.Lang, root, slug, mod.BodySHA256,
		); perr != nil {
			fmt.Fprintf(os.Stderr, "warn: tag lang/repo_root %s: %v\n", mod.Name, perr)
		}
		// Capture the touched id for the orphan sweep.
		var rowID int64
		_ = tx.QueryRow(`SELECT id FROM modules WHERE app = $1 AND body_sha256 = $2`,
			slug, mod.BodySHA256).Scan(&rowID)
		if rowID != 0 {
			touchedIDs[rowID] = struct{}{}
		}

		rel, _ := filepath.Rel(root, path)
		if _, serr := sighting.Exec(slug, mod.BodySHA256, rel, 0, now); serr != nil {
			fmt.Fprintf(os.Stderr, "warn: sighting %s: %v\n", mod.Name, serr)
		}
		if _, berr := bodyStmt.Exec(mod.BodySHA256, mod.FullBody, mod.Size, now); berr != nil {
			fmt.Fprintf(os.Stderr, "warn: body store %s: %v\n", mod.Name, berr)
		}
		batchModules++
		if ingestBatch > 0 && batchModules >= ingestBatch {
			if ferr := flushBatch(); ferr != nil {
				return ferr
			}
			fmt.Fprintf(os.Stderr, "committed batch: %d modules (total %d)\n", batchModules, totalModules)
			batchModules = 0
		}
		return nil
	})
	if werr != nil {
		return fmt.Errorf("walk: %w", werr)
	}
	// Final batch.
	if !ingestDryRun && tx != nil {
		closeStmts()
		if cerr := tx.Commit(); cerr != nil {
			tx = nil
			return fmt.Errorf("commit final: %w", cerr)
		}
		tx = nil
	}

	// Orphan sweep + repos UPSERT happen outside the per-batch tx loop.
	if !ingestDryRun {
		if ingestOrphanSweep {
			n, oerr := orphanSweep(db, slug, root, touchedIDs)
			if oerr != nil {
				fmt.Fprintf(os.Stderr, "warn: orphan sweep: %v\n", oerr)
			} else if n > 0 {
				fmt.Fprintf(os.Stderr, "orphan-sweep: removed %d stale modules\n", n)
			}
		}
		if uerr := upsertRepo(db, slug, root, vcs, vcsHead, len(touchedIDs), totalBytes); uerr != nil {
			fmt.Fprintf(os.Stderr, "warn: repos upsert: %v\n", uerr)
		}
	}

	fmt.Printf("ingested repo=%s files=%d modules=%d langs=%s dropped=%d dry_run=%v\n",
		slug, totalFiles, totalModules, formatLangCounts(langCounts), dropped, ingestDryRun)
	return nil
}

// detectVCS sniffs the repo root for a .git/HEAD and reads the ref / sha.
// Other VCS systems are out of scope for v1.
func detectVCS(root string) (vcs, head string) {
	headPath := filepath.Join(root, ".git", "HEAD")
	f, err := os.Open(headPath)
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		head = strings.TrimSpace(sc.Text())
	}
	return "git", head
}

// orphanSweep deletes modules under (app, repo_root) whose ids weren't in
// touchedIDs. FK CASCADE handles module_sightings drops.
func orphanSweep(db *sql.DB, app, root string, touched map[int64]struct{}) (int64, error) {
	if len(touched) == 0 {
		// Don't sweep on a zero-touch run — could be a dry-run-like
		// failure mode, and we don't want to wipe the partition.
		return 0, nil
	}
	// Build "id NOT IN (...)" via a temp table to avoid the Postgres
	// bound-parameter limit on a large touched set.
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`CREATE TEMP TABLE IF NOT EXISTS ingest_keep(id INTEGER PRIMARY KEY)`); err != nil {
		return 0, fmt.Errorf("temp keep: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM ingest_keep`); err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT INTO ingest_keep(id) VALUES ($1) ON CONFLICT (id) DO NOTHING`)
	if err != nil {
		return 0, err
	}
	for id := range touched {
		if _, err := stmt.Exec(id); err != nil {
			_ = stmt.Close()
			return 0, err
		}
	}
	_ = stmt.Close()
	res, err := tx.Exec(`DELETE FROM modules
		WHERE app = $1 AND repo_root = $2
		  AND id NOT IN (SELECT id FROM ingest_keep)`, app, root)
	if err != nil {
		return 0, fmt.Errorf("orphan delete: %w", err)
	}
	n, _ := res.RowsAffected()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}

// upsertRepo INSERTs OR REPLACEs the repos row for this slug.
func upsertRepo(db *sql.DB, slug, root, vcs, head string, modCount int, bytes int64) error {
	now := time.Now().UnixMilli()
	_, err := db.Exec(`INSERT INTO repos (slug, root, vcs, vcs_head, indexed_at, module_count, total_bytes)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(slug) DO UPDATE SET
			root         = excluded.root,
			vcs          = excluded.vcs,
			vcs_head     = excluded.vcs_head,
			indexed_at   = excluded.indexed_at,
			module_count = excluded.module_count,
			total_bytes  = excluded.total_bytes`,
		slug, root, vcs, head, now, modCount, bytes)
	return err
}

func formatLangCounts(m map[string]int) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s:%d", k, m[k])
	}
	b.WriteByte('}')
	return b.String()
}

// ── repos subcommand ────────────────────────────────────────────────

func runKBRepos(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(reposListDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(`SELECT slug, root, COALESCE(vcs,''), COALESCE(vcs_head,''),
		COALESCE(indexed_at,0), COALESCE(module_count,0), COALESCE(total_bytes,0)
		FROM repos ORDER BY slug`)
	if err != nil {
		return fmt.Errorf("query repos: %w", err)
	}
	defer func() { _ = rows.Close() }()

	fmt.Printf("%-24s %-8s %-12s %-12s %-12s %s\n", "slug", "vcs", "head", "modules", "bytes", "root")
	n := 0
	for rows.Next() {
		var (
			slug, root, vcs, head string
			indexedAt             int64
			modCount              int
			totalBytes            int64
		)
		if err := rows.Scan(&slug, &root, &vcs, &head, &indexedAt, &modCount, &totalBytes); err != nil {
			return err
		}
		shortHead := head
		if len(shortHead) > 12 {
			shortHead = shortHead[:12]
		}
		fmt.Printf("%-24s %-8s %-12s %-12d %-12d %s\n",
			slug, vcs, shortHead, modCount, totalBytes, root)
		n++
	}
	if n == 0 {
		fmt.Println("(no repos indexed)")
	}
	return rows.Err()
}
