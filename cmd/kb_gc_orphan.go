/*
Copyright (c) 2026 Security Research

Phase 34 Plan 03 — `unravel kb gc` orphan-cleanup branches.

Three mutually-exclusive modes (D-34-ORPHAN-MUTEX), each inheriting the
P32 `--dry-run` / `--yes` / exit-code semantics:

  --orphan-folders : walks <kb-store>/apps/<kb_id>/versions/<ks_id_fs>/
                     and removes leaves whose (kb_id, captured_at) pair
                     has no matching knowledge_sources row. Decode is
                     pair-based per D-34-ORPHAN-FOLDERS-DECODE because
                     ks_id_fs version sanitisation is lossy.

  --orphan-bodies  : DELETE FROM module_bodies WHERE body_sha256 has no
                     matching module_app_refs row.

  --orphan-files   : DELETE FROM files WHERE file_sha256 has no matching
                     file_app_refs row.

T-34-09/10/11 (threat register): mass DELETE / RemoveAll guarded by
LEFT JOIN, root prefix, kb_id-hex+captured_at-int validation, prompt
gate. T-34-12 mutex is enforced by runKbGC dispatcher (caller).
*/

package cmd

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/fsutil"
)

// kbIDRE matches a 16-char lowercase hex kb_id. The hashutil package
// produces these via HashHex16String. Anything else is treated as a
// malformed directory name and skipped (T-34-11).
var kbIDRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

type orphanRowResult struct {
	Deleted       int64  `json:"deleted"`
	Mode          string `json:"mode"`
	SchemaVersion int    `json:"schema_version"`
}

type orphanFolderResult struct {
	Removed       int      `json:"removed"`
	Failed        int      `json:"failed"`
	Failures      []string `json:"failures,omitempty"`
	Mode          string   `json:"mode"`
	SchemaVersion int      `json:"schema_version"`
}

// runOrphanMode dispatches the single active orphan flag. Exactly one
// of gcOrphanFolders/gcOrphanBodies/gcOrphanFiles must be true; the
// caller (runKbGC) enforces this via the mutex check.
func runOrphanMode(cmd *cobra.Command, db *sql.DB) error {
	ctx := cmd.Context()
	switch {
	case gcOrphanBodies:
		return runOrphanBodies(cmd, ctx, db)
	case gcOrphanFiles:
		return runOrphanFiles(cmd, ctx, db)
	case gcOrphanFolders:
		return runOrphanFolders(cmd, ctx, db)
	default:
		return errors.New("orphan dispatcher: no flag set (caller bug)")
	}
}

// runOrphanRowMode is the shared body for --orphan-bodies and
// --orphan-files. The two SQL families differ only in column / table
// names, so we parameterise via the q* statements.
func runOrphanRowMode(
	cmd *cobra.Command, ctx context.Context, db *sql.DB,
	mode, header, qCount, qSample, qDelete string,
) error {
	out := cmd.OutOrStdout()

	var n int64
	if err := db.QueryRowContext(ctx, qCount).Scan(&n); err != nil {
		return fmt.Errorf("%s count: %w", mode, err)
	}

	if gcDryRun {
		rows, err := db.QueryContext(ctx, qSample)
		if err != nil {
			return fmt.Errorf("%s sample: %w", mode, err)
		}
		defer rows.Close()
		var sample [][]string
		for rows.Next() {
			var sha string
			if err := rows.Scan(&sha); err != nil {
				return fmt.Errorf("%s scan: %w", mode, err)
			}
			sample = append(sample, []string{sha})
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("%s sample iter: %w", mode, err)
		}
		fmt.Fprintf(out, "DRY RUN: would delete %d orphan rows (%s)\n\n", n, mode)
		if len(sample) > 0 {
			if err := kb_output.WriteTable(out, []string{header}, sample); err != nil {
				return err
			}
		}
		return nil
	}

	if n == 0 {
		if gcJSON {
			return kb_output.WriteJSON(out, 1, orphanRowResult{Mode: mode, SchemaVersion: 1})
		}
		fmt.Fprintf(out, "no orphan rows in %s\n", mode)
		return nil
	}

	if !gcYes {
		fmt.Printf("Delete %d orphan rows (%s)? [y/N]: ", n, mode)
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(os.Stderr, "cancelled by user")
			os.Exit(2)
		}
	}

	res, err := db.ExecContext(ctx, qDelete)
	if err != nil {
		return fmt.Errorf("%s delete: %w", mode, err)
	}
	deleted, _ := res.RowsAffected()

	if gcJSON {
		return kb_output.WriteJSON(out, 1, orphanRowResult{
			Deleted:       deleted,
			Mode:          mode,
			SchemaVersion: 1,
		})
	}
	fmt.Fprintf(out, "Deleted %d orphan rows from %s.\n", deleted, mode)
	return nil
}

func runOrphanBodies(cmd *cobra.Command, ctx context.Context, db *sql.DB) error {
	const qCount = `SELECT COUNT(*) FROM module_bodies mb
		LEFT JOIN module_app_refs r ON r.body_sha256 = mb.body_sha256
		WHERE r.body_sha256 IS NULL`
	const qSample = `SELECT mb.body_sha256 FROM module_bodies mb
		LEFT JOIN module_app_refs r ON r.body_sha256 = mb.body_sha256
		WHERE r.body_sha256 IS NULL LIMIT 10`
	const qDelete = `DELETE FROM module_bodies
		WHERE body_sha256 IN (
			SELECT mb.body_sha256 FROM module_bodies mb
			LEFT JOIN module_app_refs r ON r.body_sha256 = mb.body_sha256
			WHERE r.body_sha256 IS NULL
		)`
	return runOrphanRowMode(cmd, ctx, db, "orphan-bodies", "BODY_SHA256", qCount, qSample, qDelete)
}

func runOrphanFiles(cmd *cobra.Command, ctx context.Context, db *sql.DB) error {
	const qCount = `SELECT COUNT(*) FROM files f
		LEFT JOIN file_app_refs r ON r.file_sha256 = f.file_sha256
		WHERE r.file_sha256 IS NULL`
	const qSample = `SELECT f.file_sha256 FROM files f
		LEFT JOIN file_app_refs r ON r.file_sha256 = f.file_sha256
		WHERE r.file_sha256 IS NULL LIMIT 10`
	const qDelete = `DELETE FROM files
		WHERE file_sha256 IN (
			SELECT f.file_sha256 FROM files f
			LEFT JOIN file_app_refs r ON r.file_sha256 = f.file_sha256
			WHERE r.file_sha256 IS NULL
		)`
	return runOrphanRowMode(cmd, ctx, db, "orphan-files", "FILE_SHA256", qCount, qSample, qDelete)
}

type orphanFolderCandidate struct {
	KbID       string
	CapturedAt int64
	Path       string
}

// runOrphanFolders walks <KBStoreRoot>/apps/<kb_id>/versions/<leaf>/.
// For each leaf with a parseable (kb_id, captured_at) pair, queries
// knowledge_sources; missing rows mean the leaf is an orphan candidate.
//
// Per D-34-ORPHAN-FOLDERS-DECODE we match by pair, not exact ks_id,
// because version sanitisation in fsutil.EncodeKsID is lossy.
//
// Per T-34-10 path safety, all RemoveAll targets stay rooted under
// fsutil.KBStoreRoot(); user input never feeds path construction.
func runOrphanFolders(cmd *cobra.Command, ctx context.Context, db *sql.DB) error {
	out := cmd.OutOrStdout()

	storeRoot, err := fsutil.KBStoreRoot()
	if err != nil {
		return fmt.Errorf("kb store root: %w", err)
	}
	appsRoot := filepath.Join(storeRoot, "apps")

	candidates, err := scanOrphanFolders(ctx, db, appsRoot)
	if err != nil {
		return err
	}

	if gcDryRun {
		fmt.Fprintf(out, "DRY RUN: would remove %d orphan folders\n\n", len(candidates))
		if len(candidates) > 0 {
			limit := len(candidates)
			if limit > 10 {
				limit = 10
			}
			rows := make([][]string, 0, limit)
			for i := 0; i < limit; i++ {
				c := candidates[i]
				rows = append(rows, []string{c.KbID, strconv.FormatInt(c.CapturedAt, 10), c.Path})
			}
			if err := kb_output.WriteTable(out, []string{"KB_ID", "CAPTURED_AT", "PATH"}, rows); err != nil {
				return err
			}
		}
		return nil
	}

	if len(candidates) == 0 {
		if gcJSON {
			return kb_output.WriteJSON(out, 1, orphanFolderResult{Mode: "orphan-folders", SchemaVersion: 1})
		}
		fmt.Fprintln(out, "no orphan folders")
		return nil
	}

	if !gcYes {
		fmt.Printf("Remove %d orphan folders? [y/N]: ", len(candidates))
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(os.Stderr, "cancelled by user")
			os.Exit(2)
		}
	}

	var failures []string
	removed := 0
	for _, c := range candidates {
		if err := os.RemoveAll(fsutil.WrapLongPath(c.Path)); err != nil {
			fmt.Fprintf(os.Stderr, "WARN: failed to remove %s: %v\n", c.Path, err)
			failures = append(failures, c.Path)
			continue
		}
		removed++
	}

	if gcJSON {
		return kb_output.WriteJSON(out, 1, orphanFolderResult{
			Removed:       removed,
			Failed:        len(failures),
			Failures:      failures,
			Mode:          "orphan-folders",
			SchemaVersion: 1,
		})
	}
	fmt.Fprintf(out, "Removed %d orphan folders.\n", removed)
	if len(failures) > 0 {
		fmt.Fprintf(out, "FS removal had %d failures (logged to stderr).\n", len(failures))
	}
	return nil
}

// scanOrphanFolders walks the apps tree and returns leaves whose
// (kb_id, captured_at) pair has no row in knowledge_sources. Malformed
// directory names (kb_id not 16 hex, captured_at not int64, fewer than
// 3 underscore segments) are skipped silently per T-34-11.
func scanOrphanFolders(ctx context.Context, db *sql.DB, appsRoot string) ([]orphanFolderCandidate, error) {
	if _, err := os.Stat(appsRoot); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat apps root: %w", err)
	}

	var candidates []orphanFolderCandidate
	err := filepath.WalkDir(fsutil.WrapLongPath(appsRoot), func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "WARN: walk %s: %v\n", path, walkErr)
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		// Compute relative depth: appsRoot=0, kb_id=1, "versions"=2, leaf=3.
		rel, err := filepath.Rel(appsRoot, path)
		if err != nil {
			return nil
		}
		if rel == "." {
			return nil
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		switch len(parts) {
		case 1:
			// kb_id directory — descend.
			return nil
		case 2:
			// must be "versions"; if not, prune.
			if parts[1] != "versions" {
				return fs.SkipDir
			}
			return nil
		case 3:
			// Leaf candidate. Don't descend further.
			leaf := parts[2]
			if cand, ok := decodeOrphanLeaf(leaf, path); ok {
				orphan, err := isOrphanPair(ctx, db, cand.KbID, cand.CapturedAt)
				if err != nil {
					return err
				}
				if orphan {
					candidates = append(candidates, cand)
				}
			}
			return fs.SkipDir
		default:
			return fs.SkipDir
		}
	})
	if err != nil {
		return nil, fmt.Errorf("walk apps root: %w", err)
	}
	return candidates, nil
}

// decodeOrphanLeaf parses a `<kb_id>_<version_safe>_<captured_at>`
// directory name into the (kb_id, captured_at) pair. Returns ok=false
// if the name is malformed.
func decodeOrphanLeaf(name, path string) (orphanFolderCandidate, bool) {
	parts := strings.Split(name, "_")
	if len(parts) < 3 {
		return orphanFolderCandidate{}, false
	}
	kbID := parts[0]
	if !kbIDRE.MatchString(kbID) {
		return orphanFolderCandidate{}, false
	}
	capturedAt, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return orphanFolderCandidate{}, false
	}
	return orphanFolderCandidate{KbID: kbID, CapturedAt: capturedAt, Path: path}, true
}

// isOrphanPair reports whether (kb_id, captured_at) is missing from
// knowledge_sources. Uses errors.Is(sql.ErrNoRows) per project Go
// standards (never `==` on errors).
func isOrphanPair(ctx context.Context, db *sql.DB, kbID string, capturedAt int64) (bool, error) {
	var dummy int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM knowledge_sources WHERE kb_id = $1 AND captured_at = $2 LIMIT 1`,
		kbID, capturedAt,
	).Scan(&dummy)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	return false, fmt.Errorf("query knowledge_sources for (%s, %d): %w", kbID, capturedAt, err)
}
