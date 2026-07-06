/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/synthname"
)

var (
	synthDB     string
	synthApp    string
	synthLimit  int
	synthForce  bool
	synthDryRun bool
	synthVerify bool
)

// placeholderNameSQL matches the Teams numeric-placeholder names this command
// backfills. Kept in sync with semanticNameSQL's teams_module exclusion.
const placeholderNameSQL = `m.name ~ '^teams_module_[0-9]+$'`

var kbSynthNamesCmd = &cobra.Command{
	Use:   "synth-names",
	Short: "Derive deterministic synthetic_name for teams_module_<N> placeholder modules (pure-Go, no AI)",
	RunE:  runKBSynthNames,
}

func runKBSynthNames(cmd *cobra.Command, _ []string) error {
	db, err := kbOpenDB(synthDB)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	app := synthApp
	if app == "" {
		app = "teams"
	}

	if synthVerify {
		return runSynthVerify(db, app, cmd.OutOrStdout())
	}

	args := []any{app}
	q := `SELECT m.id, m.body_excerpt, mb.body
	      FROM modules m
	      LEFT JOIN module_bodies mb ON mb.body_sha256 = m.body_sha256
	      WHERE m.app = $1 AND ` + placeholderNameSQL
	if !synthForce {
		q += ` AND (m.synthetic_name IS NULL OR m.synthetic_name = '')`
	}
	q += ` ORDER BY m.id ASC`
	if synthLimit > 0 {
		args = append(args, synthLimit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		return fmt.Errorf("synth-names candidate query: %w", err)
	}
	type cand struct {
		id          int64
		bodyExcerpt sql.NullString
		body        []byte
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.bodyExcerpt, &c.body); err != nil {
			_ = rows.Close()
			return fmt.Errorf("synth-names scan: %w", err)
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("synth-names rows: %w", err)
	}
	_ = rows.Close()

	total := len(cands)
	done, named, noSignal, failed := 0, 0, 0, 0
	for _, c := range cands {
		done++
		text := strings.TrimSpace(c.bodyExcerpt.String)
		if text == "" {
			text = string(c.body)
		}
		name, ok := synthname.Derive(text)
		if !ok {
			noSignal++
		} else if synthDryRun {
			fmt.Fprintf(cmd.OutOrStdout(), "[%d] %d -> %q (dry-run)\n", done, c.id, name)
			named++
		} else if _, err := db.Exec(
			`UPDATE modules SET synthetic_name = $1 WHERE id = $2`, name, c.id); err != nil {
			slog.Error("synth-names update failed", "id", c.id, "err", err)
			failed++
		} else {
			named++
		}
		if enrichProgressEvery(done, 50, total) {
			slog.Info("synth-names progress", "app", app, "done", done, "total", total,
				"named", named, "no_signal", noSignal, "failed", failed)
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"done — total=%d named=%d no_signal=%d failed=%d\n", total, named, noSignal, failed)
	if total > 0 && named == 0 && !synthDryRun {
		return errors.New("synth-names: 0 of candidates received a synthetic_name")
	}
	return nil
}

// runSynthVerify is read-only: placeholder rows total vs synthetic_name-filled.
func runSynthVerify(db *sql.DB, app string, w io.Writer) error {
	var placeholders, filled int64
	base := `FROM modules m WHERE m.app = $1 AND ` + placeholderNameSQL
	if err := db.QueryRow(`SELECT count(*) `+base, app).Scan(&placeholders); err != nil {
		return fmt.Errorf("synth verify placeholder count: %w", err)
	}
	if err := db.QueryRow(`SELECT count(*) `+base+
		` AND m.synthetic_name IS NOT NULL AND m.synthetic_name <> ''`, app).Scan(&filled); err != nil {
		return fmt.Errorf("synth verify filled count: %w", err)
	}
	fmt.Fprintf(w, "  %-10s placeholders=%-8d synthetic_named=%d\n", app, placeholders, filled)
	if placeholders > 0 && filled == 0 {
		return fmt.Errorf("synth verify: %s has %d placeholder modules but 0 synthetic_named", app, placeholders)
	}
	return nil
}
