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

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/topic"
)

var (
	topicsDB     string
	topicsApp    string
	topicsLimit  int
	topicsForce  bool
	topicsDryRun bool
	topicsVerify bool
)

var kbTopicsCmd = &cobra.Command{
	Use:   "topics",
	Short: "Derive deterministic modules.topic over the enriched subset (pure-Go, no AI)",
	RunE:  runKBTopics,
}

func runKBTopics(cmd *cobra.Command, _ []string) error {
	db, err := kbOpenDB(topicsDB)
	if err != nil {
		return fmt.Errorf("open kb db: %w", err)
	}
	defer func() { _ = db.Close() }()

	app := topicsApp
	if app == "" {
		app = "whatsapp"
	}

	if topicsVerify {
		return runTopicsVerify(db, app, cmd.OutOrStdout())
	}

	args := []any{app}
	q := `SELECT m.id, COALESCE(m.tags,''), COALESCE(m.summary,''),
	             COALESCE(me.role,''), COALESCE(me.deps_json,'')
	      FROM modules m
	      LEFT JOIN module_enrichment me ON me.module_id = m.id
	      WHERE m.app = $1 AND m.summary IS NOT NULL AND m.summary <> ''`
	if !topicsForce {
		q += ` AND (m.topic IS NULL OR m.topic = '')`
	}
	q += ` ORDER BY m.id ASC`
	if topicsLimit > 0 {
		args = append(args, topicsLimit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}

	rows, err := db.Query(q, args...)
	if err != nil {
		return fmt.Errorf("topics candidate query: %w", err)
	}
	type cand struct {
		id      int64
		tags    string
		summary string
		role    string
		deps    string
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.tags, &c.summary, &c.role, &c.deps); err != nil {
			_ = rows.Close()
			return fmt.Errorf("topics scan: %w", err)
		}
		cands = append(cands, c)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("topics rows: %w", err)
	}
	_ = rows.Close()

	total := len(cands)
	done, topiced, failed := 0, 0, 0
	for _, c := range cands {
		done++
		tp := topic.Derive(c.role, c.tags, c.summary, c.deps)
		if topicsDryRun {
			fmt.Fprintf(cmd.OutOrStdout(), "[%d] %d -> %q (dry-run)\n", done, c.id, tp)
			topiced++
		} else if _, err := db.Exec(
			`UPDATE modules SET topic = $1 WHERE id = $2`, tp, c.id); err != nil {
			slog.Error("topics update failed", "id", c.id, "err", err)
			failed++
		} else {
			topiced++
		}
		if enrichProgressEvery(done, 50, total) {
			slog.Info("topics progress", "app", app, "done", done, "total", total,
				"failed", failed)
		}
	}
	fmt.Fprintf(cmd.OutOrStdout(),
		"done — total=%d topiced=%d failed=%d\n", total, topiced, failed)
	if total > 0 && topiced == 0 && !topicsDryRun {
		return errors.New("topics: 0 of candidates received a topic")
	}
	return nil
}

func runTopicsVerify(db *sql.DB, app string, w io.Writer) error {
	var enriched int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM modules m
		 WHERE m.app = $1 AND m.summary IS NOT NULL AND m.summary <> ''`,
		app).Scan(&enriched); err != nil {
		return fmt.Errorf("topics verify enriched count: %w", err)
	}
	var topicedCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM modules m
		 WHERE m.app = $1 AND m.summary IS NOT NULL AND m.summary <> ''
		   AND m.topic IS NOT NULL AND m.topic <> ''`,
		app).Scan(&topicedCount); err != nil {
		return fmt.Errorf("topics verify topiced count: %w", err)
	}
	fmt.Fprintf(w, "  %-10s enriched=%-8d topiced=%d\n", app, enriched, topicedCount)
	if enriched > 0 && topicedCount == 0 {
		return fmt.Errorf("topics verify: %s has %d enriched modules but 0 topiced", app, enriched)
	}
	return nil
}
