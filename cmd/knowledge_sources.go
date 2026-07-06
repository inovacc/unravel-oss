/*
Copyright (c) 2026 Security Research
*/
// cmd/knowledge_sources.go — `unravel knowledge sources` reads the
// knowledge_source_evolution view (migration 000002) and prints a
// per-app capture timeline with module-count delta between consecutive
// epochs. Optional --app filter narrows to a single app.

package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	sourcesApp  string
	sourcesJSON bool
	sourcesDB   string
)

var kbSourcesCmd = &cobra.Command{
	Use:   "sources",
	Short: "Print the knowledge_sources evolution timeline",
	Long: `Reads the knowledge_source_evolution view (migration 000002) and
prints one row per (app, epoch) capture event. Each row shows the
modules_indexed and bodies_indexed counts plus the delta versus the
prior epoch — i.e. how the app evolved between captures.`,
	RunE: runKBSources,
}

func init() {
	kbSourcesCmd.Flags().StringVar(&sourcesApp, "app", "", "filter by app (whatsapp, teams, ...)")
	kbSourcesCmd.Flags().BoolVar(&sourcesJSON, "json", false, "emit JSON instead of a table")
	kbSourcesCmd.Flags().StringVar(&sourcesDB, "database", "", "DSN override (defaults to config.yaml)")
	kbCatalogCmd.AddCommand(kbSourcesCmd)
}

type sourceRow struct {
	App          string `json:"app"`
	Epoch        int    `json:"epoch"`
	AppVersion   string `json:"app_version,omitempty"`
	CapturedAt   int64  `json:"captured_at"`
	SourceKind   string `json:"source_kind"`
	ModulesNow   int64  `json:"modules"`
	ModulesDelta *int64 `json:"modules_delta,omitempty"`
	BodiesNow    int64  `json:"bodies"`
	BodiesDelta  *int64 `json:"bodies_delta,omitempty"`
	SourcePath   string `json:"source_path"`
	Notes        string `json:"notes,omitempty"`
}

func runKBSources(_ *cobra.Command, _ []string) error {
	db, err := kbOpenDB(sourcesDB)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	rows, err := queryEvolution(context.Background(), db, sourcesApp)
	if err != nil {
		return err
	}

	if sourcesJSON {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}

	if len(rows) == 0 {
		fmt.Println("(no captures yet — run `unravel knowledge sweep` to populate)")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	defer func() { _ = tw.Flush() }()
	fmt.Fprintln(tw, "APP\tEPOCH\tWHEN\tKIND\tVERSION\tMODULES\tΔMOD\tBODIES\tΔBOD\tSOURCE")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%s\n",
			r.App, r.Epoch,
			time.UnixMilli(r.CapturedAt).UTC().Format("2006-01-02 15:04:05Z"),
			r.SourceKind, dash(r.AppVersion),
			r.ModulesNow, fmtDelta(r.ModulesDelta),
			r.BodiesNow, fmtDelta(r.BodiesDelta),
			r.SourcePath,
		)
	}
	return nil
}

func queryEvolution(ctx context.Context, db *sql.DB, app string) ([]sourceRow, error) {
	q := `SELECT app, epoch, COALESCE(app_version,'') AS version,
	       captured_at, source_kind,
	       COALESCE(modules_indexed,0) AS modules,
	       modules_delta,
	       COALESCE(bodies_indexed,0)  AS bodies,
	       bodies_delta,
	       source_path, COALESCE(notes,'') AS notes
	  FROM knowledge_source_evolution`
	args := []any{}
	if app != "" {
		q += " WHERE app = $1"
		args = append(args, app)
	}
	q += " ORDER BY app, epoch"

	rs, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query evolution: %w", err)
	}
	defer func() { _ = rs.Close() }()

	var out []sourceRow
	for rs.Next() {
		var r sourceRow
		var modDelta, bodDelta sql.NullInt64
		if err := rs.Scan(&r.App, &r.Epoch, &r.AppVersion, &r.CapturedAt,
			&r.SourceKind, &r.ModulesNow, &modDelta, &r.BodiesNow, &bodDelta,
			&r.SourcePath, &r.Notes,
		); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		if modDelta.Valid {
			v := modDelta.Int64
			r.ModulesDelta = &v
		}
		if bodDelta.Valid {
			v := bodDelta.Int64
			r.BodiesDelta = &v
		}
		out = append(out, r)
	}
	return out, rs.Err()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func fmtDelta(d *int64) string {
	if d == nil {
		return "-"
	}
	if *d > 0 {
		return fmt.Sprintf("+%d", *d)
	}
	return fmt.Sprintf("%d", *d)
}
