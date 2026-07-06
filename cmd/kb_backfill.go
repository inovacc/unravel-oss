/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/backfill"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
)

var (
	kbBackfillDSN    string
	kbBackfillDryRun bool
	kbBackfillYes    bool
	kbBackfillJSON   bool
)

// kbBackfillCmd is the Phase-34 BACK-01/BACK-02 entry point. Runs the
// idempotent legacy backfill: synthesizes kb_apps rows for distinct
// legacy app names and writes derived kb_id values onto every
// knowledge_sources row whose kb_id is still NULL.
//
// Per D-34-CLI-NEW-COMMANDS, the command lives under `unravel kb` with
// the same DSN + JSON flag conventions as the rest of the kb_* family
// (D-34-CLI-PARITY).
var kbBackfillCmd = &cobra.Command{
	Use:   "backfill",
	Short: "Backfill kb_id for legacy knowledge_sources rows",
	Long: `Derive kb_id for every knowledge_sources row captured before the P29
identity migration, and synthesize the matching kb_apps rows.

The legacy kb_id is SHA-256(lower(app)||'|unknown')[:16]. Re-runs are
no-ops: the UPDATE filters on WHERE kb_id IS NULL and the kb_apps
INSERT uses ON CONFLICT (kb_id) DO NOTHING.

Connection:
  DSN comes from %LOCALAPPDATA%/Unravel/config.yaml (run "unravel db setup").

Examples:
  unravel kb backfill --dry-run
  unravel kb backfill --yes --json`,
	RunE: runKbBackfill,
}

func init() {
	kb_output.BindDSNFlag(kbBackfillCmd, &kbBackfillDSN)
	kb_output.BindJSONFlag(kbBackfillCmd, &kbBackfillJSON)
	kbBackfillCmd.Flags().BoolVar(&kbBackfillDryRun, "dry-run", false, "count would-affect rows without mutating the database")
	kbBackfillCmd.Flags().BoolVar(&kbBackfillYes, "yes", false, "skip safety prompt")

	kbEnrichCmd.AddCommand(kbBackfillCmd)
}

func runKbBackfill(cmd *cobra.Command, _ []string) error {
	dsn, err := kb_output.ResolveDSN(kbBackfillDSN)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Safety prompt: only when running for real, interactively, and not in
	// JSON mode (machine-readable output should never block on stdin).
	if !kbBackfillYes && !kbBackfillDryRun && !kbBackfillJSON {
		fmt.Fprint(cmd.OutOrStdout(), "backfill will write to kb_apps and knowledge_sources. proceed? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		response, _ := reader.ReadString('\n')
		response = strings.ToLower(strings.TrimSpace(response))
		if response != "y" && response != "yes" {
			fmt.Fprintln(os.Stderr, "cancelled by user")
			os.Exit(2)
		}
	}

	rep, err := backfill.Run(ctx, db, backfill.Options{DryRun: kbBackfillDryRun})
	if err != nil {
		return fmt.Errorf("backfill: %w", err)
	}

	if kbBackfillJSON {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, rep)
	}

	mode := "live"
	if kbBackfillDryRun {
		mode = "dry-run"
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"backfilled %d rows; created %d kb_apps entries (mode=%s, schema_version=%d)\n",
		rep.RowsBackfilled, rep.AppsCreated, mode, rep.SchemaVersion,
	)
	return nil
}
