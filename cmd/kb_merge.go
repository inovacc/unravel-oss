/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

var (
	kbMergeReason string
	kbMergeBy     string
	kbMergeDryRun bool
)

// kbMergeCmd executes the Day-1 identity-merge primitive: collapses two
// kb_id rows by recording loser→winner in kb_aliases, rewriting any
// knowledge_sources rows still pointing at the loser, and deleting the
// loser kb_apps row. Single tx, no undo (D-29-MERGE-NO-UNDO).
var kbMergeCmd = &cobra.Command{
	Use:   "merge <kb_id_loser> <kb_id_winner>",
	Short: "Merge two kb_ids — make loser an alias of winner. Final, no undo.",
	Long: `Merge two kb_ids into one canonical identity.

The loser kb_id becomes an alias of the winner. All knowledge_sources rows
referencing the loser are rewritten in-place to the winner, and the loser
kb_apps row is deleted. The operation runs in a single transaction.

Constraints:
  * Winner must be canonical — it cannot itself be a stale alias of some
    third kb_id. Merge into the canonical kb_id directly to avoid chains.
  * Both kb_ids must exist in kb_apps.
  * Operation is final. There is no undo (D-29-MERGE-NO-UNDO).

Audit trail:
  * --reason captures free-text rationale; stored in kb_aliases.reason.
  * --by records the analyst identifier; defaults to $USER / $USERNAME, or
    "unknown" when neither is set.

Connection:
  DSN comes from %LOCALAPPDATA%/Unravel/config.yaml (run "unravel db setup").

Example:
  unravel kb merge aaaa1111aaaa1111 bbbb2222bbbb2222 \
    --reason "cert rotation" --by analyst@example.com`,
	Args: cobra.ExactArgs(2),
	RunE: runKbMerge,
}

func init() {
	kbMergeCmd.Flags().StringVar(&kbMergeReason, "reason", "", "free-text rationale recorded in kb_aliases.reason")
	kbMergeCmd.Flags().StringVar(&kbMergeBy, "by", "", "analyst identifier recorded in kb_aliases.merged_by (defaults to $USER/$USERNAME)")
	kbMergeCmd.Flags().BoolVar(&kbMergeDryRun, "dry-run", false, "preview the merge (resolve winner + count knowledge_sources rows) without mutating — recommended before this irreversible op")

	kbOpsCmd.AddCommand(kbMergeCmd)
}

func runKbMerge(cmd *cobra.Command, args []string) error {
	loser := args[0]
	winner := args[1]

	dsn, err := kb_output.ResolveDSN("")
	if err != nil {
		return err
	}

	by := kbMergeBy
	if by == "" {
		by = os.Getenv("USER")
	}
	if by == "" {
		by = os.Getenv("USERNAME")
	}
	if by == "" {
		by = "unknown"
	}

	ctx := context.Background()
	if cmd != nil && cmd.Context() != nil {
		ctx = cmd.Context()
	}

	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Defense in depth: the identity package also rejects stale-alias winners
	// inside the merge tx. We surface a friendlier error up front.
	canonical, err := identity.ResolveAlias(ctx, db, winner)
	if err != nil {
		return fmt.Errorf("resolve winner: %w", err)
	}
	if canonical != winner {
		return fmt.Errorf("winner is itself a stale alias of %s; merge into the canonical kb_id instead", canonical)
	}

	if kbMergeDryRun {
		var srcRows int
		if err := db.QueryRowContext(ctx,
			`SELECT count(*) FROM knowledge_sources WHERE kb_id = $1`, loser,
		).Scan(&srcRows); err != nil {
			return fmt.Errorf("dry-run count sources: %w", err)
		}
		_, _ = fmt.Fprintf(cmd.OutOrStdout(),
			"[dry-run] would merge alias=%s -> canonical=%s | knowledge_sources to rewrite=%d | merged_by=%s | reason=%q (NO changes made)\n",
			loser, winner, srcRows, by, kbMergeReason)
		return nil
	}

	rowsUpdated, err := identity.MergeIDs(ctx, db, loser, winner, by, kbMergeReason)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(),
		"merged: alias=%s -> canonical=%s | knowledge_sources updated=%d | merged_by=%s | reason=%q\n",
		loser, winner, rowsUpdated, by, kbMergeReason)
	return nil
}
