/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/cmd/kb_output"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/validatefk"
)

var (
	kbValidateFKDSN  string
	kbValidateFKJSON bool
)

// kbValidateFKCmd promotes the Phase-29 NOT VALID FK on
// knowledge_sources.kb_id to a validated constraint. Operators run this
// after `unravel kb backfill` has populated every legacy row.
//
// Per D-34-FK-VALIDATE, VALIDATE remains a separate command — it is
// never folded into the backfill transaction. The underlying ALTER
// TABLE acquires SHARE UPDATE EXCLUSIVE: concurrent reads proceed,
// concurrent writers are briefly blocked.
var kbValidateFKCmd = &cobra.Command{
	Use:   "validate-fk",
	Short: "VALIDATE the knowledge_sources kb_id FK constraint (briefly blocks writers)",
	Long: `Promote the Phase-29 NOT VALID FK on knowledge_sources.kb_id to a
validated constraint by running ALTER TABLE ... VALIDATE CONSTRAINT
knowledge_sources_kb_id_fkey.

Idempotent: re-running against an already-validated FK is a no-op.

Run AFTER ` + "`unravel kb backfill`" + ` so every legacy row has a
matching kb_apps parent. If orphan rows remain, the command exits
non-zero with the orphan row count and a diagnostic SELECT.

Connection:
  * --dsn flag overrides the env var.
  * UNRAVEL_KB_DSN env var is the fallback.

Example:
  unravel kb validate-fk --dsn $DSN`,
	RunE: runKbValidateFK,
}

func init() {
	kb_output.BindDSNFlag(kbValidateFKCmd, &kbValidateFKDSN)
	kb_output.BindJSONFlag(kbValidateFKCmd, &kbValidateFKJSON)

	kbOpsCmd.AddCommand(kbValidateFKCmd)
}

func runKbValidateFK(cmd *cobra.Command, _ []string) error {
	dsn, err := kb_output.ResolveDSN(kbValidateFKDSN)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	db, err := kbdb.Open(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open kb: %w", err)
	}
	defer func() { _ = db.Close() }()

	if err := validatefk.ValidateFK(ctx, db); err != nil {
		return err
	}

	if kbValidateFKJSON {
		return kb_output.WriteJSON(cmd.OutOrStdout(), 1, struct {
			Validated bool `json:"validated"`
		}{true})
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "validated knowledge_sources_kb_id_fkey")
	return nil
}
