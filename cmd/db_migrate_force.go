/*
Copyright (c) 2026 Security Research
*/
// cmd/db_migrate_force.go owns `unravel db migrate-force <version>` — a
// recovery command that clears a dirty schema_migrations state by forcing the
// recorded version without running SQL. Pair with a normal KB open afterward
// to idempotently re-apply any pending migrations.

package cmd

import (
	"context"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
)

var dbMigrateForceYes bool

var dbMigrateForceCmd = &cobra.Command{
	Use:   "migrate-force <version>",
	Short: "Clear a dirty migration state by forcing schema_migrations to <version>",
	Long: "Recovery tool for a catalog left in 'Dirty database version N' state by " +
		"an interrupted migration. Forces the recorded version and clears the dirty " +
		"flag WITHOUT running migration SQL. After forcing to the last known-good " +
		"version, re-run any KB command to idempotently apply pending migrations.",
	Args: cobra.ExactArgs(1),
	RunE: runDBMigrateForce,
}

func init() {
	dbMigrateForceCmd.Flags().BoolVar(&dbMigrateForceYes, "yes", false,
		"confirm the destructive force-write of schema_migrations (required to proceed)")
	dbCmd.AddCommand(dbMigrateForceCmd)
}

func runDBMigrateForce(cmd *cobra.Command, args []string) error {
	version, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("version must be an integer: %w", err)
	}
	if version < 0 {
		return fmt.Errorf("version must be >= 0, got %d", version)
	}
	// Destructive: this force-writes schema_migrations without running SQL.
	// Require explicit --yes; otherwise describe the action and bail.
	if !dbMigrateForceYes {
		fmt.Fprintf(cmd.OutOrStdout(),
			"DRY RUN: would force schema_migrations to version %d and clear the dirty flag "+
				"(no SQL executed). Re-run with --yes to proceed.\n", version)
		return nil
	}
	// OpenRaw, not kbOpenDB: the catalog is dirty, so the normal Open path
	// (which runs Migrate) would fail before we could force the version.
	conn, err := kbdb.OpenRaw(context.Background(), "")
	if err != nil {
		return fmt.Errorf("open postgres: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := kbdb.ForceVersion(conn, version); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "forced schema_migrations to version %d (dirty cleared)\n", version)
	return nil
}
