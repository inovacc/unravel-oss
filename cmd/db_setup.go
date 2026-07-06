/*
Copyright (c) 2026 Security Research
*/
package cmd

import (
	"github.com/spf13/cobra"
)

// dbSetupCmd is the canonical entry point for first-run KB configuration,
// exposed as `unravel db setup`. It shares runDBSetup + the setup* flag
// vars declared in db.go.
//
// Interactive when stdin is a TTY and a flag/env is missing; otherwise
// non-interactive (flags + UNRAVEL_DB_PASSWORD). Writes config.yaml,
// AES-256-GCM-encrypts the Postgres password, mirrors to keychain,
// then pings the resolved pool.
var dbSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Configure the Postgres knowledge-base (interactive or flags)",
	Long: `Write %LOCALAPPDATA%\Unravel\config.yaml and seed the OS keychain
with the AES-256-GCM data key (auto-generated) and the Postgres password.

Two modes:

  Non-interactive (preferred — no stdin required):
    unravel db setup --host 192.168.15.100 --port 5432 \
        --user unravel_app --dbname unravel --sslmode prefer \
        --password 'secret'

  Or set UNRAVEL_DB_PASSWORD in the env and omit --password.

  Interactive:
    unravel db setup
        (prompts for any value not supplied via flag)

After setup, every unravel binary + the MCP server reads the resolved
DSN from config.yaml. UNRAVEL_KB_DB / UNRAVEL_KB_DSN remain optional
escape hatches for ephemeral overrides (CI, tests, throwaway hosts).`,
	RunE: runDBSetup,
}

func init() {
	// Flag vars (setupHost, setupPort, ...) are declared in db.go and
	// shared via the `cmd` package scope — same vars, same Go variables,
	// just exposed under the `db setup` cobra path.
	dbCmd.AddCommand(dbSetupCmd)
	dbSetupCmd.Flags().StringVar(&setupHost, "host", "", "Postgres host (default: existing config or built-in)")
	dbSetupCmd.Flags().IntVar(&setupPort, "port", 0, "Postgres port (default: existing config or 5432)")
	dbSetupCmd.Flags().StringVar(&setupUser, "user", "", "Postgres user (default: existing config or built-in)")
	dbSetupCmd.Flags().StringVar(&setupDBName, "dbname", "", "Database name (default: existing config or built-in)")
	dbSetupCmd.Flags().StringVar(&setupSSLMode, "sslmode", "", "SSL mode (default: existing config or built-in)")
	dbSetupCmd.Flags().StringVar(&setupPassword, "password", "", "Postgres password (or set UNRAVEL_DB_PASSWORD)")
	dbSetupCmd.Flags().BoolVar(&setupNoPing, "no-ping", false, "skip the post-write ping check")
}
