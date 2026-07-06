/*
Copyright (c) 2026 Security Research
*/
// cmd/db_bootstrap.go owns `unravel db bootstrap` — a one-shot helper that
// connects to a Postgres cluster as a superuser, creates the unravel role
// + database + extensions, and grants the role full access to the public
// schema. Idempotent: re-running on an already-bootstrapped cluster is a
// no-op (uses IF NOT EXISTS / DO blocks throughout).
//
// The helper is *separate* from `unravel db setup`: bootstrap uses
// superuser credentials, setup writes the runtime config.yaml that points
// at the unravel app role.
//
// Usage:
//
//	unravel db bootstrap --super-dsn postgres://postgres:postgres@host:5432/postgres \
//	    --role unravel_app --password '<role-password>' --dbname unravel
//
// The --super-dsn defaults to postgres://postgres:postgres@HOST:PORT/postgres
// where HOST/PORT come from existing config.yaml (or the project defaults).

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/inovacc/unravel-oss/pkg/config"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"

	"github.com/jackc/pgx/v5"
	"github.com/spf13/cobra"
)

var (
	bootstrapSuperDSN  string
	bootstrapSuperUser string
	bootstrapSuperPass string
	bootstrapRole      string
	bootstrapPassword  string
	bootstrapDBName    string
)

var dbBootstrapCmd = &cobra.Command{
	Use:   "bootstrap",
	Short: "Create the unravel role + database + extensions on the cluster (run once)",
	Long: `Connect to the Postgres cluster as a superuser, create the unravel
application role, the unravel database (owned by that role), and the
required extensions (pg_trgm, vector). Idempotent.

Either pass a full --super-dsn or supply --super-user / --super-pass to
build it from the existing config.yaml host:port. The default super-user
is "postgres".`,
	RunE: runDBBootstrap,
}

func init() {
	dbBootstrapCmd.Flags().StringVar(&bootstrapSuperDSN, "super-dsn", "", "full superuser DSN (postgres://...). Overrides --super-user / --super-pass.")
	dbBootstrapCmd.Flags().StringVar(&bootstrapSuperUser, "super-user", "postgres", "Postgres superuser name")
	dbBootstrapCmd.Flags().StringVar(&bootstrapSuperPass, "super-pass", "", "Postgres superuser password (or PGPASSWORD env)")
	dbBootstrapCmd.Flags().StringVar(&bootstrapRole, "role", config.DefaultUser, "application role to create")
	dbBootstrapCmd.Flags().StringVar(&bootstrapPassword, "password", "", "password for the application role (required)")
	dbBootstrapCmd.Flags().StringVar(&bootstrapDBName, "dbname", config.DefaultDBName, "database name to create")
	dbCmd.AddCommand(dbBootstrapCmd)
}

func runDBBootstrap(_ *cobra.Command, _ []string) error {
	if bootstrapPassword == "" {
		bootstrapPassword = os.Getenv("UNRAVEL_DB_PASSWORD")
	}
	if bootstrapPassword == "" {
		return fmt.Errorf("--password (or UNRAVEL_DB_PASSWORD) is required")
	}

	cfg, err := config.Load()
	if errors.Is(err, config.ErrConfigNotFound) {
		cfg = config.Default()
	} else if err != nil {
		return err
	}

	superDSN := bootstrapSuperDSN
	if superDSN == "" {
		pass := bootstrapSuperPass
		if pass == "" {
			pass = os.Getenv("PGPASSWORD")
		}
		if pass == "" {
			return fmt.Errorf("either --super-dsn or --super-pass / PGPASSWORD must be set")
		}
		u := url.URL{
			Scheme: "postgres",
			Host:   net(cfg.Database.Host, cfg.Database.Port),
			User:   url.UserPassword(bootstrapSuperUser, pass),
			Path:   "/postgres", // connect to the maintenance DB first
		}
		q := u.Query()
		if cfg.Database.SSLMode != "" {
			q.Set("sslmode", cfg.Database.SSLMode)
		}
		u.RawQuery = q.Encode()
		superDSN = u.String()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, superDSN)
	if err != nil {
		return fmt.Errorf("connect superuser (%s): %w", kbdb.RedactDSN(superDSN), err)
	}
	defer func() { _ = conn.Close(ctx) }()

	// Role
	if err := ensureRole(ctx, conn, bootstrapRole, bootstrapPassword); err != nil {
		return err
	}
	fmt.Printf("role %q ready\n", bootstrapRole)

	// Database (owned by the role). Must run outside a tx.
	if err := ensureDatabase(ctx, conn, bootstrapDBName, bootstrapRole); err != nil {
		return err
	}
	fmt.Printf("database %q ready (owner=%s)\n", bootstrapDBName, bootstrapRole)

	// Reconnect to the new DB to install extensions + grants.
	dbConn, err := pgx.Connect(ctx, replaceDBPath(superDSN, bootstrapDBName))
	if err != nil {
		return fmt.Errorf("connect %s (%s): %w", bootstrapDBName, kbdb.RedactDSN(replaceDBPath(superDSN, bootstrapDBName)), err)
	}
	defer func() { _ = dbConn.Close(ctx) }()

	for _, ext := range []string{"pg_trgm", "vector"} {
		if _, err := dbConn.Exec(ctx, fmt.Sprintf(`CREATE EXTENSION IF NOT EXISTS %q`, ext)); err != nil {
			return fmt.Errorf("create extension %s: %w", ext, err)
		}
	}
	fmt.Println("extensions: pg_trgm, vector ready")

	// Grant the app role full access on the public schema (PG 15+ revokes
	// public schema CREATE from PUBLIC by default).
	for _, stmt := range []string{
		fmt.Sprintf(`GRANT ALL ON SCHEMA public TO %s`, quoteIdent(bootstrapRole)),
		fmt.Sprintf(`ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT ALL ON TABLES TO %s`, quoteIdent(bootstrapRole), quoteIdent(bootstrapRole)),
		fmt.Sprintf(`ALTER DEFAULT PRIVILEGES FOR ROLE %s IN SCHEMA public GRANT ALL ON SEQUENCES TO %s`, quoteIdent(bootstrapRole), quoteIdent(bootstrapRole)),
	} {
		if _, err := dbConn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("grant: %w", err)
		}
	}
	fmt.Println("grants: public schema -> app role")
	fmt.Println()
	fmt.Println("next: run `unravel db setup --host", cfg.Database.Host,
		"--port", cfg.Database.Port,
		"--user", bootstrapRole,
		"--dbname", bootstrapDBName,
		"--password '<role-password>'`")
	return nil
}

// ensureRole CREATEs the role if missing; otherwise resets the password.
func ensureRole(ctx context.Context, conn *pgx.Conn, role, password string) error {
	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
		return fmt.Errorf("probe role: %w", err)
	}
	if exists {
		_, err := conn.Exec(ctx,
			fmt.Sprintf(`ALTER ROLE %s WITH LOGIN PASSWORD %s`,
				quoteIdent(role), quoteLiteral(password)))
		if err != nil {
			return fmt.Errorf("alter role: %w", err)
		}
		return nil
	}
	_, err := conn.Exec(ctx,
		fmt.Sprintf(`CREATE ROLE %s WITH LOGIN PASSWORD %s`,
			quoteIdent(role), quoteLiteral(password)))
	if err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	return nil
}

// ensureDatabase CREATEs the database if missing. Must run outside a tx.
func ensureDatabase(ctx context.Context, conn *pgx.Conn, dbname, owner string) error {
	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, dbname).Scan(&exists); err != nil {
		return fmt.Errorf("probe database: %w", err)
	}
	if exists {
		// Ensure owner is correct.
		_, err := conn.Exec(ctx,
			fmt.Sprintf(`ALTER DATABASE %s OWNER TO %s`,
				quoteIdent(dbname), quoteIdent(owner)))
		if err != nil {
			return fmt.Errorf("alter database owner: %w", err)
		}
		return nil
	}
	_, err := conn.Exec(ctx,
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`,
			quoteIdent(dbname), quoteIdent(owner)))
	if err != nil {
		return fmt.Errorf("create database: %w", err)
	}
	return nil
}

func net(host string, port int) string { return host + ":" + strconv.Itoa(port) }

// quoteIdent wraps an SQL identifier in double-quotes and escapes embedded
// double-quotes, matching libpq's PQescapeIdentifier.
func quoteIdent(s string) string {
	out := []rune{'"'}
	for _, r := range s {
		if r == '"' {
			out = append(out, '"')
		}
		out = append(out, r)
	}
	out = append(out, '"')
	return string(out)
}

// quoteLiteral wraps a string literal in single-quotes and doubles embedded
// single-quotes, matching libpq's PQescapeLiteral. Used only for DDL where
// parameter binding isn't available (CREATE ROLE ... PASSWORD '...').
func quoteLiteral(s string) string {
	out := []rune{'\''}
	for _, r := range s {
		if r == '\'' {
			out = append(out, '\'')
		}
		out = append(out, r)
	}
	out = append(out, '\'')
	return string(out)
}

// replaceDBPath swaps the database segment of a postgres URL.
func replaceDBPath(dsn, newDB string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	u.Path = "/" + newDB
	return u.String()
}
