// Package db opens a Postgres connection for the unravel knowledge catalog.
//
// As of v3.0 the catalog is Postgres-only — the prior SQLite backend was
// removed. The connection is constructed from pkg/config (config.yaml +
// keychain-backed encrypted password) and migrations are applied on Open
// via embedded golang-migrate sources.
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/config"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	migrateiofs "github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// PoolDefaults tunes pgxpool for short-lived CLI invocations.
var PoolDefaults = struct {
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}{
	MaxConns:          8,
	MinConns:          0,
	MaxConnLifetime:   30 * time.Minute,
	MaxConnIdleTime:   5 * time.Minute,
	HealthCheckPeriod: 1 * time.Minute,
	ConnectTimeout:    10 * time.Second,
}

// Open builds a *sql.DB backed by a pgxpool, applies pending migrations,
// and returns the handle. The DSN comes from pkg/config (config.yaml +
// keychain). An optional dsnOverride bypasses config.yaml entirely — used
// by tests and `--dsn` CLI flag.
func Open(ctx context.Context, dsnOverride string) (*sql.DB, error) {
	dsn := dsnOverride
	if dsn == "" {
		cfg, err := config.Load()
		if err != nil {
			return nil, fmt.Errorf("kb open: %w", err)
		}
		dsn, err = cfg.DSN(ctx)
		if err != nil {
			return nil, fmt.Errorf("kb open: build dsn: %w", err)
		}
	}

	pool, err := newPool(ctx, dsn)
	if err != nil {
		return nil, err
	}

	conn := stdlib.OpenDBFromPool(pool)

	if err := Migrate(conn); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("kb open: migrate: %w", err)
	}

	return conn, nil
}

// OpenPool returns a raw *pgxpool.Pool — used by callers that prefer the
// pgx native API over database/sql. The caller OWNS the returned pool and MUST
// `defer pool.Close()`: the pool runs a background health-check goroutine plus
// connection reapers that leak until it is closed (finding #13).
func OpenPool(ctx context.Context, dsnOverride string) (*pgxpool.Pool, error) {
	dsn := dsnOverride
	if dsn == "" {
		cfg, err := config.Load()
		if err != nil {
			return nil, fmt.Errorf("kb open: %w", err)
		}
		dsn, err = cfg.DSN(ctx)
		if err != nil {
			return nil, fmt.Errorf("kb open: build dsn: %w", err)
		}
	}
	return newPool(ctx, dsn)
}

// OpenRaw builds a *sql.DB backed by a pgxpool WITHOUT applying migrations.
// Used by recovery tooling (e.g. ForceVersion) that must operate on a catalog
// whose migration state is dirty — Open's migrate step would fail before the
// recovery could run. DSN resolution matches Open/OpenPool.
func OpenRaw(ctx context.Context, dsnOverride string) (*sql.DB, error) {
	dsn := dsnOverride
	if dsn == "" {
		cfg, err := config.Load()
		if err != nil {
			return nil, fmt.Errorf("kb open: %w", err)
		}
		dsn, err = cfg.DSN(ctx)
		if err != nil {
			return nil, fmt.Errorf("kb open: build dsn: %w", err)
		}
	}
	// Use database/sql's own pooling over a single pgx conn config rather than a
	// pgxpool: stdlib.OpenDBFromPool does NOT close the *pgxpool.Pool when the
	// returned *sql.DB is closed (pgx v5), so the pool's health-check + reaper
	// goroutines and idle conns leak on every recovery open — and the supervisor
	// opens recovery handles repeatedly. With stdlib.OpenDB the *sql.DB owns its
	// connections and Close() fully releases them (hardening finding #13).
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// The pgx parse error can embed the full DSN incl. password; do not wrap
		// it verbatim — return a generic, cred-free message.
		return nil, fmt.Errorf("parse dsn: invalid connection string")
	}
	return stdlib.OpenDB(*poolCfg.ConnConfig), nil
}

// RedactDSN replaces the password in a postgres URL userinfo
// (postgres://user:PASS@host) with ":***@" so the DSN is safe to log or
// embed in an error message. If the string can't be parsed as a URL it is
// returned unchanged (it carries no recognisable userinfo to leak).
func RedactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return dsn
	}
	if _, hasPass := u.User.Password(); hasPass {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.String()
}

func newPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// The pgx parse error can embed the full DSN incl. password.
		// Do NOT wrap it verbatim — return a generic, cred-free message.
		return nil, fmt.Errorf("parse dsn: invalid connection string")
	}
	cfg.MaxConns = PoolDefaults.MaxConns
	cfg.MinConns = PoolDefaults.MinConns
	cfg.MaxConnLifetime = PoolDefaults.MaxConnLifetime
	cfg.MaxConnIdleTime = PoolDefaults.MaxConnIdleTime
	cfg.HealthCheckPeriod = PoolDefaults.HealthCheckPeriod
	cfg.ConnConfig.ConnectTimeout = PoolDefaults.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("new pool: %w", err)
	}
	return pool, nil
}

// Migrate applies all embedded migrations to conn. Idempotent: re-applying
// after a successful run is a no-op.
func Migrate(conn *sql.DB) error {
	src, err := migrateiofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("migrate source: %w", err)
	}
	driver, err := migratepg.WithInstance(conn, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrate new: %w", err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// ForceVersion sets the migration version and clears the dirty flag WITHOUT
// running migration SQL. Use to recover a catalog left dirty by an
// interrupted migration. After forcing to the last known-good version, call
// Migrate to (idempotently) re-apply any pending migrations.
func ForceVersion(conn *sql.DB, version int) error {
	src, err := migrateiofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("migrate source: %w", err)
	}
	driver, err := migratepg.WithInstance(conn, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		return fmt.Errorf("migrate new: %w", err)
	}
	if err := m.Force(version); err != nil {
		return fmt.Errorf("migrate force %d: %w", version, err)
	}
	return nil
}

// Ping validates the connection round-trips.
func Ping(ctx context.Context, conn *sql.DB) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := conn.PingContext(c); err != nil {
		return fmt.Errorf("ping: %w", err)
	}
	return nil
}

// Sanitize strips a trailing semicolon. Reserved for callers that build
// queries dynamically and need a single statement.
func Sanitize(q string) string { return strings.TrimRight(q, ";\n\r\t ") }

// CheckOrphans counts soft-FK violations between modules and module_bodies.
func CheckOrphans(db *sql.DB) (modules int, enrichment int, err error) {
	if err = db.QueryRow(`
		SELECT COUNT(*) FROM modules m
		WHERE m.body_sha256 IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM module_bodies b WHERE b.body_sha256 = m.body_sha256)
	`).Scan(&modules); err != nil {
		return 0, 0, fmt.Errorf("modules orphan scan: %w", err)
	}
	if err = db.QueryRow(`
		SELECT COUNT(*) FROM module_enrichment e
		WHERE e.body_sha256 IS NOT NULL
		  AND NOT EXISTS (SELECT 1 FROM module_bodies b WHERE b.body_sha256 = e.body_sha256)
	`).Scan(&enrichment); err != nil {
		return 0, 0, fmt.Errorf("enrichment orphan scan: %w", err)
	}
	return modules, enrichment, nil
}

// CheckEmbeddingDims counts embedding rows whose blob length disagrees
// with both f32 and f16 layouts.
func CheckEmbeddingDims(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow(`
		SELECT COUNT(*) FROM module_embeddings
		WHERE octet_length(vector) <> dim * 4 AND octet_length(vector) <> dim * 2
	`).Scan(&n); err != nil {
		return 0, fmt.Errorf("embedding dim scan: %w", err)
	}
	return n, nil
}

// CountFactHistory returns the row count of fact_history.
func CountFactHistory(db *sql.DB) (int, error) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fact_history`).Scan(&n); err != nil {
		return 0, fmt.Errorf("fact_history count: %w", err)
	}
	return n, nil
}

// MigrateFactHistoryToMillis is a no-op on Postgres — the seconds→millis
// hack predated the schema cutover. Retained as a stub so doctor compiles
// across the SQLite→PG transition.
func MigrateFactHistoryToMillis(_ *sql.DB) (int64, error) { return 0, nil }
